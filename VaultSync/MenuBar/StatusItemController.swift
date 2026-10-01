/// Menu-bar status item: icon state machine + attached popover lifecycle.
///
/// Owns the `NSStatusItem` and the transient `NSPopover` that hosts the SwiftUI
/// navigation stack. Renders the aggregate ``StatusActivity`` published by
/// ``AppModel`` as the button image (idle shield / animated / error badge) and
/// toggles the popover on left-click, anchored directly below the item.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit
import Combine
import SwiftUI

@MainActor
final class StatusItemController {
    private let statusItem: NSStatusItem
    private let popover = NSPopover()
    private let model: AppModel
    private var cancellables = Set<AnyCancellable>()

    /// Rotation-frame animation state.
    private var animationTimer: Timer?
    private var animationFrame = 0

    init(model: AppModel) {
        self.model = model
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        configureButton()
        configurePopover()

        // Re-render the icon whenever aggregate activity changes.
        model.$activity
            .removeDuplicates()
            .sink { [weak self] activity in self?.render(activity) }
            .store(in: &cancellables)

        render(model.activity)
    }

    // MARK: - Setup

    private func configureButton() {
        guard let button = statusItem.button else { return }
        button.target = self
        button.action = #selector(togglePopover(_:))
        button.imageScaling = .scaleProportionallyDown
        button.toolTip = "Vault Sync"
    }

    private func configurePopover() {
        // `.applicationDefined` (not `.transient`) so the popover survives the app resigning
        // active — e.g. when the OneDrive OAuth window takes focus mid-form. Dismissal is
        // therefore driven explicitly (button click toggle, or `model.dismissPopover`).
        popover.behavior = .applicationDefined
        popover.animates = true
        let root = HomeRootView(model: model)
        let host = NSHostingController(rootView: root)
        // Required for the popover to size to its content at all: without it the controller never
        // publishes a size and `NSPopover` falls back to its default 320x320 for every route,
        // squeezing the 380pt-wide panels 60pt narrower than they ask for. With it the popover
        // tracks the current route's fitting size, shrinking as well as growing — which is only
        // the *right* height because `HomeRootView` no longer reports its stack root's (see there).
        host.sizingOptions = [.preferredContentSize]
        popover.contentViewController = host
        model.dismissPopover = { [weak self] in self?.popover.performClose(nil) }
        model.reanchorPopover = { [weak self] in self?.reanchorPopover() }
    }

    /// Re-pins the popover under the status-item button on the button's own screen.
    ///
    /// After a system-modal focus change (the OneDrive OAuth consent prompt), `NSPopover`
    /// re-anchors to the wrong screen on multi-monitor setups. Closing and re-showing it
    /// against the live button bounds forces it back beneath the menu-bar icon. The current
    /// navigation `path` is preserved (unlike ``showPopover``, which resets to Home).
    private func reanchorPopover() {
        guard let button = statusItem.button, popover.isShown else { return }
        popover.performClose(nil)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
    }

    // MARK: - Popover

    /// Dismiss the popover, if shown. Used on quit: the popover is a window, and tearing the app
    /// down while it is still tracking is what made the Quit item look inert.
    func closePopover() {
        if popover.isShown { popover.performClose(nil) }
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        if popover.isShown {
            popover.performClose(sender)
        } else {
            showPopover()
        }
    }

    private func showPopover() {
        guard let button = statusItem.button else { return }
        // Reset to Home on open (except while an add/edit draft is in progress), or route
        // straight to the readiness gate when the vault key is missing.
        model.prepareForPopoverPresentation()
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        popover.contentViewController?.view.window?.makeKey()
    }

    // MARK: - Icon rendering

    private func render(_ activity: StatusActivity) {
        stopAnimation()
        guard let button = statusItem.button else { return }
        button.toolTip = model.aggregateStatusSummary()
        switch activity {
        case .idle:
            button.image = Self.idleImage()
        case .active:
            startAnimation()
        case .locked:
            button.image = Self.lockedImage()
        case .error:
            button.image = Self.errorImage()
        case .vaultError:
            button.image = Self.vaultErrorImage()
        }
    }

    /// Bare exclamation mark for an orphaned vault key. Deliberately not the shield used by
    /// ``errorImage()``: the shield says "protected, but something is wrong with a domain",
    /// while here the protection itself is gone.
    private static func vaultErrorImage() -> NSImage? {
        let image = NSImage(systemSymbolName: "exclamationmark.triangle.fill",
                            accessibilityDescription: "Vault Sync — vault key missing")
        image?.isTemplate = false
        return image
    }

    /// Solid shield, template-tinted by the menu bar.
    static func idleImage() -> NSImage? {
        let image = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "Vault Sync")
        image?.isTemplate = true
        return image
    }

    /// Shield with a lock, template-tinted: a locked vault is a state the user chose, so it
    /// reads as locked rather than as the red fault badge.
    static func lockedImage() -> NSImage? {
        let image = NSImage(systemSymbolName: "lock.shield.fill",
                            accessibilityDescription: "Vault Sync — locked")
        image?.isTemplate = true
        return image
    }

    /// Shield with a non-template red error badge (kept red regardless of menu-bar tint).
    static func errorImage() -> NSImage? {
        let config = NSImage.SymbolConfiguration(paletteColors: [.labelColor, .systemRed])
        let image = NSImage(systemSymbolName: "exclamationmark.shield.fill",
                            accessibilityDescription: "Vault Sync — error")?
            .withSymbolConfiguration(config)
        image?.isTemplate = false
        return image
    }

    // MARK: - Activity animation (interim: rotating arrows badge)

    private func startAnimation() {
        guard animationTimer == nil else { return }
        let frames = Self.activityFrames()
        guard !frames.isEmpty else {
            statusItem.button?.image = Self.idleImage()
            return
        }
        animationFrame = 0
        let timer = Timer(timeInterval: 0.12, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.statusItem.button?.image = frames[self.animationFrame % frames.count]
                self.animationFrame += 1
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        animationTimer = timer
    }

    private func stopAnimation() {
        animationTimer?.invalidate()
        animationTimer = nil
    }

    /// Pre-rendered rotation frame set.
    ///
    /// A single circular-arrows glyph is rasterised at evenly-spaced rotation angles into
    /// template `NSImage`s, so the menu bar tints them and the timer cycles a smooth spin.
    /// Frames are built once and cached.
    static let activityFrameSet: [NSImage] = buildActivityFrames(count: 12)

    static func activityFrames() -> [NSImage] { activityFrameSet }

    private static func buildActivityFrames(count: Int) -> [NSImage] {
        let side: CGFloat = 18
        guard let base = NSImage(systemSymbolName: "arrow.triangle.2.circlepath",
                                 accessibilityDescription: "Vault Sync — syncing") else { return [] }
        var frames: [NSImage] = []
        for i in 0..<count {
            let angle = CGFloat(i) / CGFloat(count) * 2 * .pi
            let frame = NSImage(size: NSSize(width: side, height: side))
            frame.lockFocus()
            let ctx = NSGraphicsContext.current?.cgContext
            ctx?.translateBy(x: side / 2, y: side / 2)
            ctx?.rotate(by: -angle) // clockwise
            ctx?.translateBy(x: -side / 2, y: -side / 2)
            base.draw(in: NSRect(x: 0, y: 0, width: side, height: side),
                      from: .zero, operation: .sourceOver, fraction: 1)
            frame.unlockFocus()
            frame.isTemplate = true
            frames.append(frame)
        }
        return frames
    }
}
