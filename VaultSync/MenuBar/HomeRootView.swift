/// Root of the popover navigation stack.
///
/// Renders the top of ``AppModel/path`` — Home when it is empty — mapping each
/// ``AppModel/Route`` to its view. Home is the stack root; add/edit/detail/file-list push on top.
///
/// **Why this is not a `NavigationStack`.** A `NavigationStack` reports its *root's* height as its
/// own, whatever route is on top, so the hosting controller published Home's height for every
/// pushed panel and `NSPopover` sized to that: a taller panel (measured at 369pt against a 200pt
/// root) was compressed to the root's height and everything past it — the footer, with the
/// settings menu in it — fell outside the popover. No arrangement of `fixedSize`, `minHeight` or
/// `NSHostingSizingOptions` changes that; the height is fixed at the stack's root.
///
/// Switching on the path publishes the *current* route's own height, so each panel sizes to
/// itself. Nothing was lost with the stack: every route is driven by `model.path` (there are no
/// `NavigationLink`s), and each panel already draws its own header, back button and footer.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import SwiftUI
import Common

struct HomeRootView: View {
    @ObservedObject var model: AppModel

    /// Popover intrinsic width. Views grow vertically within this to "match shown panels".
    static let contentWidth: CGFloat = 380

    var body: some View {
        Group {
            if let route = model.path.last {
                destination(for: route)
            } else {
                HomeView(model: model)
            }
        }
        .frame(width: Self.contentWidth)
        .frame(minHeight: 200)
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func destination(for route: AppModel.Route) -> some View {
        switch route {
        case .addDomain:
            AddEditDomainScreen(model: model, existingDomainID: nil)
        case .editDomain(let domainID):
            AddEditDomainScreen(model: model, existingDomainID: domainID)
        case .domainDetail(let domainID):
            DomainDetailView(model: model, domainID: domainID)
        case .fileList(let domainID, let kind):
            FileListView(model: model, domainID: domainID, kind: kind)
        case .security:
            // The flow is created by `openSecurity()` before this route is ever pushed; the
            // fallback keeps the view total rather than crashing on an unreachable state.
            SecurityView(model: model, flow: model.securityFlow ?? SecurityFlow())
        case .unlock(let domainIDs, let then):
            UnlockView(model: model, domainIDs: domainIDs, then: then)
        case .confirmLock(let domainIDs, let pendingCount):
            ConfirmLockView(model: model, domainIDs: domainIDs, pendingCount: pendingCount)
        case .vaultGate(let readiness):
            VaultGateView(model: model, readiness: readiness)
        }
    }
}
