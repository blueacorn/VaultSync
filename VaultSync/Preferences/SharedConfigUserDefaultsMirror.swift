/// Two-way mirror between selected ``UserDefaults`` keys and ``SharedConfigStore`` fields.
///
/// MainMenu.xib carries legacy Cocoa Bindings that target
/// `userDefaultsController.values.syncChildrenBeforeParentMove` and similar keys. After migrating those
/// values to the cross-process JSON store, the XIB bindings would otherwise dead-end at
/// host `UserDefaults` and never reach the Provider. This mirror keeps the two paths in
/// sync: writes through the XIB land in `UserDefaults`, are observed via Objective-C KVO,
/// and pushed into ``SharedConfigStore``. Writes through the SwiftUI Tweaks tab land in
/// the store, fire `objectWillChange`, and are written back to `UserDefaults` so the XIB
/// controls display the current state. Equality guards prevent feedback loops.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Foundation
import Combine
import Common

@MainActor
final class SharedConfigUserDefaultsMirror: NSObject {

    private let defaults: UserDefaults
    private let store = SharedConfigStore.shared
    private var storeCancellable: AnyCancellable?

    private struct Entry {
        let defaultsKey: String
        let read: () -> Bool
        let write: (Bool) -> Void
    }

    private let entries: [Entry]

    init(defaults: UserDefaults) {
        self.defaults = defaults
        // Only keys with live MainMenu.xib bindings need mirroring. Others are written
        // exclusively through SwiftUI bindings on SharedConfigStore.
        self.entries = [
            Entry(defaultsKey: "syncChildrenBeforeParentMove",
                  read: { SharedConfigStore.shared.read(\.syncChildrenBeforeParentMove) },
                  write: { SharedConfigStore.shared.write(\.syncChildrenBeforeParentMove, $0) }),
        ]
        super.init()
        prime()
        observeDefaults()
        observeStore()
    }

    deinit {
        for entry in entries {
            defaults.removeObserver(self, forKeyPath: entry.defaultsKey)
        }
    }

    /// Push current store values into `UserDefaults` so the XIB controls reflect the
    /// migrated state on first display.
    private func prime() {
        for entry in entries {
            defaults.set(entry.read(), forKey: entry.defaultsKey)
        }
    }

    /// Register Objective-C KVO for each mirrored `UserDefaults` key.
    private func observeDefaults() {
        for entry in entries {
            defaults.addObserver(self, forKeyPath: entry.defaultsKey, options: [.new], context: nil)
        }
    }

    /// Mirror store changes back into `UserDefaults` so legacy XIB controls update.
    private func observeStore() {
        storeCancellable = store.objectWillChange
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self else { return }
                for entry in entries {
                    let storeValue = entry.read()
                    if defaults.bool(forKey: entry.defaultsKey) != storeValue {
                        defaults.set(storeValue, forKey: entry.defaultsKey)
                    }
                }
            }
    }

    override func observeValue(forKeyPath keyPath: String?,
                               of object: Any?,
                               change: [NSKeyValueChangeKey: Any]?,
                               context: UnsafeMutableRawPointer?) {
        guard let keyPath, let entry = entries.first(where: { $0.defaultsKey == keyPath }) else {
            return
        }
        let current = defaults.bool(forKey: keyPath)
        guard entry.read() != current else { return }
        entry.write(current)
    }
}
