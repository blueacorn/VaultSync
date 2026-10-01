/// Process suppression editor.
///
/// Binds directly to ``SharedConfigStore``; per-domain suppressed identifiers live in the
/// App Group `config.json` and propagate to the Provider extension via Darwin notifications.
// Copyright (c) 2024 Apple Inc.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Common
import SwiftUI
import FileProvider

struct UserInteractionSuppressionEditor: View {
    @State private var newSuppressionIdentifier: String = ""
    @ObservedObject private var store = SharedConfigStore.shared

    let domainIdentifier: NSFileProviderDomainIdentifier
    let domainDisplayName: String

    init(domainIdentifier: NSFileProviderDomainIdentifier,
         domainDisplayName: String) {
        self.domainIdentifier = domainIdentifier
        self.domainDisplayName = domainDisplayName
    }

    var body: some View {
        List {
            HStack {
                Button(action: add) {
                    Image(systemName: "plus.app.fill")
                }
                .buttonStyle(PlainButtonStyle())

                TextField("SuppressionIdentifier", text: $newSuppressionIdentifier, onCommit: add)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
            }

            ForEach(currentIdentifiers, id: \.self) { name in
                CellWithLabelAndDeleteAction(label: name) {
                    remove(name)
                }
            }
        }
    }

    private var currentIdentifiers: [String] {
        store.read(\.userInteractionSuppressedIdentifiers)[domainIdentifier.rawValue] ?? []
    }

    private func add() {
        guard !newSuppressionIdentifier.isEmpty else { return }
        let identifier = newSuppressionIdentifier
        store.mutate { config in
            var list = config.userInteractionSuppressedIdentifiers[domainIdentifier.rawValue] ?? []
            guard !list.contains(identifier) else { return }
            list.insert(identifier, at: 0)
            config.userInteractionSuppressedIdentifiers[domainIdentifier.rawValue] = list
        }
        newSuppressionIdentifier = ""
    }

    private func remove(_ name: String) {
        store.mutate { config in
            guard var list = config.userInteractionSuppressedIdentifiers[domainIdentifier.rawValue] else { return }
            list.removeAll { $0 == name }
            config.userInteractionSuppressedIdentifiers[domainIdentifier.rawValue] = list
        }
    }
}
