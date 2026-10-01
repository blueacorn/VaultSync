/// SwiftUI view for process exclusion configuration.
///
/// Binds directly to ``SharedConfigStore`` so the Provider extension sees mutations via
/// the App Group JSON channel without going through `cfprefsd`.
// Copyright (c) 2024 Apple Inc.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Common
import SwiftUI

struct BlockedProcessesEditorView: View {
    @State private var newProcessName: String = ""
    @ObservedObject private var store = SharedConfigStore.shared

    var body: some View {
        List {
            HStack {
                Button(action: add) {
                    Image(systemName: "plus.app.fill")
                }
                .buttonStyle(PlainButtonStyle())

                TextField("Process name", text: $newProcessName, onCommit: add)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
            }

            ForEach(store.read(\.blockedProcesses), id: \.self) { name in
                CellWithLabelAndDeleteAction(label: name) {
                    remove(name)
                }
            }
        }
    }

    private func add() {
        guard !newProcessName.isEmpty else { return }
        store.mutate { config in
            guard !config.blockedProcesses.contains(newProcessName) else { return }
            config.blockedProcesses.insert(newProcessName, at: 0)
        }
        newProcessName = ""
    }

    private func remove(_ name: String) {
        store.mutate { config in
            config.blockedProcesses.removeAll { $0 == name }
        }
    }
}
