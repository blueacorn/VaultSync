/// Tweaks tab: SwiftUI bindings to host-local UserDefaults plus cross-process SharedConfigStore.
///
/// Host-local toggles (`ignoreAuthentication`, simulation knobs, batch size, etc.) bind
/// directly to ``UserDefaults.sharedContainerDefaults`` via `@AppStorage`. Provider-read
/// toggles (BRM tunables, sync/upload behaviour) bind to
/// ``SharedConfigStore`` so changes propagate across the App Group boundary without
/// triggering `cfprefsd` sandbox Faults inside `Provider.appex`.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import Cocoa
import SwiftUI
import Common

final class TweaksViewController: NSViewController {

    @objc dynamic var userDefaultsController =
        NSUserDefaultsController(defaults: .sharedContainerDefaults, initialValues: nil)

    override func loadView() {
        view = NSView(frame: NSRect(x: 0, y: 0, width: 540, height: 360))
        view.autoresizingMask = [.width, .height]

        let hosting = NSHostingController(rootView: TweaksView())
        addChild(hosting)
        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hosting.view)
        NSLayoutConstraint.activate([
            hosting.view.topAnchor.constraint(equalTo: view.topAnchor),
            hosting.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            hosting.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hosting.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
    }
}

// MARK: - SwiftUI view

private struct TweaksView: View {

    // Host-local: stays on UserDefaults (Provider never reads these).
    @AppStorage("ignoreAuthentication", store: .sharedContainerDefaults)
    var ignoreAuthentication = true

    @AppStorage("contentStoredInline", store: .sharedContainerDefaults)
    var contentStoredInline = false

    @AppStorage("ignoreContentVersionOnDeletion", store: .sharedContainerDefaults)
    var ignoreContentVersionOnDeletion = false

    @AppStorage("errorRate", store: .sharedContainerDefaults)
    var errorRate = 0.0

    @AppStorage("responseDelay", store: .sharedContainerDefaults)
    var responseDelay = 0.0

    @AppStorage("batchSize", store: .sharedContainerDefaults)
    var batchSize = 200

    // Cross-process: backed by SharedConfigStore so Provider sees mutations live.
    @ObservedObject private var store = SharedConfigStore.shared

    var body: some View {
        Form {
            Section("Authentication") {
                Toggle("Ignore Authentication", isOn: $ignoreAuthentication)
            }
            Section("Content") {
                Toggle("Content Stored Inline", isOn: $contentStoredInline)
            }
            Section("Sync Behaviour") {
                Toggle("Sync Children Before Parent Move",
                       isOn: store.binding(\.syncChildrenBeforeParentMove))
                Toggle("Ignore Content Version on Deletion", isOn: $ignoreContentVersionOnDeletion)
            }
            Section("Simulation") {
                HStack {
                    Text("Error Rate")
                    Slider(value: $errorRate, in: 0...100, step: 1)
                    Text("\(Int(errorRate)) %").frame(width: 40, alignment: .trailing)
                }
                HStack {
                    Text("Response Delay")
                    Slider(value: $responseDelay, in: 0...5000, step: 50)
                    Text("\(Int(responseDelay)) ms").frame(width: 50, alignment: .trailing)
                }
                HStack {
                    Text("Batch Size")
                    TextField("200", value: $batchSize, format: .number)
                        .multilineTextAlignment(.trailing)
                        .frame(width: 80)
                }
            }
            Section("Blocked Processes") {
                BlockedProcessesEditorView()
                    .frame(minHeight: 80)
            }
        }
        .padding()
        .formStyle(.grouped)
    }
}
