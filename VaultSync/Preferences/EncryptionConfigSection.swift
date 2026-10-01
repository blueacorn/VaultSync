/// SwiftUI section for per-domain encryption configuration embedded in the Edit Domain tab.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import SwiftUI
import Common
import AppKit
import UniformTypeIdentifiers

struct EncryptionConfigSection: View {
    @Binding var algorithm: CryptoAlgorithm
    @Binding var bckeyPath: String
    @Binding var password: String
    /// Inline validation state, driven by a failed key derivation on Save.
    var bckeyFieldInvalid: Bool = false
    var passwordFieldInvalid: Bool = false
    var validationMessage: String? = nil
    /// Called when the user edits either field, so the host can clear stale validation errors.
    var onEdit: () -> Void = {}
    @State private var browsedKeyURL: URL?

    var bckeyURL: URL? {
        browsedKeyURL ?? (bckeyPath.isEmpty ? nil : URL(fileURLWithPath: bckeyPath))
    }

    var body: some View {
        Section {
            Picker("Algorithm", selection: $algorithm) {
                ForEach(CryptoAlgorithm.allCases, id: \.self) { algo in
                    Text(algo.displayName).tag(algo)
                }
            }

            if algorithm == .bc01 {
                bc01Fields
            }
        } header: {
            Text("Encryption")
        }
    }

    @ViewBuilder
    private var bc01Fields: some View {
        HStack {
            TextField(".bckey file", text: $bckeyPath)
                .textFieldStyle(.roundedBorder)
                .disabled(true)
                .overlay(invalidOutline(bckeyFieldInvalid))
            Button("Browse…") { browseBckey() }
        }
        SecureField("Password", text: $password)
            .textFieldStyle(.roundedBorder)
            .overlay(invalidOutline(passwordFieldInvalid))
            .onChange(of: password) { _ in onEdit() }
        if let validationMessage {
            Text(validationMessage)
                .foregroundStyle(.red).font(.caption)
        }
    }

    @ViewBuilder
    private func invalidOutline(_ invalid: Bool) -> some View {
        if invalid {
            RoundedRectangle(cornerRadius: 5).strokeBorder(Color.red, lineWidth: 1.5)
        }
    }

    private func browseBckey() {
        let panel = NSOpenPanel()
        if let bckey = UTType(filenameExtension: "bckey") {
            panel.allowedContentTypes = [bckey]
        }
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.prompt = "Select"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        browsedKeyURL = url
        bckeyPath = url.path
        onEdit()
    }
}
