/// Modal folder picker for selecting a OneDrive serving folder during domain setup.
///
/// Navigates the OneDrive folder tree via ``OneDriveFolderBrowser`` and returns the
/// chosen folder (or `nil` for the drive root) to the caller. App-side only.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

import SwiftUI
import Common

/// A chosen folder: Graph DriveItem id + display name. The drive root is represented
/// by `nil` at the call site (see ``OneDriveFolderPicker``'s completion).
struct PickedOneDriveFolder: Equatable {
    let id: String
    let name: String
}

struct OneDriveFolderPicker: View {
    let domainID: String
    /// Called with the chosen folder, or `nil` for the drive root. Not called on cancel.
    let onSelect: (PickedOneDriveFolder?) -> Void

    @Environment(\.dismiss) private var dismiss
    @StateObject private var model: Model

    init(domainID: String, onSelect: @escaping (PickedOneDriveFolder?) -> Void) {
        self.domainID = domainID
        self.onSelect = onSelect
        _model = StateObject(wrappedValue: Model(domainID: domainID))
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Choose OneDrive Folder").font(.headline)
                Spacer()
            }
            .padding()

            // Breadcrumb of the current navigation stack.
            HStack(spacing: 4) {
                ForEach(Array(model.stack.enumerated()), id: \.offset) { idx, level in
                    if idx > 0 { Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.secondary) }
                    Button(level.name) { model.popTo(idx) }
                        .buttonStyle(.link)
                }
                Spacer()
            }
            .padding(.horizontal)

            Divider()

            Group {
                if model.isLoading {
                    ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if let error = model.errorMessage {
                    VStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                        Text(error).font(.caption).multilineTextAlignment(.center)
                        Button("Retry") { model.reload() }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding()
                } else if model.folders.isEmpty {
                    Text("No subfolders here.")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(model.folders) { folder in
                        HStack {
                            Image(systemName: "folder")
                            Text(folder.name)
                            Spacer()
                            if folder.hasChildren {
                                Button {
                                    model.push(folder)
                                } label: {
                                    Image(systemName: "chevron.right")
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                        .contentShape(Rectangle())
                        .onTapGesture { model.push(folder) }
                    }
                }
            }
            .frame(minHeight: 240)

            Divider()

            HStack {
                Button("Use Drive Root") {
                    onSelect(nil)
                    dismiss()
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Select This Folder") {
                    onSelect(model.currentFolder)
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.currentFolder == nil)
            }
            .padding()
        }
        .frame(width: 460, height: 460)
        .task { model.reload() }
    }

    // MARK: - Model

    @MainActor
    final class Model: ObservableObject {
        /// A level in the navigation stack: the folder whose children are shown.
        /// The first level (root) has `id == nil`.
        struct Level: Equatable {
            let id: String?   // nil = drive root
            let name: String
        }

        @Published var stack: [Level] = [Level(id: nil, name: "OneDrive")]
        @Published var folders: [OneDriveFolder] = []
        @Published var isLoading = false
        @Published var errorMessage: String?

        /// The currently-navigated folder, or `nil` when at the drive root.
        var currentFolder: PickedOneDriveFolder? {
            guard let last = stack.last, let id = last.id else { return nil }
            return PickedOneDriveFolder(id: id, name: last.name)
        }

        private let browser: OneDriveFolderBrowser

        init(domainID: String) {
            self.browser = OneDriveFolderBrowser(domainID: domainID)
        }

        func push(_ folder: OneDriveFolder) {
            stack.append(Level(id: folder.id, name: folder.name))
            reload()
        }

        func popTo(_ index: Int) {
            guard index < stack.count - 1 else { return }
            stack.removeSubrange((index + 1)...)
            reload()
        }

        func reload() {
            isLoading = true
            errorMessage = nil
            let parentID = stack.last?.id
            Task { @MainActor in
                defer { isLoading = false }
                do {
                    let pid: String
                    if let parentID { pid = parentID }
                    else { pid = try await browser.rootFolderID() }
                    folders = try await browser.childFolders(of: pid)
                } catch {
                    errorMessage = error.localizedDescription
                    folders = []
                }
            }
        }
    }
}
