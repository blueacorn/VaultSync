/// Confirmation for a lock that would discard unsynced local changes.
///
/// Shown only when the lock is actually destructive — "Lock and Remove Vault" with items still
/// pending upload, or a pending count that could not be determined (which fails safe). A plain
/// lock, or a lock-and-remove with everything synced, proceeds without asking.
///
/// A route in the popover stack rather than a centre-screen sheet, per the panel idiom.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Common
import SwiftUI

struct ConfirmLockView: View {
    @ObservedObject var model: AppModel
    let domainIDs: [String]
    /// Items with unsynced local changes, or `-1` when the count is unknown.
    let pendingCount: Int

    private var countUnknown: Bool { pendingCount < 0 }

    private var message: String {
        if countUnknown {
            return "Some changes may not have finished uploading. Locking removes this Mac's "
                 + "copy, so anything not yet on the server would be lost."
        }
        let noun = pendingCount == 1 ? "change has" : "changes have"
        return "\(pendingCount.formatted()) \(noun) not finished uploading. Locking removes this "
             + "Mac's copy, so they would be lost."
    }

    var body: some View {
        VStack(spacing: 0) {
            HomeHeader(backAction: { dismiss() }) {
                Text("Lock Vaults?").font(.headline)
                Spacer()
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
            Divider()

            VStack(alignment: .leading, spacing: 8) {
                Text(message)
                Text("Files already on the server are not affected, and unlocking restores the "
                     + "vault.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)

            Spacer(minLength: 0)
            Divider()
            HStack {
                Button("Cancel") { dismiss() }
                    .buttonStyle(.plain)
                Spacer()
                Button("Lock Anyway", role: .destructive) {
                    model.actions?.confirmedLockAndRemoveAction(domainIDs: domainIDs)
                    dismiss()
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }

    private func dismiss() {
        if !model.path.isEmpty { model.path.removeLast() }
    }
}
