/// Add / edit domain screen — hosts the reused ``EditDomainView`` in the popover stack.
///
/// Builds an ``EditDomainViewModel`` from host state (new domain for add, existing
/// account for edit) and pops the navigation stack on close. The form itself
/// (backend picker, folder chooser, encryption, options, save/validation) is unchanged.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import SwiftUI
import FileProvider
import Common

struct AddEditDomainScreen: View {
    @ObservedObject var model: AppModel
    let existingDomainID: String?

    /// The form view model is owned by ``AppModel`` (keyed by flow identity), not held as a
    /// `@StateObject` here, so the in-progress draft survives the popover being torn down and
    /// rebuilt — e.g. the re-anchor after OneDrive OAuth on multi-monitor setups.
    private var formModel: EditDomainViewModel {
        model.domainForm(existingDomainID: existingDomainID)
    }

    init(model: AppModel, existingDomainID: String?) {
        self.model = model
        self.existingDomainID = existingDomainID
    }

    var body: some View {
        EditDomainView(model: formModel,
                       onSignIn: { try await model.signInToOneDrive(domainID: $0) },
                       onVaultOrphaned: { model.routeToVaultGateIfOrphaned() },
                       onOpenSecurity: { model.openSecurity() }) {
            // Invoked on Cancel and on successful Save only (validation failures keep the
            // form open). Discard the cached draft, pop the nav stack, dismiss the popover.
            model.discardDomainForm(existingDomainID: existingDomainID)
            if !model.path.isEmpty { model.path.removeLast() }
            model.dismissPopover?()
        }
    }
}
