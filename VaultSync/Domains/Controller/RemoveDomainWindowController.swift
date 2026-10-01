/// Domain removal confirmation UI
//
//  Abstract:
//  A view controller for displaying options when removing a domain.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import AppKit
import FileProvider
import Common

class RemoveDomainWindowController: NSWindowController {
    @objc class var keyPathsForValuesAffectingIdentifier: Set<String> {
        return ["displayName"]
    }

    @objc dynamic var displayName: String = ""
    @objc dynamic var identifier: String {
        "\(domain.identifier.rawValue)"
    }

    /// - Parameter onConfirm: Invoked with the chosen removal mode when the user confirms.
    ///   The controller does not perform the removal itself: tearing a domain down safely
    ///   requires winding the Provider down first, which is ``AppDelegate``'s responsibility
    ///   (see `AppDelegate.confirmedDelete(_:mode:)`).
    init(_ domain: NSFileProviderDomain,
         spinner: NSProgressIndicator,
         onConfirm: @escaping (NSFileProviderManager.DomainRemovalMode) -> Void) {
        self.domain = domain
        self.spinner = spinner
        self.onConfirm = onConfirm
        super.init(window: nil)
        self.loadWindow()
    }

    override var windowNibName: NSNib.Name? {
        return NSNib.Name("RemoveDomainWindow")
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    let domain: NSFileProviderDomain
    private let onConfirm: (NSFileProviderManager.DomainRemovalMode) -> Void
    var removeMode: NSFileProviderManager.DomainRemovalMode = .removeAll
    var spinner: NSProgressIndicator

    @IBOutlet weak var removeAllRadioButton: NSButton!
    @IBOutlet weak var preserveDownloadedRadioButton: NSButton!
    @IBOutlet weak var preserveDirtyRadioButton: NSButton!
    @IBAction func radioButtonClick(_ sender: NSButton) {
        if sender == self.removeAllRadioButton {
            self.removeMode = .removeAll
        }

        if sender == self.preserveDownloadedRadioButton {
            self.removeMode = .preserveDownloadedUserData
        }

        if sender == self.preserveDirtyRadioButton {
            self.removeMode = .preserveDirtyUserData
        }
    }

    @IBAction func removeButton(_ sender: Any) {
        guard let window = window else { fatalError() }
        onConfirm(removeMode)
        window.sheetParent?.endSheet(window)
    }

    @IBOutlet weak var button: NSButton!
    @IBAction func cancelButton(_ sender: Any) {
        guard let window = window else { fatalError() }
        window.sheetParent?.endSheet(window)
    }
}
