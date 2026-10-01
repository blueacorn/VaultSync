/// Custom action result UI handler
//
//  Abstract:
//  A controller that provides the user interface for actions.
//
//  Copyright (c) 2024 Apple Inc.
//  SPDX-License-Identifier: MIT
//

import Cocoa
import FileProviderUI
import Common
import Extension
import os.log

protocol ConcreteActionViewController: NSViewController {
    func prepareForDisplay()
}

public class ActionViewController: FPUIActionExtensionViewController {
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "action")

    var domain: NSFileProviderDomain {
        guard let identifier = extensionContext.domainIdentifier else {
            fatalError("not expected to be called with default domain")
        }
        return NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(rawValue: identifier.rawValue), displayName: "")
    }

    func prepare(_ childViewController: ConcreteActionViewController) {
        addChild(childViewController)
        view.addSubview(childViewController.view)

        NSLayoutConstraint.activate([
            view.leadingAnchor.constraint(equalTo: childViewController.view.leadingAnchor),
            view.trailingAnchor.constraint(equalTo: childViewController.view.trailingAnchor),
            view.topAnchor.constraint(equalTo: childViewController.view.topAnchor),
            view.bottomAnchor.constraint(equalTo: childViewController.view.bottomAnchor)
        ])

        childViewController.prepareForDisplay()
    }

    public override func prepare(forError error: Error) {
        prepare(AuthenticationViewController())
    }

    override public func loadView() {
        self.view = NSView()
    }

    public override func prepare(forAction actionIdentifier: String, itemIdentifiers: [NSFileProviderItemIdentifier]) {
        // You need to add each action to this switch statement.
        switch actionIdentifier {
        case "\(AppIdentifiers.bundleID).ConflictAction":
            prepare(ConflictViewController(itemIdentifiers))
        default:
            fatalError()
        }
    }
}
