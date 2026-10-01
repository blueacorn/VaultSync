/// Authentication UI (login dialogs)
//
//  Abstract:
//  A controller for a mock authentication view.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Cocoa
import Common
import Extension
import FileProviderUI
import os.log

class AuthenticationViewController: NSViewController, ConcreteActionViewController {
    private let logger = Logger(subsystem: "org.vaultsync.VaultSync", category: "auth")

    private let port: in_port_t

    init() {
        self.port = defaultPort

        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    public override var nibName: NSNib.Name? {
         return NSNib.Name("AuthenticationViewController")
    }

    var actionViewController: ActionViewController! {
        return parent as? ActionViewController
    }

    func prepareForDisplay() {

    }

    @IBAction func authenticate(_ sender: Any) {
        Task {
            // Authenticate by reading the demo secret from the shared config and
            // setting it for the domain. This is a demonstration of authentication-
            // related flows and is intentionally insecure.
            let avc = self.actionViewController!
            let domain = avc.domain
            do {
                let defaults = UserDefaults.sharedContainerDefaults
                // Ensure a secret exists for the domain; mint one if absent.
                if defaults.secret(for: domain.identifier) == nil {
                    defaults.set(secret: String(UUID().uuidString.suffix(12)), for: domain.identifier)
                }

                guard let manager = NSFileProviderManager(for: domain) else {
                    throw CommonError.domainNotFound
                }

                do {
                    try await manager.signalErrorResolved(NSFileProviderError(.notAuthenticated))

                    self.logger.info("✅ succeeded to signal authentication resolved for \(domain.displayName)")
                    avc.extensionContext.completeRequest()
                } catch let error as NSError {
                    self.logger.error("❌ failed to signal authentication resolved for \(domain.displayName): \(error)")
                    throw error
                }
            } catch {
                avc.extensionContext.cancelRequest(withError: error)
            }
        }
    }

    @IBAction func cancel(_ sender: Any) {
        let error = NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError, userInfo: nil)
        self.actionViewController.extensionContext.cancelRequest(withError: error)
    }
}
