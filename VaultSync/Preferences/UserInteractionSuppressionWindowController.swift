/// Process exclusion configuration UI
//
//  Abstract:
//  A window controller for adding and removing suppression identifiers.
//
//  Copyright (c) 2024 Apple Inc.
//  SPDX-License-Identifier: MIT
//

import AppKit
import Common
import SwiftUI

class UserInteractionSuppressionWindowController: NSWindowController {
    init(_ userInteractionSuppressionEditor: UserInteractionSuppressionEditor) {
        let size = CGSize(width: 700, height: 300)
        let rootView = userInteractionSuppressionEditor.frame(minWidth: size.width, minHeight: size.height, alignment: .center)
        let hosting = NSHostingController(rootView: rootView)
        let window = NSWindow(contentViewController: hosting)
        window.minSize = size
        window.maxSize = CGSize(width: CGFloat.infinity, height: CGFloat.infinity)
        window.styleMask.update(with: [.resizable, .titled])
        // The window displays suppressions for a specific domain, so specify
        // the domain in the title and exclude it from the windows menu.
        window.isExcludedFromWindowsMenu = true
        window.title = "UserInteraction Suppressions for \(userInteractionSuppressionEditor.domainDisplayName)"
        super.init(window: window)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
}
