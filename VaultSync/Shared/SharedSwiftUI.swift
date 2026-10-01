/// Shared SwiftUI utilities
//
//  Abstract:
//  A cell view that displays a label and has a delete action.
//
//  Copyright (c) 2024 Apple Inc.
//  SPDX-License-Identifier: MIT
//

import SwiftUI

// This cell is configurable so you can use it in multiple contexts.
struct CellWithLabelAndDeleteAction: View {
    let label: String
    let deleteAction: () -> Void

    var body: some View {
        HStack {
            Button(action: deleteAction) {
                Image(systemName: "x.circle.fill")
            }
            .buttonStyle(PlainButtonStyle())

            Text(label)
        }
    }
}
