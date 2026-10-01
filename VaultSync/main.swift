/// Application entry point.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import AppKit

/// Explicit entry point.
///
/// Replaces `@NSApplicationMain`, which installs the delegate only by way of the main nib's
/// `delegate` outlet. This app is a `LSUIElement` menu-bar agent with no main nib: when
/// `MainMenu.xib` left the build, `NSApp.delegate` was silently left nil, so
/// `applicationDidFinishLaunching` and — the visible symptom —
/// `applicationShouldTerminate` never ran, taking the quit lock and every log line on those
/// paths with them. Assigning the delegate here keeps that wiring in code, where it cannot be
/// dropped by a resource going missing.
///
/// The delegate is held in a `let` for the process lifetime: `NSApplication.delegate` is a
/// weak reference, so a temporary would deallocate immediately.
///
/// `run()` is called directly rather than via `NSApplicationMain`, which would try to load the
/// main nib this app no longer has. `.accessory` matches the `LSUIElement` Info.plist entry.
// Top-level code in `main.swift` runs on the main thread but is nonisolated, so building the
// `@MainActor` delegate needs the isolation stated explicitly.
let application = NSApplication.shared
let appDelegate = MainActor.assumeIsolated { AppDelegate() }
application.delegate = appDelegate
application.setActivationPolicy(.accessory)
application.run()
