/// Storage-layer abstraction for the cross-process ``SharedConfig`` document.
///
/// Decouples *what* is persisted (the `SharedConfig` value) from *where/how* it is persisted
/// (App-Group JSON file today; could be UserDefaults, an in-memory fake for tests, or a
/// future encrypted store). ``SharedConfigStore`` is the production conformer, layering its
/// snapshot/KeyPath/Binding API and threading on top of this raw persistence seam.
///
/// Conformers own thread-safety and any cross-process change notification. The protocol is
/// intentionally minimal — the three operations every backing store must provide.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import Foundation

public protocol ConfigStore: AnyObject {
    /// The current persisted configuration. Reads the latest snapshot the store holds.
    func load() -> SharedConfig

    /// Replace the persisted configuration with `config`.
    func save(_ config: SharedConfig)

    /// Apply an in-place mutation to the configuration and persist the result.
    /// A no-op mutation (leaving the value unchanged) need not trigger a write.
    func mutate(_ body: (inout SharedConfig) -> Void)
}
