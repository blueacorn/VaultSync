/// Logger extension for unredacted output in sandboxed processes.
// Copyright (c) 2026 Jay Jones
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
import os.log

public extension Logger {
    /// Logs a debug message with `.public` privacy, preventing redaction by host processes such as `providerd`.
    @inline(__always) func debugPublic(_ message: @autoclosure () -> String) {
        let m = message()
        debug("\(m, privacy: .public)")
    }

    /// Logs an info message with `.public` privacy.
    @inline(__always) func infoPublic(_ message: @autoclosure () -> String) {
        let m = message()
        info("\(m, privacy: .public)")
    }

    /// Logs a warning message with `.public` privacy.
    @inline(__always) func warningPublic(_ message: @autoclosure () -> String) {
        let m = message()
        warning("\(m, privacy: .public)")
    }

    /// Logs an error message with `.public` privacy.
    @inline(__always) func errorPublic(_ message: @autoclosure () -> String) {
        let m = message()
        error("\(m, privacy: .public)")
    }

    /// Logs a fault message with `.public` privacy.
    @inline(__always) func faultPublic(_ message: @autoclosure () -> String) {
        let m = message()
        fault("\(m, privacy: .public)")
    }
}
