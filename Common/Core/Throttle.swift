/// Rate limiting/throttling utility
//
//  Abstract:
//  An object that throttles responses from the local HTTP server.
//
//  Copyright (c) 2024 Apple Inc.
//  Copyright (c) 2026 Jay Jones
//  SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//

import Foundation

public class Throttle {
    internal let queue: DispatchQueue
    internal let timeout: DispatchTimeInterval
    internal let timerSource: DispatchSourceTimer
    internal var scheduled = false
    /// Whether ``resume()`` has been called. A `DispatchSource` is created suspended, and
    /// releasing one that was never resumed traps in libdispatch, so ``deinit`` must resume it
    /// before letting go. Guarded by ``queue``.
    private var resumed = false
    public typealias Block = () -> Void

    public init(timeout: DispatchTimeInterval, _ label: String) {
        queue = DispatchQueue(label: label)
        timerSource = DispatchSource.makeTimerSource(flags: [], queue: queue)
        self.timeout = timeout
    }

    public func signal() {
        queue.async {
            guard !self.scheduled else { return }
            self.timerSource.schedule(deadline: DispatchTime.now().advanced(by: self.timeout))
            self.scheduled = true
        }
    }

    public var handler: Block? {
        willSet {
            assert(handler == nil, "handler set twice")
        }
        didSet {
            timerSource.setEventHandler { [weak self] in
                guard let strongSelf = self else { return }
                strongSelf.scheduled = false
                strongSelf.handler?()
            }
        }
    }

    // You need to set the handler before calling resume.
    public func resume() {
        assert(handler != nil, "handler not set")
        queue.sync {
            guard !resumed else { return }
            resumed = true
            timerSource.resume()
        }
    }

    /// Cancels the timer, leaving the source safe to release.
    ///
    /// Idempotent, and safe whether or not ``resume()`` was ever called: a suspended source is
    /// resumed first, because releasing a suspended `DispatchSource` traps in libdispatch
    /// (`_dispatch_queue_xref_dispose`). Cancelling before resuming means the event handler
    /// never fires.
    public func cancel() {
        queue.sync {
            timerSource.setEventHandler(handler: nil)
            timerSource.cancel()
            if !resumed {
                resumed = true
                timerSource.resume()
            }
        }
    }

    deinit {
        // A `Throttle` built but never resumed (e.g. a `StandaloneServer` that was never run)
        // would otherwise crash on release.
        //
        // Done inline rather than via ``cancel()``: nothing else can hold a reference at this
        // point, so the queue hop is unnecessary, and `queue.sync` from `deinit` would deadlock
        // if deallocation ever happened on `queue` itself.
        timerSource.setEventHandler(handler: nil)
        timerSource.cancel()
        if !resumed { timerSource.resume() }
    }
}
