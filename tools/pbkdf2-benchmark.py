#!/usr/bin/env python3
"""Benchmark PBKDF2-HMAC-SHA512 to find iteration count for target runtime."""

import hashlib
import time

TARGET = 0.20  # seconds
password = b"test-password"
salt = b"12345678"
iters = 50000


def measure(iterations):
    t0 = time.time()
    hashlib.pbkdf2_hmac("sha512", password, salt, iterations)
    return time.time() - t0


while True:
    t = measure(iters)
    if t > TARGET:
        print(f"{iters:,}")
        break
    iters = int(iters * 1.5)
