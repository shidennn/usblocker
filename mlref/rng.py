"""Randomness source abstraction.

Production code uses the OS CSPRNG (os.urandom -> BCryptGenRandom on Windows).
Tests inject a deterministic generator to produce reproducible test vectors that
the C implementation must match byte for byte (ADR-06, test T-12).
"""

import hashlib
import os


class Rng:
    def bytes(self, n: int) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


class SystemRng(Rng):
    def bytes(self, n: int) -> bytes:
        return os.urandom(n)


class DeterministicRng(Rng):
    """SHA-256 counter-mode stream. TEST ONLY - never use for real keys.

    stream = SHA256(seed || LE64(0)) || SHA256(seed || LE64(1)) || ...
    Each call to bytes(n) consumes the next n bytes of the stream.
    """

    def __init__(self, seed: bytes):
        self._seed = seed
        self._ctr = 0
        self._buf = b""

    def bytes(self, n: int) -> bytes:
        while len(self._buf) < n:
            self._buf += hashlib.sha256(self._seed + self._ctr.to_bytes(8, "little")).digest()
            self._ctr += 1
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


SYSTEM = SystemRng()
