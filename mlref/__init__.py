"""MyLocker reference implementation (Phase 1).

This package is the *executable specification* of docs/spec/format-v1.md.
It is used as a test oracle for the C core (mlcore). It is NOT the production
implementation: key material lives in Python objects that cannot be reliably
zeroized (threat model G4 is intentionally not met here).
"""

__all__ = ["errors", "constants"]
