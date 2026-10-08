"""Error hierarchy. Mirrors `enum ml_err` in the C core."""


class MyLockerError(Exception):
    """Base class."""


class FormatError(MyLockerError):
    """Malformed / unsupported structure (bad magic, version, length, reserved bits)."""


class IntegrityError(MyLockerError):
    """Authentication failed: data was modified or does not belong here."""

    def __init__(self, msg: str, *, path: str | None = None, chunk: int | None = None):
        super().__init__(msg)
        self.path = path
        self.chunk = chunk

    def __str__(self) -> str:
        s = super().__str__()
        if self.path is not None:
            s += f" [file={self.path}]"
        if self.chunk is not None:
            s += f" [chunk={self.chunk}]"
        return s


class AuthError(MyLockerError):
    """Wrong key file, password or recovery key (deliberately not more specific)."""


class KdfPolicyError(FormatError):
    """Argon2id parameters outside accepted bounds (downgrade / DoS protection)."""


class PathError(MyLockerError):
    """Path violates spec §4.5 or would escape the vault root."""


class StateError(MyLockerError):
    """Operation not allowed in the current vault state."""


class UnsafeFilesystemError(MyLockerError):
    """Reparse point / junction / symlink encountered."""
