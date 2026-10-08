"""USB key file (spec §2) and recovery key (spec §6)."""

import base64
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from . import rng as _rng
from .constants import (
    KEY_LEN,
    KEYFILE_FIXED_LEN,
    KEYFILE_MAGIC,
    KEYFILE_MAX_LABEL,
    KEYFILE_VERSION,
    L_KEYCHECK,
    L_RECOVERY_CHECK,
)
from .crypto import ct_equal, hkdf, sha256
from .errors import FormatError

_FIXED = struct.Struct("<8sHH16s32sQ8sH")  # 78 bytes
assert _FIXED.size == KEYFILE_FIXED_LEN


@dataclass(frozen=True)
class KeyFile:
    key_id: bytes
    k_usb: bytes
    created: int
    label: str

    def __repr__(self) -> str:  # never print secrets
        return f"KeyFile(key_id={self.key_id.hex()}, label={self.label!r})"

    @staticmethod
    def generate(label: str = "", rng: _rng.Rng = _rng.SYSTEM, created: int | None = None) -> "KeyFile":
        key_id = rng.bytes(16)
        k_usb = rng.bytes(KEY_LEN)
        return KeyFile(key_id, k_usb, int(time.time()) if created is None else created, label)

    def to_bytes(self) -> bytes:
        label = self.label.encode("utf-8")
        if len(label) > KEYFILE_MAX_LABEL:
            raise FormatError("label too long")
        check = hkdf(self.k_usb, self.key_id, L_KEYCHECK, 8)
        return _FIXED.pack(KEYFILE_MAGIC, KEYFILE_VERSION, 0, self.key_id, self.k_usb,
                           self.created, check, len(label)) + label

    @staticmethod
    def from_bytes(data: bytes) -> "KeyFile":
        if len(data) < KEYFILE_FIXED_LEN:
            raise FormatError("key file too short")
        magic, ver, flags, key_id, k_usb, created, check, label_len = _FIXED.unpack_from(data)
        if magic != KEYFILE_MAGIC:
            raise FormatError("not a MyLocker key file")
        if ver != KEYFILE_VERSION or flags != 0:
            raise FormatError("unsupported key file version/flags")
        if label_len > KEYFILE_MAX_LABEL or len(data) != KEYFILE_FIXED_LEN + label_len:
            raise FormatError("key file length mismatch")
        if not ct_equal(check, hkdf(k_usb, key_id, L_KEYCHECK, 8)):
            raise FormatError("key file corrupted (check value mismatch)")
        try:
            label = data[KEYFILE_FIXED_LEN:].decode("utf-8")
        except UnicodeDecodeError:
            raise FormatError("key file label is not UTF-8") from None
        return KeyFile(key_id, k_usb, created, label)

    def save(self, directory: Path) -> Path:
        """Write to <directory>/<hex(key_id)>.mlk. Refuses to overwrite."""
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.key_id.hex()}.mlk"
        with open(path, "xb") as f:
            f.write(self.to_bytes())
            f.flush()
            import os

            os.fsync(f.fileno())
        return path

    @staticmethod
    def load(path: Path) -> "KeyFile":
        return KeyFile.from_bytes(Path(path).read_bytes())


# --- recovery key ----------------------------------------------------------

def recovery_generate(rng: _rng.Rng = _rng.SYSTEM) -> bytes:
    return rng.bytes(KEY_LEN)


def recovery_encode(key: bytes) -> str:
    assert len(key) == KEY_LEN
    data = key + sha256(L_RECOVERY_CHECK + key)[:2]
    text = base64.b32encode(data).decode("ascii").rstrip("=")
    assert len(text) == 55
    return "-".join(text[i:i + 5] for i in range(0, 55, 5))


def recovery_decode(text: str) -> bytes:
    s = "".join(ch for ch in text.upper() if ch not in " -\t\r\n")
    if len(s) != 55:
        raise FormatError("recovery key must be 55 characters (11 groups of 5)")
    try:
        data = base64.b32decode(s + "=" * 1)  # 55 chars -> pad to 56
    except Exception:
        raise FormatError("recovery key contains invalid characters") from None
    if len(data) != 34:
        raise FormatError("recovery key length mismatch")
    key, chk = data[:32], data[32:]
    if not ct_equal(chk, sha256(L_RECOVERY_CHECK + key)[:2]):
        raise FormatError("recovery key checksum mismatch (typo?)")
    return key
