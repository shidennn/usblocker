"""Path rules (spec §4.5) and safe resolution under a root directory.

Defends against: path traversal / zip-slip (S18), DOS device names, ADS (`:`),
case-insensitive collisions on NTFS, and reparse-point redirection (S19).
"""

import os
import stat
import unicodedata
from pathlib import Path

from .constants import MAX_PATH_BYTES
from .errors import PathError, UnsafeFilesystemError

_FORBIDDEN = set('<>:"/\\|?*')
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def validate_component(c: str) -> None:
    if not c or c in (".", ".."):
        raise PathError(f"invalid path component {c!r}")
    for ch in c:
        if ord(ch) < 0x20 or ch in _FORBIDDEN:
            raise PathError(f"forbidden character {ch!r} in {c!r}")
    if c[-1] in ". ":
        raise PathError(f"component ends with dot or space: {c!r}")
    base = c.split(".", 1)[0].rstrip(" ").upper()
    if base in _RESERVED:
        raise PathError(f"reserved device name: {c!r}")
    if len(c.encode("utf-16-le")) // 2 > 255:
        raise PathError("component longer than 255 UTF-16 units")


def validate_path(p: str) -> None:
    """Validate a manifest path. Raises PathError."""
    if not isinstance(p, str) or not p:
        raise PathError("empty path")
    if unicodedata.normalize("NFC", p) != p:
        raise PathError("path is not NFC-normalized")
    if len(p.encode("utf-8")) > MAX_PATH_BYTES:
        raise PathError("path too long")
    for c in p.split("/"):
        validate_component(c)


def to_manifest_path(rel: Path) -> str:
    """Convert a filesystem-relative path to canonical manifest form."""
    p = unicodedata.normalize("NFC", "/".join(rel.parts))
    validate_path(p)
    return p


def collision_key(p: str) -> str:
    return p.casefold()


def parents(p: str) -> list[str]:
    parts = p.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def is_reparse_point(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def resolve_under(root: Path, manifest_path: str) -> Path:
    """Map a validated manifest path to a filesystem path under `root`.

    Every existing intermediate component is checked for reparse points so
    an attacker-planted junction cannot redirect writes outside `root`.
    """
    validate_path(manifest_path)
    target = root
    for comp in manifest_path.split("/"):
        target = target / comp
        if is_reparse_point(target):
            raise UnsafeFilesystemError(f"reparse point in path: {target}")
    # Defense in depth: lexical containment check.
    root_abs = os.path.abspath(root)
    tgt_abs = os.path.abspath(target)
    if os.path.commonpath([root_abs, tgt_abs]) != root_abs:
        raise PathError("path escapes vault root")
    return target
