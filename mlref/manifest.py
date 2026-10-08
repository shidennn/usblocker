"""Manifest TLV encoding (spec §4.4). Flat records, no nesting, canonical order."""

import struct
from dataclasses import dataclass

from . import pathsafe
from .constants import (
    DIR_FIXED_LEN,
    FILE_FIXED_LEN,
    MANIFEST_VERSION,
    MAX_RECORDS,
    TLV_CRITICAL,
    TLV_DIR,
    TLV_FILE,
    TLV_HDR_LEN,
    TLV_INFO,
    TLV_MAX_VALUE,
)
from .errors import FormatError, PathError

_HDR = struct.Struct("<HI")
_FILE = struct.Struct("<32sQQI32s")
_DIR = struct.Struct("<QI")
assert _FILE.size == FILE_FIXED_LEN and _DIR.size == DIR_FIXED_LEN


@dataclass(frozen=True)
class FileEntry:
    path: str
    file_id: bytes
    size: int
    mtime_ns: int
    attrs: int
    header_hash: bytes


@dataclass(frozen=True)
class DirEntry:
    path: str
    mtime_ns: int
    attrs: int


@dataclass
class Manifest:
    files: dict[str, FileEntry]
    dirs: dict[str, DirEntry]

    @staticmethod
    def empty() -> "Manifest":
        return Manifest({}, {})

    def validate(self) -> None:
        """Structural invariants: valid paths, no collisions, explicit parents."""
        seen: dict[str, str] = {}
        for p in list(self.dirs) + list(self.files):
            pathsafe.validate_path(p)
            k = pathsafe.collision_key(p)
            if k in seen:
                raise PathError(f"path collision: {seen[k]!r} vs {p!r}")
            seen[k] = p
        for p in list(self.dirs) + list(self.files):
            for parent in pathsafe.parents(p):
                if parent not in self.dirs:
                    raise FormatError(f"missing parent DIR record for {p!r}")
        for fe in self.files.values():
            if len(fe.file_id) != 32 or len(fe.header_hash) != 32:
                raise FormatError("bad FILE record")

    def encode(self) -> bytes:
        self.validate()
        out = [_rec(TLV_INFO, struct.pack("<H", MANIFEST_VERSION))]
        items: list[tuple[bytes, int, object]] = []
        for d in self.dirs.values():
            items.append((d.path.encode("utf-8"), TLV_DIR, d))
        for f in self.files.values():
            items.append((f.path.encode("utf-8"), TLV_FILE, f))
        items.sort(key=lambda x: x[0])
        for pb, t, e in items:
            if t == TLV_DIR:
                out.append(_rec(t, _DIR.pack(e.mtime_ns, e.attrs) + pb))
            else:
                out.append(_rec(t, _FILE.pack(e.file_id, e.size, e.mtime_ns, e.attrs, e.header_hash) + pb))
        return b"".join(out)

    @staticmethod
    def decode(data: bytes) -> "Manifest":
        m = Manifest.empty()
        off, n, first, prev_path = 0, 0, True, None
        while off < len(data):
            if len(data) - off < TLV_HDR_LEN:
                raise FormatError("truncated TLV header")
            t, ln = _HDR.unpack_from(data, off)
            off += TLV_HDR_LEN
            if ln > TLV_MAX_VALUE or ln > len(data) - off:
                raise FormatError("TLV length out of bounds")
            v = data[off:off + ln]
            off += ln
            n += 1
            if n > MAX_RECORDS:
                raise FormatError("too many records")
            if first:
                if t != TLV_INFO or ln != 2 or struct.unpack("<H", v)[0] != MANIFEST_VERSION:
                    raise FormatError("manifest must start with INFO v1")
                first = False
                continue
            if t == TLV_INFO:
                raise FormatError("duplicate INFO record")
            if t == TLV_FILE:
                if ln <= FILE_FIXED_LEN:
                    raise FormatError("FILE record too short")
                fid, size, mt, attrs, hh = _FILE.unpack_from(v)
                path = _path(v[FILE_FIXED_LEN:])
                entry = FileEntry(path, fid, size, mt, attrs, hh)
            elif t == TLV_DIR:
                if ln <= DIR_FIXED_LEN:
                    raise FormatError("DIR record too short")
                mt, attrs = _DIR.unpack_from(v)
                path = _path(v[DIR_FIXED_LEN:])
                entry = DirEntry(path, mt, attrs)
            elif t & TLV_CRITICAL:
                raise FormatError(f"unknown critical record type 0x{t:04x}")
            else:
                continue  # unknown non-critical: skip
            pb = path.encode("utf-8")
            if prev_path is not None and pb <= prev_path:
                raise FormatError("manifest not in canonical order (or duplicate path)")
            prev_path = pb
            if isinstance(entry, FileEntry):
                m.files[path] = entry
            else:
                m.dirs[path] = entry
        if first:
            raise FormatError("empty manifest")
        m.validate()
        return m


def _rec(t: int, v: bytes) -> bytes:
    if len(v) > TLV_MAX_VALUE:
        raise FormatError("record too large")
    return _HDR.pack(t, len(v)) + v


def _path(b: bytes) -> str:
    try:
        p = b.decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("path is not valid UTF-8") from None
    pathsafe.validate_path(p)
    return p
