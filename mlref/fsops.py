"""Filesystem operations: scan, atomic writes, commit protocol, best-effort secure delete.

All operations follow spec §7. Guiding rules (docs/plan/06 §4):
  1. Fail closed.
  2. Never delete plaintext before its ciphertext is verified AND committed.
"""

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from . import pathsafe
from . import rng as _rng
from .blob import decrypt_stream, encrypt_stream
from .constants import (
    ATTR_MASK,
    BLOB_DIR,
    L_MANIFEST,
    STATE_FILE,
    VAULT_BAK,
    VAULT_DIR,
    VAULT_FILE,
)
from .crypto import aead_decrypt, sha256
from .errors import IntegrityError, PathError, UnsafeFilesystemError
from .manifest import DirEntry, FileEntry, Manifest
from .vault import OpenVault, manifest_key, parse_unauthenticated, serialize

FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x2000
FILE_ATTRIBUTE_READONLY = 0x1

if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _k32.SetFileAttributesW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _k32.SetFileAttributesW.restype = wintypes.BOOL

    def set_attrs(path: Path, attrs: int) -> None:
        if not _k32.SetFileAttributesW(str(path), attrs or 0x80):  # 0x80 = NORMAL
            raise ctypes.WinError(ctypes.get_last_error())
else:  # pragma: no cover
    def set_attrs(path: Path, attrs: int) -> None:
        if attrs & FILE_ATTRIBUTE_READONLY:
            os.chmod(path, 0o444)


@dataclass(frozen=True)
class Layout:
    root: Path

    @property
    def vdir(self) -> Path:
        return self.root / VAULT_DIR

    @property
    def vault_file(self) -> Path:
        return self.vdir / VAULT_FILE

    @property
    def vault_bak(self) -> Path:
        return self.vdir / VAULT_BAK

    @property
    def state(self) -> Path:
        return self.vdir / STATE_FILE

    @property
    def blobs(self) -> Path:
        return self.vdir / BLOB_DIR

    def blob_path(self, file_id: bytes) -> Path:
        h = file_id.hex()
        return self.blobs / h[:2] / f"{h}.mlf"


# --- primitives ------------------------------------------------------------

def fsync_write(path: Path, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def atomic_replace(tmp: Path, dst: Path) -> None:
    os.replace(tmp, dst)  # MoveFileExW(MOVEFILE_REPLACE_EXISTING) on Windows


def file_attrs(st: os.stat_result) -> int:
    return getattr(st, "st_file_attributes", 0) & ATTR_MASK


def secure_delete(path: Path, rng: _rng.Rng = _rng.SYSTEM) -> None:
    """Best-effort overwrite + rename + delete.

    LIMITATIONS (threat model §10, R-1): on SSDs (FTL wear levelling), with
    VSS snapshots, NTFS resident data moved by defrag, or copies made by other
    programs, the plaintext may still be recoverable. This is precisely why
    Phase 6 (VFS) exists.
    """
    st = os.lstat(path)
    if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_READONLY:
        set_attrs(path, 0)
    size = st.st_size
    with open(path, "r+b", buffering=0) as f:
        block = b"\x00" * (1 << 20)
        left = size
        while left > 0:
            n = min(left, len(block))
            f.write(block[:n])
            left -= n
        f.flush()
        os.fsync(f.fileno())
    tmp = path.with_name("." + rng.bytes(8).hex() + ".del")
    os.replace(path, tmp)
    os.remove(tmp)


# --- scanning --------------------------------------------------------------

@dataclass(frozen=True)
class ScanItem:
    fs_path: Path
    size: int
    mtime_ns: int
    attrs: int


def scan_tree(root: Path) -> tuple[dict[str, ScanItem], dict[str, ScanItem]]:
    """Return (files, dirs) keyed by manifest path. Excludes the top-level
    .mylocker directory. Any reparse point aborts the scan (S19)."""
    files: dict[str, ScanItem] = {}
    dirs: dict[str, ScanItem] = {}
    seen: dict[str, str] = {}

    def walk(d: Path, rel: tuple[str, ...]) -> None:
        with os.scandir(d) as it:
            entries = sorted(it, key=lambda e: e.name)
        for e in entries:
            if not rel and e.name == VAULT_DIR:
                continue
            p = Path(e.path)
            if pathsafe.is_reparse_point(p):
                raise UnsafeFilesystemError(f"reparse point / symlink / junction not allowed: {p}")
            st = e.stat(follow_symlinks=False)
            mp = pathsafe.to_manifest_path(Path(*rel, e.name))
            k = pathsafe.collision_key(mp)
            if k in seen:
                raise PathError(f"case collision: {seen[k]!r} vs {mp!r}")
            seen[k] = mp
            item = ScanItem(p, st.st_size, st.st_mtime_ns, file_attrs(st))
            if stat.S_ISDIR(st.st_mode):
                dirs[mp] = item
                walk(p, rel + (e.name,))
            elif stat.S_ISREG(st.st_mode):
                files[mp] = item
            else:
                raise UnsafeFilesystemError(f"unsupported file type: {p}")

    walk(root, ())
    return files, dirs


# --- blobs -----------------------------------------------------------------

def write_blob(lay: Layout, ov: OpenVault, src: Path, mpath: str, item: ScanItem,
               rng: _rng.Rng = _rng.SYSTEM) -> FileEntry:
    """Encrypt src -> blob (.tmp, fsync, verify, rename). Returns manifest entry."""
    lay.blobs.mkdir(parents=True, exist_ok=True)
    tmp = lay.blobs / f"{rng.bytes(16).hex()}.mlf.tmp"
    try:
        with open(src, "rb") as fi, open(tmp, "wb") as fo:
            res = encrypt_stream(fi, fo, vmk=ov.vmk, vault_id=ov.header.vault_id,
                                 chunk_log2=ov.header.chunk_log2, rng=rng)
            fo.flush()
            os.fsync(fo.fileno())
        # Verification pass: decrypt what is on disk and compare the plaintext hash.
        import hashlib

        h = hashlib.sha256()
        with open(tmp, "rb") as f:
            for chunk in decrypt_stream(f, vmk=ov.vmk, vault_id=ov.header.vault_id,
                                        chunk_log2=ov.header.chunk_log2, content_alg=ov.header.content_alg,
                                        expected_file_id=res.file_id, expected_header_hash=res.header_hash,
                                        path_label=mpath):
                h.update(chunk)
        if h.digest() != res.plain_sha256:
            raise IntegrityError("verification after write failed", path=mpath)
        dst = lay.blob_path(res.file_id)
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, dst)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    # The file may have been modified while we read it; record what we read.
    return FileEntry(mpath, res.file_id, res.size, item.mtime_ns, item.attrs, res.header_hash)


def extract_blob(lay: Layout, ov: OpenVault, fe: FileEntry, dst: Path, rng: _rng.Rng = _rng.SYSTEM,
                 restore_meta: bool = True) -> None:
    """Decrypt to a temp file next to dst; rename only after every chunk authenticated."""
    tmp = dst.with_name("." + rng.bytes(8).hex() + ".mltmp")
    try:
        n = 0
        with open(lay.blob_path(fe.file_id), "rb") as fi, open(tmp, "xb") as fo:
            if sys.platform == "win32":
                set_attrs(tmp, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
            for chunk in decrypt_stream(fi, vmk=ov.vmk, vault_id=ov.header.vault_id,
                                        chunk_log2=ov.header.chunk_log2, content_alg=ov.header.content_alg,
                                        expected_file_id=fe.file_id, expected_header_hash=fe.header_hash,
                                        path_label=fe.path):
                fo.write(chunk)
                n += len(chunk)
            fo.flush()
            os.fsync(fo.fileno())
        if n != fe.size:
            raise IntegrityError("size differs from manifest", path=fe.path)
        os.replace(tmp, dst)  # release point
    except FileNotFoundError as e:
        tmp.unlink(missing_ok=True)
        if not lay.blob_path(fe.file_id).exists():
            raise IntegrityError("blob missing", path=fe.path) from e
        raise
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    if restore_meta:
        os.utime(dst, ns=(fe.mtime_ns, fe.mtime_ns))
        if sys.platform == "win32":
            set_attrs(dst, (fe.attrs & ATTR_MASK) | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)


def verify_blob(lay: Layout, ov: OpenVault, fe: FileEntry) -> None:
    n = 0
    try:
        f = open(lay.blob_path(fe.file_id), "rb")
    except FileNotFoundError:
        raise IntegrityError("blob missing", path=fe.path) from None
    with f:
        for chunk in decrypt_stream(f, vmk=ov.vmk, vault_id=ov.header.vault_id,
                                    chunk_log2=ov.header.chunk_log2, content_alg=ov.header.content_alg,
                                    expected_file_id=fe.file_id, expected_header_hash=fe.header_hash,
                                    path_label=fe.path):
            n += len(chunk)
    if n != fe.size:
        raise IntegrityError("size differs from manifest", path=fe.path)


# --- commit ----------------------------------------------------------------

def commit(lay: Layout, ov: OpenVault, rng: _rng.Rng = _rng.SYSTEM) -> None:
    """Spec §7 steps 2-3. Blobs must already be written (step 1)."""
    data = serialize(ov, rng)
    tmp = lay.vdir / (VAULT_FILE + ".tmp")
    fsync_write(tmp, data)
    if lay.vault_file.exists():
        bak_tmp = lay.vdir / (VAULT_BAK + ".tmp")
        fsync_write(bak_tmp, lay.vault_file.read_bytes())
        atomic_replace(bak_tmp, lay.vault_bak)
    atomic_replace(tmp, lay.vault_file)  # <-- single commit point


def _manifest_with_vmk(data: bytes, vmk: bytes) -> Manifest:
    hdr, prefix, nonce, ct = parse_unauthenticated(data)
    plain = aead_decrypt(manifest_key(vmk, hdr.vault_id), nonce, ct, L_MANIFEST + prefix)
    return Manifest.decode(plain)


def garbage_collect(lay: Layout, ov: OpenVault) -> int:
    """Delete blobs referenced by neither vault.mlv nor vault.mlv.bak, and stale temps.
    Conservative: if the backup cannot be read, only temp files are removed."""
    keep = {fe.file_id.hex() for fe in ov.manifest.files.values()}
    if lay.vault_bak.exists():
        try:
            keep |= {fe.file_id.hex() for fe in _manifest_with_vmk(lay.vault_bak.read_bytes(), ov.vmk).files.values()}
        except Exception:
            keep = None  # unknown -> delete nothing referenced
    removed = 0
    if not lay.blobs.exists():
        return 0
    for sub in lay.blobs.iterdir():
        if sub.is_file() and sub.name.endswith(".tmp"):
            sub.unlink()
            removed += 1
            continue
        if not sub.is_dir():
            continue
        for f in sub.iterdir():
            if f.name.endswith(".tmp"):
                f.unlink()
                removed += 1
            elif keep is not None and f.suffix == ".mlf" and f.stem not in keep:
                f.unlink()
                removed += 1
        try:
            sub.rmdir()
        except OSError:
            pass
    for t in lay.vdir.glob("*.tmp"):
        t.unlink()
    return removed


def dir_entries_for(files: dict[str, ScanItem], dirs: dict[str, ScanItem]) -> dict[str, DirEntry]:
    return {p: DirEntry(p, it.mtime_ns, it.attrs) for p, it in dirs.items()}
