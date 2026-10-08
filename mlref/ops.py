"""High-level vault operations (MVP workflow: unlock -> edit -> lock)."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from . import pathsafe
from . import rng as _rng
from . import vault as _vault
from .constants import PRODUCTION_POLICY, SLOT_RECOVERY, SLOT_USB, SLOT_USB_PASSWORD, KdfPolicy
from .errors import StateError
from .fsops import (
    Layout,
    ScanItem,
    commit,
    dir_entries_for,
    extract_blob,
    garbage_collect,
    scan_tree,
    secure_delete,
    verify_blob,
    write_blob,
)
from .keyfile import KeyFile, recovery_encode, recovery_generate
from .manifest import FileEntry, Manifest
from .vault import Credentials, OpenVault


@dataclass
class Report:
    encrypted: int = 0
    reused: int = 0
    extracted: int = 0
    deleted_plaintext: int = 0
    gc_removed: int = 0
    warnings: list[str] = field(default_factory=list)
    recovery_key: str | None = None


def _open(lay: Layout, creds: Credentials, policy: KdfPolicy, use_backup: bool = False) -> OpenVault:
    src = lay.vault_bak if use_backup else lay.vault_file
    if not src.exists():
        raise StateError(f"no vault at {lay.root}")
    return _vault.open_vault(src.read_bytes(), creds, policy)


def _import(lay: Layout, ov: OpenVault, files: dict[str, ScanItem], dirs: dict[str, ScanItem],
            rng: _rng.Rng, report: Report) -> Manifest:
    """Build a new manifest from a scan, reusing unchanged blobs."""
    new_files: dict[str, FileEntry] = {}
    for mp, it in files.items():
        old = ov.manifest.files.get(mp)
        if old is not None and old.size == it.size and old.mtime_ns == it.mtime_ns:
            new_files[mp] = old
            report.reused += 1
        else:
            new_files[mp] = write_blob(lay, ov, it.fs_path, mp, it, rng)
            report.encrypted += 1
    m = Manifest(new_files, dir_entries_for(files, dirs))
    m.validate()
    return m


def _remove_plaintext(files: dict[str, ScanItem], dirs: dict[str, ScanItem], rng: _rng.Rng,
                      report: Report) -> bool:
    """Delete working copies that are unchanged since the scan. Returns True if all removed."""
    clean = True
    for mp, it in files.items():
        try:
            st = os.lstat(it.fs_path)
        except FileNotFoundError:
            continue
        if st.st_size != it.size or st.st_mtime_ns != it.mtime_ns:
            report.warnings.append(f"'{mp}' changed during lock; left as plaintext (lock again)")
            clean = False
            continue
        try:
            secure_delete(it.fs_path, rng)
            report.deleted_plaintext += 1
        except OSError as e:
            report.warnings.append(f"could not delete '{mp}' (in use?): {e}")
            clean = False
    for mp in sorted(dirs, key=lambda p: p.count("/"), reverse=True):
        try:
            os.rmdir(dirs[mp].fs_path)
        except OSError:
            clean = False
            report.warnings.append(f"directory '{mp}' not empty; left in place")
    return clean


# --- public API --------------------------------------------------------------

def init(root: Path, keyfile: KeyFile, password: str | None, *, with_recovery: bool = True,
         policy: KdfPolicy = PRODUCTION_POLICY, rng: _rng.Rng = _rng.SYSTEM, chunk_log2: int = 16) -> Report:
    """Turn an existing folder into a locked vault."""
    root = Path(root).resolve()
    lay = Layout(root)
    if lay.vault_file.exists():
        raise StateError("folder is already a vault")
    if pathsafe.is_reparse_point(root):
        raise StateError("vault root must not be a reparse point")
    report = Report()
    files, dirs = scan_tree(root)  # scan before creating .mylocker

    slots: list[tuple[int, dict]] = []
    if password:
        slots.append((SLOT_USB_PASSWORD, {"keyfile": keyfile, "password": password}))
    else:
        slots.append((SLOT_USB, {"keyfile": keyfile}))
    rec = None
    if with_recovery:
        rec = recovery_generate(rng)
        slots.append((SLOT_RECOVERY, {"recovery_key": rec}))
        report.recovery_key = recovery_encode(rec)
    ov = _vault.create(slots, chunk_log2=chunk_log2, policy=policy, rng=rng)

    if lay.vdir.exists():  # leftovers of an interrupted init (no vault.mlv): start clean
        import shutil

        shutil.rmtree(lay.vdir)
    lay.vdir.mkdir()
    ov.manifest = _import(lay, ov, files, dirs, rng, report)
    commit(lay, ov, rng)
    if not _remove_plaintext(files, dirs, rng, report):
        lay.state.write_text("unlocked")
    return report


def unlock(root: Path, creds: Credentials, *, policy: KdfPolicy = PRODUCTION_POLICY,
           rng: _rng.Rng = _rng.SYSTEM, use_backup: bool = False) -> Report:
    """Decrypt all files into the folder as working copies."""
    lay = Layout(Path(root).resolve())
    ov = _open(lay, creds, policy, use_backup)
    resuming = lay.state.exists()
    lay.state.write_text("unlocked")  # before extracting: a crash leaves a lockable state
    report = Report()
    for mp in sorted(ov.manifest.dirs, key=lambda p: p.count("/")):
        d = pathsafe.resolve_under(lay.root, mp)
        d.mkdir(exist_ok=True)
    for mp, fe in sorted(ov.manifest.files.items()):
        dst = pathsafe.resolve_under(lay.root, mp)
        if dst.exists():
            st = os.lstat(dst)
            if resuming and st.st_size == fe.size and st.st_mtime_ns == fe.mtime_ns:
                continue
            raise StateError(f"'{mp}' already exists in the folder; refusing to overwrite")
        extract_blob(lay, ov, fe, dst, rng)
        report.extracted += 1
    for mp, de in ov.manifest.dirs.items():
        os.utime(pathsafe.resolve_under(lay.root, mp), ns=(de.mtime_ns, de.mtime_ns))
    return report


def lock(root: Path, creds: Credentials, *, policy: KdfPolicy = PRODUCTION_POLICY,
         rng: _rng.Rng = _rng.SYSTEM, allow_empty: bool = False) -> Report:
    """Re-encrypt working copies (only changed files), commit, delete plaintext."""
    lay = Layout(Path(root).resolve())
    if not lay.state.exists():
        raise StateError("vault is not unlocked (no state marker); refusing to commit an empty view")
    ov = _open(lay, creds, policy)
    files, dirs = scan_tree(lay.root)
    if not files and ov.manifest.files and not allow_empty:
        raise StateError("folder is empty but vault has files; use allow_empty to delete everything")
    report = Report()
    ov.manifest = _import(lay, ov, files, dirs, rng, report)
    ov.header.epoch += 1
    commit(lay, ov, rng)
    if _remove_plaintext(files, dirs, rng, report):
        lay.state.unlink()
    report.gc_removed = garbage_collect(lay, ov)
    return report


def list_files(root: Path, creds: Credentials, *, policy: KdfPolicy = PRODUCTION_POLICY) -> OpenVault:
    return _open(Layout(Path(root).resolve()), creds, policy)


def extract(root: Path, creds: Credentials, mpath: str, dst: Path, *,
            policy: KdfPolicy = PRODUCTION_POLICY, rng: _rng.Rng = _rng.SYSTEM) -> None:
    lay = Layout(Path(root).resolve())
    ov = _open(lay, creds, policy)
    fe = ov.manifest.files.get(mpath)
    if fe is None:
        raise StateError(f"no such file in vault: {mpath}")
    dst = Path(dst)
    if dst.exists():
        raise StateError(f"destination exists: {dst}")
    extract_blob(lay, ov, fe, dst, rng)


def verify(root: Path, creds: Credentials, *, policy: KdfPolicy = PRODUCTION_POLICY) -> list[str]:
    """Authenticate every blob. Returns list of error strings (empty = OK)."""
    lay = Layout(Path(root).resolve())
    ov = _open(lay, creds, policy)
    errors = []
    for fe in ov.manifest.files.values():
        try:
            verify_blob(lay, ov, fe)
        except Exception as e:  # report all, don't stop at first
            errors.append(str(e))
    return errors
