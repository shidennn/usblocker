"""Reference CLI.

    python -m mlref keygen  <usb_root> [--label L]
    python -m mlref init    <folder> [--key K | --usb X:] [--no-password] [--no-recovery]
    python -m mlref unlock  <folder> [--key K | --usb X: | --recovery]
    python -m mlref lock    <folder> [--key K | --usb X: | --recovery]
    python -m mlref ls      <folder> ...
    python -m mlref extract <folder> <path-in-vault> <dst> ...
    python -m mlref verify  <folder> ...

If neither --key nor --usb is given, removable drives are searched for
\\MyLocker\\keys\\*.mlk files.
"""

import argparse
import getpass
import sys
from pathlib import Path

from . import ops
from .constants import SLOT_USB_PASSWORD, VAULT_DIR, VAULT_FILE
from .errors import FormatError, MyLockerError
from .keyfile import KeyFile, recovery_decode
from .vault import Credentials, parse_unauthenticated

KEYS_SUBDIR = Path("MyLocker") / "keys"


def removable_roots() -> list[Path]:
    if sys.platform != "win32":
        return []
    import ctypes

    k32 = ctypes.windll.kernel32
    mask = k32.GetLogicalDrives()
    roots = []
    for i in range(26):
        if mask & (1 << i):
            r = f"{chr(65 + i)}:\\"
            if k32.GetDriveTypeW(r) == 2:  # DRIVE_REMOVABLE
                roots.append(Path(r))
    return roots


def find_keyfiles(explicit_key: str | None, usb: str | None) -> list[KeyFile]:
    if explicit_key:
        return [KeyFile.load(Path(explicit_key))]
    roots = [Path(usb if usb.endswith("\\") else usb + "\\")] if usb else removable_roots()
    found = []
    for r in roots:
        d = r / KEYS_SUBDIR
        if d.is_dir():
            for f in sorted(d.glob("*.mlk")):
                try:
                    found.append(KeyFile.load(f))
                except FormatError as e:
                    print(f"warning: ignoring {f}: {e}", file=sys.stderr)
    return found


def _needs_password(folder: Path) -> bool:
    try:
        hdr, *_ = parse_unauthenticated((folder / VAULT_DIR / VAULT_FILE).read_bytes())
    except (OSError, FormatError):
        return False
    return any(s.slot_type == SLOT_USB_PASSWORD for s in hdr.slots)


def creds_from_args(a) -> Credentials:
    if a.recovery:
        return Credentials(recovery_key=recovery_decode(getpass.getpass("Recovery key: ")))
    kfs = find_keyfiles(a.key, a.usb)
    if not kfs:
        raise MyLockerError("no MyLocker key file found (insert the USB key or use --key)")
    pw = getpass.getpass("Password: ") if _needs_password(Path(a.folder)) else None
    return Credentials(keyfiles=tuple(kfs), password=pw)


def _print_report(r: ops.Report) -> None:
    for k in ("encrypted", "reused", "extracted", "deleted_plaintext", "gc_removed"):
        v = getattr(r, k)
        if v:
            print(f"  {k}: {v}")
    for w in r.warnings:
        print(f"  WARNING: {w}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mlref", description="MyLocker reference CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen")
    k.add_argument("usb_root")
    k.add_argument("--label", default="")

    def common(sp, recovery=True):
        sp.add_argument("folder")
        sp.add_argument("--key")
        sp.add_argument("--usb")
        if recovery:
            sp.add_argument("--recovery", action="store_true")

    i = sub.add_parser("init")
    common(i, recovery=False)
    i.add_argument("--no-password", action="store_true")
    i.add_argument("--no-recovery", action="store_true")
    for name in ("unlock", "lock", "ls", "verify"):
        common(sub.add_parser(name))
    e = sub.add_parser("extract")
    common(e)
    e.add_argument("path")
    e.add_argument("dst")

    a = p.parse_args(argv)
    try:
        if a.cmd == "keygen":
            kf = KeyFile.generate(a.label)
            path = kf.save(Path(a.usb_root) / KEYS_SUBDIR)
            print(f"key file written: {path}")
            print("WARNING: anyone who copies this file holds one factor of your vaults.")
            return 0
        if a.cmd == "init":
            kfs = find_keyfiles(a.key, a.usb)
            if len(kfs) != 1:
                raise MyLockerError(f"expected exactly one key file, found {len(kfs)}; use --key")
            pw = None
            if not a.no_password:
                pw = getpass.getpass("New password: ")
                if pw != getpass.getpass("Repeat password: "):
                    raise MyLockerError("passwords do not match")
                if not pw:
                    raise MyLockerError("empty password (use --no-password for USB-only mode)")
            else:
                print("WARNING: USB-only mode - a copy of the USB stick unlocks the vault.")
            r = ops.init(Path(a.folder), kfs[0], pw, with_recovery=not a.no_recovery)
            print("vault created and locked.")
            _print_report(r)
            if r.recovery_key:
                print("\nRECOVERY KEY (write it down, store it offline, it is shown only once):")
                print(f"  {r.recovery_key}\n")
            return 0
        creds = creds_from_args(a)
        if a.cmd == "unlock":
            r = ops.unlock(Path(a.folder), creds)
            print("unlocked.")
            _print_report(r)
        elif a.cmd == "lock":
            r = ops.lock(Path(a.folder), creds)
            print("locked.")
            _print_report(r)
        elif a.cmd == "ls":
            ov = ops.list_files(Path(a.folder), creds)
            for mp in sorted(ov.manifest.dirs):
                print(f"{'<DIR>':>12}  {mp}/")
            for mp, fe in sorted(ov.manifest.files.items()):
                print(f"{fe.size:>12}  {mp}")
        elif a.cmd == "extract":
            ops.extract(Path(a.folder), creds, a.path, Path(a.dst))
            print("extracted.")
        elif a.cmd == "verify":
            errs = ops.verify(Path(a.folder), creds)
            for err in errs:
                print(f"  FAIL: {err}")
            print("OK" if not errs else f"{len(errs)} file(s) failed verification")
            return 0 if not errs else 2
        return 0
    except MyLockerError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
