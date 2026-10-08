"""Key file, recovery key, manifest TLV and path rule tests (incl. T-10)."""

import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mlref import pathsafe
from mlref.constants import TLV_FILE, TLV_INFO
from mlref.errors import FormatError, PathError
from mlref.keyfile import KeyFile, recovery_decode, recovery_encode, recovery_generate
from mlref.manifest import DirEntry, FileEntry, Manifest


# --- key file ---------------------------------------------------------------

def test_keyfile_roundtrip(keyfile):
    b = keyfile.to_bytes()
    assert len(b) == 78 + len("test")
    assert KeyFile.from_bytes(b) == keyfile


def test_keyfile_repr_hides_secret(keyfile):
    assert keyfile.k_usb.hex() not in repr(keyfile)


@pytest.mark.parametrize("off", [0, 8, 10, 20, 40, 70, 77])
def test_keyfile_corruption_detected(keyfile, off):
    b = bytearray(keyfile.to_bytes())
    b[off] ^= 1
    with pytest.raises(FormatError):
        KeyFile.from_bytes(bytes(b))


def test_keyfile_trailing_data(keyfile):
    with pytest.raises(FormatError):
        KeyFile.from_bytes(keyfile.to_bytes() + b"x")


def test_keyfile_save_refuses_overwrite(tmp_path, keyfile):
    keyfile.save(tmp_path)
    with pytest.raises(FileExistsError):
        keyfile.save(tmp_path)


# --- recovery key -----------------------------------------------------------

def test_recovery_roundtrip():
    k = recovery_generate()
    s = recovery_encode(k)
    assert len(s) == 55 + 10 and s.count("-") == 10
    assert recovery_decode(s) == k
    assert recovery_decode(s.lower().replace("-", " ")) == k


def test_recovery_typo_detected():
    k = recovery_generate()
    s = list(recovery_encode(k))
    s[3] = "A" if s[3] != "A" else "B"
    with pytest.raises(FormatError):
        recovery_decode("".join(s))


# --- path rules -------------------------------------------------------------

@pytest.mark.parametrize("p", [
    "../x", "a/../b", "/abs", "C:/x", "a\\b", "a:stream", "CON", "con.txt", "nul.tar.gz",
    "COM1", "lpt9.doc", "a/./b", "a//b", "a/", "trail.", "trail ", "x\x00y", "x\ny",
    "a?b", "a*b", 'a"b', "a<b", "a|b", "", "e\u0301",  # last: NFD
])
def test_bad_paths_rejected(p):
    with pytest.raises(PathError):
        pathsafe.validate_path(p)


@pytest.mark.parametrize("p", ["a", "a/b/c.txt", "Türkçe ğüşiöç/dosya.docx", "CONFIG.SYS", "com10", ".hidden", "a b/c d"])
def test_good_paths_accepted(p):
    pathsafe.validate_path(p)


def test_resolve_under_stays_inside(tmp_path):
    assert pathsafe.resolve_under(tmp_path, "a/b") == tmp_path / "a" / "b"
    with pytest.raises(PathError):
        pathsafe.resolve_under(tmp_path, "../evil")


# --- manifest ---------------------------------------------------------------

def _fe(path, fid=b"\x01" * 32):
    return FileEntry(path, fid, 5, 123, 0x20, b"\x02" * 32)


def _m(files=(), dirs=()):
    return Manifest({f.path: f for f in files}, {d: DirEntry(d, 1, 0) for d in dirs})


def test_manifest_roundtrip_and_canonical():
    m = _m([_fe("b.txt"), _fe("a/z.txt"), _fe("a/b.txt")], ["a"])
    enc = m.encode()
    m2 = Manifest.decode(enc)
    assert m2 == m
    assert m2.encode() == enc


def test_manifest_empty():
    assert Manifest.decode(Manifest.empty().encode()) == Manifest.empty()


def test_manifest_missing_parent():
    with pytest.raises(FormatError):
        _m([_fe("a/b.txt")]).encode()


def test_manifest_case_collision():
    with pytest.raises(PathError):
        _m([_fe("A.txt"), _fe("a.txt")]).encode()


def _raw(*records):
    return b"".join(struct.pack("<HI", t, len(v)) + v for t, v in records)


INFO = (TLV_INFO, struct.pack("<H", 1))


def _file_val(path):
    return struct.pack("<32sQQI32s", b"\x01" * 32, 1, 1, 0, b"\x02" * 32) + path.encode()


def test_manifest_malicious_traversal_rejected():
    """T-10: attacker-crafted manifest with traversal paths."""
    for p in ["../../Windows/x", "C:/x", "a:b", "CON"]:
        with pytest.raises(PathError):
            Manifest.decode(_raw(INFO, (TLV_FILE, _file_val(p))))


def test_manifest_order_and_duplicates():
    with pytest.raises(FormatError):
        Manifest.decode(_raw(INFO, (TLV_FILE, _file_val("b")), (TLV_FILE, _file_val("a"))))
    with pytest.raises(FormatError):
        Manifest.decode(_raw(INFO, (TLV_FILE, _file_val("a")), (TLV_FILE, _file_val("a"))))


def test_manifest_unknown_types():
    Manifest.decode(_raw(INFO, (0x0042, b"ignored")))  # non-critical: skipped
    with pytest.raises(FormatError):
        Manifest.decode(_raw(INFO, (0x8042, b"x")))   # critical: rejected


def test_manifest_info_required_first():
    with pytest.raises(FormatError):
        Manifest.decode(_raw((TLV_FILE, _file_val("a")), INFO))
    with pytest.raises(FormatError):
        Manifest.decode(b"")


@settings(max_examples=300, deadline=None)
@given(st.binary(max_size=400))
def test_manifest_decoder_never_crashes(data):
    """Fuzz-like property: arbitrary bytes produce a Manifest or a defined error."""
    try:
        Manifest.decode(data)
    except (FormatError, PathError):
        pass
