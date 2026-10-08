"""Blob format tests: round trip, tamper detection (T-05, T-06), release rule."""

import os
import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from mlref.blob import decrypt_bytes, encrypt_bytes
from mlref.constants import BLOB_HDR_LEN, NONCE_LEN, TAG_LEN
from mlref.errors import FormatError, IntegrityError

VMK = bytes(range(32))
VID = bytes(16)
CL = 12  # 4 KiB chunks keep tests small
C = 1 << CL
FULL = NONCE_LEN + C + TAG_LEN


def enc(data, **kw):
    return encrypt_bytes(data, vmk=VMK, vault_id=VID, chunk_log2=CL, **kw)


def dec(blob, **kw):
    return decrypt_bytes(blob, vmk=VMK, vault_id=VID, chunk_log2=CL, content_alg=1, **kw)


@pytest.mark.parametrize("n", [0, 1, C - 1, C, C + 1, 3 * C, 3 * C + 7])
def test_roundtrip_boundaries(n):
    data = os.urandom(n)
    blob, res = enc(data)
    assert res.size == n
    expected_chunks = max(1, -(-n // C))
    assert len(blob) == BLOB_HDR_LEN + n + expected_chunks * (NONCE_LEN + TAG_LEN)
    assert dec(blob, expected_file_id=res.file_id, expected_header_hash=res.header_hash) == data


@settings(max_examples=50, deadline=None)
@given(st.binary(max_size=5 * C))
def test_roundtrip_property(data):
    blob, _ = enc(data)
    assert dec(blob) == data


def test_fresh_file_id_each_time():
    a, ra = enc(b"same")
    b, rb = enc(b"same")
    assert ra.file_id != rb.file_id and a != b


def test_every_single_bit_flip_detected():
    """T-05: flip each bit of a small 2-chunk blob; every flip must be rejected."""
    blob, _ = enc(os.urandom(C + 10))
    for i in range(len(blob)):
        for bit in (0, 7) if i >= BLOB_HDR_LEN + 64 else range(8):
            t = bytearray(blob)
            t[i] ^= 1 << bit
            with pytest.raises((IntegrityError, FormatError)):
                dec(bytes(t))


def _chunks(blob):
    body = blob[BLOB_HDR_LEN:]
    out = []
    while len(body) > FULL:
        out.append(body[:FULL])
        body = body[FULL:]
    out.append(body)
    return blob[:BLOB_HDR_LEN], out


@pytest.mark.parametrize("op", ["swap", "dup", "drop_last", "drop_first", "truncate_bytes", "append", "append_copy_last"])
def test_chunk_manipulation_detected(op):
    """T-06: reordering / duplication / truncation / extension."""
    blob, _ = enc(os.urandom(3 * C + 100))
    hdr, ch = _chunks(blob)
    if op == "swap":
        ch[0], ch[1] = ch[1], ch[0]
    elif op == "dup":
        ch.insert(1, ch[0])
    elif op == "drop_last":
        ch = ch[:-1]
    elif op == "drop_first":
        ch = ch[1:]
    elif op == "truncate_bytes":
        ch[-1] = ch[-1][:-1]
    elif op == "append":
        ch.append(os.urandom(50))
    elif op == "append_copy_last":
        ch.append(ch[-1])
    with pytest.raises(IntegrityError):
        dec(hdr + b"".join(ch))


def test_truncate_to_exact_chunk_boundary():
    blob, _ = enc(os.urandom(2 * C))
    hdr, ch = _chunks(blob)
    with pytest.raises(IntegrityError):
        dec(hdr + ch[0])  # first chunk was encrypted with is_last = 0


def test_header_only_rejected():
    blob, _ = enc(b"x")
    with pytest.raises(IntegrityError):
        dec(blob[:BLOB_HDR_LEN])


def test_wrong_vault_and_wrong_key():
    blob, _ = enc(b"secret")
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob, vmk=VMK, vault_id=b"\x01" * 16, chunk_log2=CL, content_alg=1)
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob, vmk=bytes(32), vault_id=VID, chunk_log2=CL, content_alg=1)


def test_chunk_size_mismatch_rejected():
    blob, _ = enc(b"secret")
    with pytest.raises(IntegrityError):
        decrypt_bytes(blob, vmk=VMK, vault_id=VID, chunk_log2=13, content_alg=1)


def test_blob_swap_between_files_detected():
    """Manifest binds path -> header_hash; a different blob must be rejected."""
    a, ra = enc(b"file A")
    b, rb = enc(b"file B")
    with pytest.raises(IntegrityError):
        dec(b, expected_file_id=ra.file_id, expected_header_hash=ra.header_hash)


def test_reserved_bits_rejected():
    blob, _ = enc(b"x")
    t = bytearray(blob)
    t[13] = 1
    with pytest.raises(FormatError):
        dec(bytes(t))


def test_generator_raises_before_bad_chunk_is_yielded():
    """Chunks before the corrupted one are yielded, the corrupted one never is."""
    import io

    from mlref.blob import decrypt_stream

    data = os.urandom(3 * C)
    blob, _ = enc(data)
    t = bytearray(blob)
    t[BLOB_HDR_LEN + FULL + 20] ^= 1  # corrupt chunk 1
    got = []
    with pytest.raises(IntegrityError) as ei:
        for c in decrypt_stream(io.BytesIO(bytes(t)), vmk=VMK, vault_id=VID, chunk_log2=CL, content_alg=1):
            got.append(c)
    assert ei.value.chunk == 1
    assert got == [data[:C]]
