"""File blob encryption (spec §5): chunked AES-256-GCM with STREAM-style AAD."""

import hashlib
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from . import rng as _rng
from .constants import (
    ALG_AES256GCM,
    BLOB_HDR_LEN,
    BLOB_MAGIC,
    BLOB_VERSION,
    L_COMMIT,
    L_CONTENT,
    L_FILE,
    MAX_CHUNKS,
    NONCE_LEN,
    TAG_LEN,
    WRAP_DERIVED,
)
from .crypto import aead_decrypt, aead_encrypt, ct_equal, hkdf, sha256
from .errors import FormatError, IntegrityError

_HDR = struct.Struct("<8sHBBB3s16s32s32s")
assert _HDR.size == BLOB_HDR_LEN


@dataclass(frozen=True)
class FileKeys:
    content: bytes
    commit: bytes


def derive_file_keys(vmk: bytes, vault_id: bytes, file_id: bytes) -> FileKeys:
    fk = hkdf(vmk, file_id, L_FILE + vault_id)
    return FileKeys(hkdf(fk, b"", L_CONTENT), hkdf(fk, b"", L_COMMIT))


def _aad(h: bytes, i: int, last: bool) -> bytes:
    return h + struct.pack("<QB", i, 1 if last else 0)


@dataclass(frozen=True)
class EncryptResult:
    file_id: bytes
    header_hash: bytes
    size: int
    plain_sha256: bytes


def encrypt_stream(src: BinaryIO, dst: BinaryIO, *, vmk: bytes, vault_id: bytes, chunk_log2: int,
                   rng: _rng.Rng = _rng.SYSTEM) -> EncryptResult:
    file_id = rng.bytes(32)
    keys = derive_file_keys(vmk, vault_id, file_id)
    header = _HDR.pack(BLOB_MAGIC, BLOB_VERSION, ALG_AES256GCM, chunk_log2, WRAP_DERIVED,
                       b"\x00" * 3, vault_id, file_id, keys.commit)
    h = sha256(header)
    dst.write(header)
    csize = 1 << chunk_log2
    ph = hashlib.sha256()
    total, i = 0, 0
    cur = _read_full(src, csize)
    while True:
        nxt = _read_full(src, csize) if len(cur) == csize else b""
        last = len(nxt) == 0
        if i >= MAX_CHUNKS:
            raise FormatError("file too large for one key")
        nonce = rng.bytes(NONCE_LEN)
        dst.write(nonce + aead_encrypt(keys.content, nonce, cur, _aad(h, i, last)))
        ph.update(cur)
        total += len(cur)
        i += 1
        if last:
            break
        cur = nxt
    return EncryptResult(file_id, h, total, ph.digest())


def encrypt_bytes(data: bytes, **kw) -> tuple[bytes, EncryptResult]:
    import io

    out = io.BytesIO()
    res = encrypt_stream(io.BytesIO(data), out, **kw)
    return out.getvalue(), res


@dataclass(frozen=True)
class BlobHeader:
    raw: bytes
    content_alg: int
    chunk_log2: int
    vault_id: bytes
    file_id: bytes
    key_commit: bytes


def parse_header(raw: bytes) -> BlobHeader:
    if len(raw) != BLOB_HDR_LEN:
        raise FormatError("truncated blob header")
    magic, ver, alg, clog, wrap, res, vid, fid, com = _HDR.unpack(raw)
    if magic != BLOB_MAGIC:
        raise FormatError("not a MyLocker blob")
    if ver != BLOB_VERSION or wrap != WRAP_DERIVED or res != b"\x00" * 3:
        raise FormatError("unsupported blob version / wrap type / reserved bits")
    return BlobHeader(raw, alg, clog, vid, fid, com)


def decrypt_stream(src: BinaryIO, *, vmk: bytes, vault_id: bytes, chunk_log2: int, content_alg: int,
                   expected_file_id: bytes | None = None, expected_header_hash: bytes | None = None,
                   path_label: str | None = None) -> Iterator[bytes]:
    """Yield authenticated plaintext chunks.

    NOTE: chunks are yielded as they are authenticated; the *caller* must not
    release them at the final destination until the generator is exhausted
    without error (spec §5.2 release rule). See fsops.extract_blob.
    """
    hdr = parse_header(_read_full(src, BLOB_HDR_LEN))
    if hdr.content_alg != content_alg or hdr.chunk_log2 != chunk_log2:
        raise IntegrityError("blob algorithm/chunk size differs from vault", path=path_label)
    if hdr.vault_id != vault_id:
        raise IntegrityError("blob belongs to another vault", path=path_label)
    if expected_file_id is not None and hdr.file_id != expected_file_id:
        raise IntegrityError("blob file_id mismatch", path=path_label)
    h = sha256(hdr.raw)
    if expected_header_hash is not None and not ct_equal(h, expected_header_hash):
        raise IntegrityError("blob header hash mismatch", path=path_label)
    keys = derive_file_keys(vmk, vault_id, hdr.file_id)
    if not ct_equal(keys.commit, hdr.key_commit):
        raise IntegrityError("key commitment mismatch", path=path_label)

    full = NONCE_LEN + (1 << chunk_log2) + TAG_LEN
    i = 0
    cur = _read_full(src, full)
    if len(cur) == 0:
        raise IntegrityError("blob has no chunks", path=path_label)
    while True:
        nxt = _read_full(src, full) if len(cur) == full else b""
        last = len(nxt) == 0
        if len(cur) < NONCE_LEN + TAG_LEN:
            raise IntegrityError("truncated chunk", path=path_label, chunk=i)
        if i >= MAX_CHUNKS:
            raise FormatError("too many chunks")
        try:
            pt = aead_decrypt(keys.content, cur[:NONCE_LEN], cur[NONCE_LEN:], _aad(h, i, last))
        except IntegrityError:
            raise IntegrityError("chunk authentication failed", path=path_label, chunk=i) from None
        yield pt
        i += 1
        if last:
            return
        cur = nxt


def decrypt_bytes(blob: bytes, **kw) -> bytes:
    import io

    return b"".join(decrypt_stream(io.BytesIO(blob), **kw))


def _read_full(f: BinaryIO, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        b = f.read(n - len(buf))
        if not b:
            break
        buf += b
    return buf
