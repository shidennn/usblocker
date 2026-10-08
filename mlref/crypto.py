"""Primitive wrappers (spec §1). No home-made crypto: everything delegates to
`cryptography` (OpenSSL) and `argon2-cffi` (reference Argon2 implementation)."""

import hashlib
import hmac
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import KEY_LEN, NONCE_LEN, TAG_LEN
from .errors import IntegrityError


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    # Empty salt == 32 zero bytes per RFC 5869; pass explicitly for clarity.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if salt else b"\x00" * 32,
        info=info,
    ).derive(ikm)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    assert len(key) == KEY_LEN and len(nonce) == NONCE_LEN
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
    """Raises IntegrityError on authentication failure. Never returns unauthenticated data."""
    assert len(key) == KEY_LEN and len(nonce) == NONCE_LEN
    if len(ct_and_tag) < TAG_LEN:
        raise IntegrityError("ciphertext shorter than tag")
    try:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        raise IntegrityError("authentication tag mismatch") from None


def normalize_password(password: str) -> bytes:
    return unicodedata.normalize("NFC", password).encode("utf-8")


def argon2id(password: bytes, salt: bytes, m_kib: int, t: int) -> bytes:
    """Argon2id v1.3, p=1, 32-byte output (spec §1). Caller must enforce KdfPolicy first."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=t,
        memory_cost=m_kib,
        parallelism=1,
        hash_len=KEY_LEN,
        type=Type.ID,
        version=19,
    )
