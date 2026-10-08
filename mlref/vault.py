"""Vault file (spec §4): fixed header, key slots, encrypted manifest."""

import struct
import time
from dataclasses import dataclass, field, replace

from . import rng as _rng
from .constants import (
    ALG_AES256GCM,
    CHUNK_LOG2_DEFAULT,
    CHUNK_LOG2_MAX,
    CHUNK_LOG2_MIN,
    KEY_LEN,
    L_KEK,
    L_MANIFEST,
    L_MANIFEST_KEY,
    L_SLOT,
    MAX_MANIFEST_PLAIN,
    MAX_SLOTS,
    NONCE_LEN,
    PRODUCTION_POLICY,
    SLOT_LEN,
    SLOT_PARAMS_LEN,
    SLOT_RECOVERY,
    SLOT_TYPES,
    SLOT_USB,
    SLOT_USB_PASSWORD,
    SUPPORTED_ALGS,
    TAG_LEN,
    VAULT_FIXED_LEN,
    VAULT_MAGIC,
    VAULT_VERSION,
    KdfPolicy,
)
from .crypto import aead_decrypt, aead_encrypt, argon2id, hkdf, normalize_password
from .errors import AuthError, FormatError, IntegrityError
from .keyfile import KeyFile
from .manifest import Manifest

_FIXED = struct.Struct("<8sHH16sQQBB2s")
_SLOT_PARAMS = struct.Struct("<BB2s16s32s16sII")
assert _FIXED.size == VAULT_FIXED_LEN and _SLOT_PARAMS.size == SLOT_PARAMS_LEN


# --- credentials -----------------------------------------------------------

@dataclass(frozen=True)
class Credentials:
    """What the user presents to unlock. Any subset; matching slots are tried."""

    keyfiles: tuple[KeyFile, ...] = ()
    password: str | None = None
    recovery_key: bytes | None = None

    def __repr__(self) -> str:
        return f"Credentials(keyfiles={list(self.keyfiles)}, password={'***' if self.password else None}, recovery={'***' if self.recovery_key else None})"


# --- slots -----------------------------------------------------------------

@dataclass(frozen=True)
class Slot:
    slot_type: int
    key_id: bytes
    slot_salt: bytes
    pw_salt: bytes
    argon_m_kib: int
    argon_t: int
    wrap_nonce: bytes
    wrapped_vmk: bytes

    def params_bytes(self) -> bytes:
        return _SLOT_PARAMS.pack(self.slot_type, 0, b"\x00\x00", self.key_id, self.slot_salt,
                                 self.pw_salt, self.argon_m_kib, self.argon_t)

    def to_bytes(self) -> bytes:
        b = self.params_bytes() + self.wrap_nonce + self.wrapped_vmk
        assert len(b) == SLOT_LEN
        return b

    @staticmethod
    def from_bytes(b: bytes) -> "Slot":
        st, flags, res, kid, ssalt, psalt, m, t = _SLOT_PARAMS.unpack_from(b)
        if st not in SLOT_TYPES or flags != 0 or res != b"\x00\x00":
            raise FormatError("unknown slot type / flags")
        if st != SLOT_USB_PASSWORD and (psalt != b"\x00" * 16 or m != 0 or t != 0):
            raise FormatError("password fields set on non-password slot")
        o = SLOT_PARAMS_LEN
        return Slot(st, kid, ssalt, psalt, m, t, b[o:o + NONCE_LEN], b[o + NONCE_LEN:SLOT_LEN])


def _slot_ikm(slot_type: int, *, k_usb: bytes | None, k_pw: bytes | None, recovery: bytes | None) -> bytes:
    if slot_type == SLOT_USB:
        return k_usb
    if slot_type == SLOT_USB_PASSWORD:
        return k_usb + k_pw
    return recovery


def _kek(vault_id: bytes, slot_type: int, slot_salt: bytes, ikm: bytes) -> bytes:
    return hkdf(ikm, slot_salt, L_KEK + vault_id + bytes([slot_type]))


def make_slot(vault_id: bytes, vmk: bytes, slot_type: int, *, keyfile: KeyFile | None = None,
              password: str | None = None, recovery_key: bytes | None = None,
              policy: KdfPolicy = PRODUCTION_POLICY, rng: _rng.Rng = _rng.SYSTEM) -> Slot:
    slot_salt = rng.bytes(32)
    pw_salt, m, t, k_pw = b"\x00" * 16, 0, 0, None
    if slot_type == SLOT_USB_PASSWORD:
        if not password:
            raise ValueError("password required")
        pw_salt, m, t = rng.bytes(16), policy.default_m_kib, policy.default_t
        policy.check(m, t)
        k_pw = argon2id(normalize_password(password), pw_salt, m, t)
    if slot_type in (SLOT_USB, SLOT_USB_PASSWORD):
        if keyfile is None:
            raise ValueError("key file required")
        key_id = keyfile.key_id
    elif slot_type == SLOT_RECOVERY:
        if recovery_key is None or len(recovery_key) != KEY_LEN:
            raise ValueError("recovery key required")
        key_id = rng.bytes(16)
    else:
        raise ValueError("bad slot type")
    ikm = _slot_ikm(slot_type, k_usb=keyfile.k_usb if keyfile else None, k_pw=k_pw, recovery=recovery_key)
    kek = _kek(vault_id, slot_type, slot_salt, ikm)
    proto = Slot(slot_type, key_id, slot_salt, pw_salt, m, t, b"", b"")
    nonce = rng.bytes(NONCE_LEN)
    wrapped = aead_encrypt(kek, nonce, vmk, L_SLOT + vault_id + proto.params_bytes())
    return replace(proto, wrap_nonce=nonce, wrapped_vmk=wrapped)


def try_unwrap(vault_id: bytes, slot: Slot, creds: Credentials, policy: KdfPolicy) -> bytes | None:
    if slot.slot_type == SLOT_RECOVERY:
        if creds.recovery_key is None:
            return None
        ikm = creds.recovery_key
    else:
        kf = next((k for k in creds.keyfiles if k.key_id == slot.key_id), None)
        if kf is None:
            return None
        if slot.slot_type == SLOT_USB_PASSWORD:
            if not creds.password:
                return None
            policy.check(slot.argon_m_kib, slot.argon_t)  # BEFORE running Argon2id
            k_pw = argon2id(normalize_password(creds.password), slot.pw_salt, slot.argon_m_kib, slot.argon_t)
            ikm = kf.k_usb + k_pw
        else:
            ikm = kf.k_usb
    kek = _kek(vault_id, slot.slot_type, slot.slot_salt, ikm)
    try:
        return aead_decrypt(kek, slot.wrap_nonce, slot.wrapped_vmk, L_SLOT + vault_id + slot.params_bytes())
    except IntegrityError:
        return None


# --- vault -----------------------------------------------------------------

@dataclass
class VaultHeader:
    vault_id: bytes
    created: int
    epoch: int
    content_alg: int
    chunk_log2: int
    slots: list[Slot] = field(default_factory=list)

    def prefix(self) -> bytes:
        if not 1 <= len(self.slots) <= MAX_SLOTS:
            raise FormatError("slot count out of range")
        return (_FIXED.pack(VAULT_MAGIC, VAULT_VERSION, 0, self.vault_id, self.created, self.epoch,
                            self.content_alg, self.chunk_log2, b"\x00\x00")
                + bytes([len(self.slots)]) + b"".join(s.to_bytes() for s in self.slots))


@dataclass
class OpenVault:
    """An unlocked vault: header, VMK and decrypted manifest. Treat as secret."""

    header: VaultHeader
    vmk: bytes
    manifest: Manifest

    def __repr__(self) -> str:
        return f"OpenVault(vault_id={self.header.vault_id.hex()}, epoch={self.header.epoch}, files={len(self.manifest.files)})"


def manifest_key(vmk: bytes, vault_id: bytes) -> bytes:
    return hkdf(vmk, vault_id, L_MANIFEST_KEY)


def serialize(ov: OpenVault, rng: _rng.Rng = _rng.SYSTEM) -> bytes:
    prefix = ov.header.prefix()
    plain = ov.manifest.encode()
    if len(plain) > MAX_MANIFEST_PLAIN:
        raise FormatError("manifest too large")
    nonce = rng.bytes(NONCE_LEN)
    ct = aead_encrypt(manifest_key(ov.vmk, ov.header.vault_id), nonce, plain, L_MANIFEST + prefix)
    return prefix + nonce + struct.pack("<I", len(ct)) + ct


def parse_unauthenticated(data: bytes) -> tuple[VaultHeader, bytes, bytes, bytes]:
    """Parse structure only. Returns (header, prefix, manifest_nonce, manifest_ct).
    Nothing returned here may be trusted until the manifest authenticates."""
    if len(data) < VAULT_FIXED_LEN + 1:
        raise FormatError("vault file too short")
    magic, ver, flags, vid, created, epoch, alg, clog, res = _FIXED.unpack_from(data)
    if magic != VAULT_MAGIC:
        raise FormatError("not a MyLocker vault")
    if ver != VAULT_VERSION or flags != 0 or res != b"\x00\x00":
        raise FormatError("unsupported vault version/flags")
    if alg not in SUPPORTED_ALGS or not CHUNK_LOG2_MIN <= clog <= CHUNK_LOG2_MAX:
        raise FormatError("unsupported algorithm or chunk size")
    n = data[VAULT_FIXED_LEN]
    if not 1 <= n <= MAX_SLOTS:
        raise FormatError("slot count out of range")
    off = VAULT_FIXED_LEN + 1
    if len(data) < off + n * SLOT_LEN + NONCE_LEN + 4:
        raise FormatError("vault file truncated")
    slots = [Slot.from_bytes(data[off + i * SLOT_LEN: off + (i + 1) * SLOT_LEN]) for i in range(n)]
    off += n * SLOT_LEN
    prefix = data[:off]
    nonce = data[off:off + NONCE_LEN]
    (ct_len,) = struct.unpack_from("<I", data, off + NONCE_LEN)
    off += NONCE_LEN + 4
    if ct_len < TAG_LEN or ct_len > MAX_MANIFEST_PLAIN + TAG_LEN:
        raise FormatError("manifest length out of range")
    if len(data) != off + ct_len:
        raise FormatError("vault file length mismatch (truncated or trailing data)")
    hdr = VaultHeader(vid, created, epoch, alg, clog, slots)
    return hdr, prefix, nonce, data[off:]


def open_vault(data: bytes, creds: Credentials, policy: KdfPolicy = PRODUCTION_POLICY) -> OpenVault:
    hdr, prefix, nonce, ct = parse_unauthenticated(data)
    vmk = None
    for slot in hdr.slots:
        vmk = try_unwrap(hdr.vault_id, slot, creds, policy)
        if vmk is not None:
            break
    if vmk is None:
        raise AuthError("no key slot could be opened: wrong key file, password or recovery key")
    try:
        plain = aead_decrypt(manifest_key(vmk, hdr.vault_id), nonce, ct, L_MANIFEST + prefix)
    except IntegrityError:
        raise IntegrityError("vault header/manifest authentication failed (file modified)") from None
    return OpenVault(hdr, vmk, Manifest.decode(plain))


def create(creds_slots: list[tuple[int, dict]], *, chunk_log2: int = CHUNK_LOG2_DEFAULT,
           policy: KdfPolicy = PRODUCTION_POLICY, rng: _rng.Rng = _rng.SYSTEM,
           created: int | None = None) -> OpenVault:
    """Create a new empty vault. `creds_slots` = [(slot_type, make_slot kwargs), ...]."""
    if not CHUNK_LOG2_MIN <= chunk_log2 <= CHUNK_LOG2_MAX:
        raise ValueError("chunk_log2 out of range")
    vault_id = rng.bytes(16)
    vmk = rng.bytes(KEY_LEN)
    slots = [make_slot(vault_id, vmk, st, policy=policy, rng=rng, **kw) for st, kw in creds_slots]
    hdr = VaultHeader(vault_id, int(time.time()) if created is None else created, 0,
                      ALG_AES256GCM, chunk_log2, slots)
    return OpenVault(hdr, vmk, Manifest.empty())
