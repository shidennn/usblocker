"""Constants from docs/spec/format-v1.md. Keep in sync with mlcore/include/mlcore_format.h."""

from dataclasses import dataclass

# --- primitives -----------------------------------------------------------
KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
ALG_AES256GCM = 1
SUPPORTED_ALGS = {ALG_AES256GCM}

# --- labels (spec §1.2) ---------------------------------------------------
L_KEYCHECK = b"MyLocker/v1/keycheck"
L_KEK = b"MyLocker/v1/kek"
L_SLOT = b"MyLocker/v1/slot"
L_MANIFEST_KEY = b"MyLocker/v1/manifest-key"
L_MANIFEST = b"MyLocker/v1/manifest"
L_FILE = b"MyLocker/v1/file"
L_CONTENT = b"MyLocker/v1/content"
L_COMMIT = b"MyLocker/v1/commit"
L_RECOVERY_CHECK = b"MyLocker/v1/recovery-check"

# --- key file (spec §2) ---------------------------------------------------
KEYFILE_MAGIC = b"MLKEY\x00\x00\x00"
KEYFILE_VERSION = 1
KEYFILE_FIXED_LEN = 78
KEYFILE_MAX_LABEL = 256

# --- vault (spec §4) ------------------------------------------------------
VAULT_MAGIC = b"MLVAULT\x00"
VAULT_VERSION = 1
VAULT_FIXED_LEN = 48
SLOT_LEN = 136
SLOT_PARAMS_LEN = 76
MAX_SLOTS = 8
CHUNK_LOG2_MIN = 12
CHUNK_LOG2_MAX = 20
CHUNK_LOG2_DEFAULT = 16
MAX_MANIFEST_PLAIN = 256 * 1024 * 1024

SLOT_USB = 1
SLOT_USB_PASSWORD = 2
SLOT_RECOVERY = 3
SLOT_TYPES = {SLOT_USB, SLOT_USB_PASSWORD, SLOT_RECOVERY}

# --- manifest TLV (spec §4.4) --------------------------------------------
TLV_CRITICAL = 0x8000
TLV_INFO = 0x8001
TLV_FILE = 0x8010
TLV_DIR = 0x8011
TLV_HDR_LEN = 6
TLV_MAX_VALUE = 65536
MANIFEST_VERSION = 1
MAX_RECORDS = 10_000_000
FILE_FIXED_LEN = 84
DIR_FIXED_LEN = 12
MAX_PATH_BYTES = 4096
ATTR_MASK = 0x27  # READONLY|HIDDEN|SYSTEM|ARCHIVE

# --- blob (spec §5) -------------------------------------------------------
BLOB_MAGIC = b"MLFILE\x00\x00"
BLOB_VERSION = 1
BLOB_HDR_LEN = 96
WRAP_DERIVED = 1
MAX_CHUNKS = 2**32

# --- layout (spec §3) -----------------------------------------------------
VAULT_DIR = ".mylocker"
VAULT_FILE = "vault.mlv"
VAULT_BAK = "vault.mlv.bak"
STATE_FILE = "state"
BLOB_DIR = "d"


@dataclass(frozen=True)
class KdfPolicy:
    """Argon2id parameter bounds (spec §1.1)."""

    default_m_kib: int = 262144
    default_t: int = 3
    min_m_kib: int = 65536
    min_t: int = 3
    max_m_kib: int = 4194304
    max_t: int = 32

    def check(self, m_kib: int, t: int) -> None:
        from .errors import KdfPolicyError

        if not (self.min_m_kib <= m_kib <= self.max_m_kib and self.min_t <= t <= self.max_t):
            raise KdfPolicyError(f"Argon2id parameters out of policy: m={m_kib} KiB, t={t}")


PRODUCTION_POLICY = KdfPolicy()
