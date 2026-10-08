# MyLocker On-Disk Format — v1

Status: **DRAFT → frozen at end of Phase 1** (after test vectors are published in `tests/vectors/`).
Normative language: MUST / MUST NOT / SHOULD as in RFC 2119.
Reference implementation: `mlref/` (Python). Production implementation: `mlcore/` (C, libsodium). Both MUST produce byte-identical output given identical random inputs.

---

## 0. Conventions

- All integers are **unsigned little-endian** (`u8`, `u16`, `u32`, `u64`).
- `‖` denotes concatenation. `LE16(x)`, `LE32(x)`, `LE64(x)` denote little-endian encodings.
- Strings are UTF-8. Labels (HKDF `info`, AAD prefixes) are ASCII byte strings without terminator.
- All "reserved" fields MUST be written as zero and MUST be rejected if non-zero on read.
- Any unknown version, algorithm id, slot type or flag bit MUST cause rejection (**fail-closed**).
- Random values MUST come from the OS CSPRNG (Windows: `BCryptGenRandom` / `RtlGenRandom`).

## 1. Cryptographic primitives

| Name | Definition |
|---|---|
| `AEAD(k, n, p, a)` | AES-256-GCM, 32-byte key, 12-byte nonce, 16-byte tag appended to ciphertext (`ct ‖ tag`). Algorithm id **1**. |
| `HKDF(ikm, salt, info, L)` | HKDF-SHA256 (RFC 5869), extract + expand. Empty salt ≡ 32 zero bytes. |
| `SHA256(x)` | SHA-256 |
| `Argon2id(pw, salt, m, t)` | Argon2id v1.3 (RFC 9106), **parallelism p = 1**, output 32 bytes, `m` in KiB, `t` iterations, salt 16 bytes. (p = 1 is mandatory: libsodium only supports p = 1.) |

Algorithm id **2** (XChaCha20-Poly1305) is reserved for a future version and MUST be rejected in v1.

### 1.1 Argon2id parameter policy
| | `m` (KiB) | `t` |
|---|---|---|
| Default on creation | 262144 (256 MiB) | 3 |
| Minimum accepted on open | 65536 (64 MiB) | 3 |
| Maximum accepted on open | 4194304 (4 GiB) | 32 |

Values outside [min, max] MUST be rejected *before* running Argon2id (downgrade and DoS protection). Implementations MAY allow a test-only policy with lower minimums; it MUST NOT be reachable from the production UI.

### 1.2 Domain separation labels (complete list)

| Label | Use |
|---|---|
| `MyLocker/v1/keycheck` | Key file self-check |
| `MyLocker/v1/kek` | Slot KEK derivation |
| `MyLocker/v1/slot` | Slot wrap AAD prefix |
| `MyLocker/v1/manifest-key` | Manifest key derivation |
| `MyLocker/v1/manifest` | Manifest AAD prefix |
| `MyLocker/v1/file` | File key derivation |
| `MyLocker/v1/content` | Content key derivation |
| `MyLocker/v1/commit` | Key commitment |
| `MyLocker/v1/recovery-check` | Recovery key checksum |

---

## 2. Key file (`*.mlk`, stored on the USB drive)

Location: `<USB>:\MyLocker\keys\<hex(key_id)>.mlk`

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | `4D 4C 4B 45 59 00 00 00` (`"MLKEY\0\0\0"`) |
| 8 | 2 | version | = 1 |
| 10 | 2 | flags | = 0 |
| 12 | 16 | key_id | random, not secret |
| 28 | 32 | k_usb | random, **secret** |
| 60 | 8 | created | Unix seconds |
| 68 | 8 | check | `HKDF(k_usb, salt=key_id, info="MyLocker/v1/keycheck", 8)` |
| 76 | 2 | label_len | ≤ 256 |
| 78 | n | label | UTF-8 |

Total size MUST equal `78 + label_len`. `check` detects corruption only; it is not a security mechanism.

---

## 3. Vault layout

```text
<protected folder>\
 └── .mylocker\
      ├── vault.mlv          header + slots + encrypted manifest (single file, atomically replaced)
      ├── vault.mlv.bak      previous committed version
      ├── state              plaintext marker "unlocked" (non-secret, see §7)
      └── d\<xx>\<hex>.mlf   file blobs; <hex> = hex(file_id) lower-case (64 chars), <xx> = first 2 chars
```

Blob names are derived from `file_id`; the manifest does not store them separately.

---

## 4. Vault file (`vault.mlv`)

### 4.1 Fixed header (48 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | `"MLVAULT\0"` |
| 8 | 2 | format_version | = 1 |
| 10 | 2 | flags | = 0 |
| 12 | 16 | vault_id | random |
| 28 | 8 | created | Unix seconds |
| 36 | 8 | epoch | incremented on every commit (rollback detection, Phase 5) |
| 44 | 1 | content_alg | = 1 |
| 45 | 1 | chunk_log2 | 12 ≤ x ≤ 20; default 16 (64 KiB) |
| 46 | 2 | reserved | = 0 |

### 4.2 Slot table

| Size | Field |
|---|---|
| 1 | slot_count (1 ≤ n ≤ 8) |
| n × 136 | slots |

**Slot (136 bytes):**

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | slot_type | 1 = USB key file, 2 = USB key file + password, 3 = recovery key |
| 1 | 1 | slot_flags | = 0 |
| 2 | 2 | reserved | = 0 |
| 4 | 16 | key_id | type 1/2: key file `key_id`; type 3: random |
| 20 | 32 | slot_salt | random |
| 52 | 16 | pw_salt | random for type 2; **zero** otherwise |
| 68 | 4 | argon_m_kib | type 2 only; **zero** otherwise |
| 72 | 4 | argon_t | type 2 only; **zero** otherwise |
| 76 | 12 | wrap_nonce | random |
| 88 | 48 | wrapped_vmk | `AEAD(KEK, wrap_nonce, VMK, AAD_slot)` (32 + 16) |

Let `slot_params = slot[0:76]`.

```text
K_pw     = Argon2id(NFC(password) as UTF-8, pw_salt, argon_m_kib, argon_t)      (type 2 only)
IKM      = k_usb                       (type 1)
         = k_usb ‖ K_pw                (type 2)
         = recovery_key                (type 3)
KEK      = HKDF(IKM, salt=slot_salt, info="MyLocker/v1/kek" ‖ vault_id ‖ u8(slot_type), 32)
AAD_slot = "MyLocker/v1/slot" ‖ vault_id ‖ slot_params
```

Binding `slot_params` into the AAD means any change to Argon2id parameters, salts, type or key_id makes unwrap fail. Slot position is intentionally *not* bound (slots may be reordered / removed by a holder of the VMK).

Unwrap procedure: for each slot whose `key_id` matches an available key (or type 3 if a recovery key was supplied): validate parameters (§1.1) → derive KEK → AEAD-decrypt. The first successful unwrap yields the VMK. Failure of all candidate slots → "wrong key or password" (implementations MUST NOT distinguish wrong password from wrong key file for type 2).

### 4.3 Encrypted manifest

| Size | Field |
|---|---|
| 12 | manifest_nonce |
| 4 | manifest_ct_len (≥ 16, ≤ 256 MiB + 16) |
| manifest_ct_len | `AEAD(K_man, manifest_nonce, manifest_plain, AAD_man)` |

```text
prefix  = fixed_header ‖ slot_count ‖ slots           (bytes 0 .. 49 + 136n)
K_man   = HKDF(VMK, salt=vault_id, info="MyLocker/v1/manifest-key", 32)
AAD_man = "MyLocker/v1/manifest" ‖ prefix
```

The file MUST end exactly after the manifest ciphertext; trailing bytes MUST be rejected.

Because `prefix` is the AAD of the manifest, the **whole vault file is authenticated** once the manifest decrypts successfully. Implementations MUST NOT act on any header field other than those needed for unwrap (slots, vault_id) before the manifest is authenticated.

### 4.4 Manifest plaintext (TLV)

The manifest is a flat sequence of records (no nesting):

| Size | Field |
|---|---|
| 2 | type |
| 4 | length (bytes of value) |
| length | value |

**Type bit 15 (`0x8000`) = critical.** Unknown critical types MUST cause rejection; unknown non-critical types MUST be skipped.

| Type | Name | Value layout |
|---|---|---|
| `0x8001` | INFO | `u16 manifest_version (=1)` — MUST be the first record, exactly once |
| `0x8010` | FILE | `file_id[32] ‖ u64 size ‖ u64 mtime_ns ‖ u32 attrs ‖ header_hash[32] ‖ path[...]` |
| `0x8011` | DIR | `u64 mtime_ns ‖ u32 attrs ‖ path[...]` |

- FILE fixed part = 84 bytes; DIR fixed part = 12 bytes; `path` occupies the remainder of the value.
- `mtime_ns`: nanoseconds since Unix epoch. `attrs`: Windows file attributes masked to `READONLY|HIDDEN|SYSTEM|ARCHIVE` (`0x27`).
- `header_hash = SHA256(blob fixed header)` (§5.1), binding the path to one specific blob.
- Limits: record `length` ≤ 65536; path ≤ 4096 bytes; total records ≤ 10,000,000.
- **Canonical form (required for byte-exact interop):** INFO first, then all DIR and FILE records sorted by `path` as raw UTF-8 bytes ascending; DIR before FILE for equal paths is impossible (duplicate → reject).
- Every parent directory of a FILE or DIR path MUST itself appear as a DIR record (so the tree is explicit; empty directories are preserved).

### 4.5 Path rules (applied on create AND on read)

A path is relative, uses `/` as separator, is Unicode NFC, and every component:
- is non-empty, not `.` or `..`;
- contains no code point < 0x20, and none of `< > : " / \ | ? *`;
- does not end with `.` or space;
- is not a reserved DOS device name (`CON PRN AUX NUL COM1-9 LPT1-9`), with or without extension, case-insensitively;
- is ≤ 255 UTF-16 code units.

Two paths that are equal after `casefold()` are a **collision** and MUST be rejected (NTFS is case-insensitive). A violation on read means a malicious or corrupt manifest and MUST abort the operation.

---

## 5. File blob (`*.mlf`)

### 5.1 Fixed header (96 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | `"MLFILE\0\0"` |
| 8 | 2 | version | = 1 |
| 10 | 1 | content_alg | = 1, MUST equal vault's |
| 11 | 1 | chunk_log2 | MUST equal vault's |
| 12 | 1 | key_wrap_type | 1 = derived from VMK (Phase 4 adds 2 = sealed to `pk_v`) |
| 13 | 3 | reserved | = 0 |
| 16 | 16 | vault_id | MUST equal vault's |
| 32 | 32 | file_id | random, fresh for every encryption |
| 64 | 32 | key_commit | see below |

```text
FK         = HKDF(VMK, salt=file_id, info="MyLocker/v1/file" ‖ vault_id, 32)
K_content  = HKDF(FK, salt="", info="MyLocker/v1/content", 32)
key_commit = HKDF(FK, salt="", info="MyLocker/v1/commit", 32)
H          = SHA256(fixed header)          (= header_hash in the manifest)
```

`key_commit` MUST be compared in constant time before any chunk is decrypted (AES-GCM is not key-committing).

### 5.2 Chunks

Let `C = 2^chunk_log2`. Plaintext is split into chunks of exactly `C` bytes, except the last, which has 0 < len ≤ C — or exactly 0 bytes if the whole plaintext is empty (an empty file has exactly one empty chunk). A plaintext whose length is a positive multiple of `C` ends with a full chunk (no extra empty chunk).

Each chunk on disk: `nonce[12] ‖ AEAD(K_content, nonce, chunk_plain, AAD_i)` where

```text
AAD_i = H ‖ LE64(i) ‖ u8(is_last)
```

**Parsing:** let `F = 12 + C + 16`, `R` = bytes after the header. `R = 0` → reject. While `R > F`: read one full chunk (`is_last = 0`). The final chunk has `R` bytes with `28 ≤ R ≤ F` (`is_last = 1`); `R < 28` → reject. Number of chunks MUST NOT exceed 2^32.

This detects bit flips, chunk reordering / duplication (index in AAD), truncation (the new final chunk was encrypted with `is_last = 0`), and extension (data after an `is_last = 1` chunk is impossible by construction).

**Release rule:** decrypted bytes MUST NOT be exposed at the destination path until **all** chunks have been authenticated (write to a temporary file, rename on success, delete on failure).

Nonces are random per chunk (not counters) so that a future in-place chunk rewrite (Phase 6 VFS) can never reuse a `(key, nonce)` pair. Limit: 2^32 chunk encryptions per FK.

---

## 6. Recovery key

32 random bytes `R`. Display form:

```text
data  = R ‖ SHA256("MyLocker/v1/recovery-check" ‖ R)[0:2]     (34 bytes)
text  = Base32(RFC 4648, upper-case, no padding)(data)         (55 chars)
shown = groups of 5 chars joined by "-"                          (11 groups)
```

Parsing ignores spaces, `-` and case; the checksum catches typos (it is not a security mechanism).

---

## 7. Operations and commit protocol (informative for v1, normative for implementations)

**Commit (atomic):**
1. Each new blob is written as `<hex>.mlf.tmp`, flushed (`FlushFileBuffers` / `fsync`), re-read and verified (decrypt + compare plaintext SHA-256), then renamed to `<hex>.mlf`.
2. New `vault.mlv` is written to `vault.mlv.tmp` and flushed.
3. The current `vault.mlv` is preserved as `vault.mlv.bak`, and `vault.mlv.tmp` atomically replaces `vault.mlv` (Win32 `ReplaceFileW`; reference impl: copy-to-bak then `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`). **This is the single commit point.**
4. Only after (3): plaintext working copies are deleted (best-effort overwrite).
5. Garbage collection deletes blobs referenced by neither `vault.mlv` nor `vault.mlv.bak`, and stale `*.tmp` files.

**State marker:** `.mylocker\state` exists while working copies are unlocked. `lock` MUST refuse when it is absent (otherwise an empty folder would be committed as "all files deleted"). The marker is not security-relevant (tampering = denial of service only).

**Backup manifest:** `vault.mlv.bak` is never used automatically; the user must explicitly request it (silent fallback would enable rollback).
