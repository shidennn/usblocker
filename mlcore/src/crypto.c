#include "crypto.h"
#include <windows.h>
#include <bcrypt.h>
#include "argon2/argon2.h"
#include <string.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// --- Random Bytes ---
MLCORE_API int mlcore_randombytes(uint8_t* buf, size_t len) {
    NTSTATUS status = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return NT_SUCCESS(status) ? 0 : -1;
}

// --- KDF ---
MLCORE_API int mlcore_kdf(const uint8_t* password, size_t pwd_len,
                          const uint8_t* salt, size_t salt_len,
                          uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                          uint8_t* out_key, size_t out_len) {
    int res = argon2id_hash_raw(t_cost, m_cost, parallelism,
                                password, pwd_len,
                                salt, salt_len,
                                out_key, out_len);
    return (res == ARGON2_OK) ? 0 : -1;
}

// --- AES-256-GCM ---

static NTSTATUS bc_aes_gcm(int encrypt,
                           const uint8_t* key, 
                           const uint8_t* nonce, size_t nonce_len,
                           const uint8_t* in, size_t in_len,
                           const uint8_t* aad, size_t aad_len,
                           uint8_t* out, uint8_t* tag) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status)) goto cleanup;

    // Generate symmetric key
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, 32, 0); // 32 bytes for AES-256
    if (!NT_SUCCESS(status)) goto cleanup;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = (ULONG)nonce_len;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = (ULONG)aad_len;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;
    
    // For single-shot GCM, cbMacContext must be set according to property, and pbMacContext must be allocated
    DWORD cbMacContext = 0;
    DWORD cbResult = 0;
    // BCRYPT_AUTH_TAG_LENGTH gives max tag length, but we use fixed 16
    authInfo.cbTag = 16;

    // Get mac context size
    // For some reason BCryptGetProperty might not return cbMacContext correctly for GCM, but we'll try or just allocate max
    // Actually, MSDN says "pbMacContext" is required if we chain, but for single-shot it can be NULL? 
    // wait: "pbMacContext member must be NULL and cbMacContext must be 0 for one-shot encrypt/decrypt." - Let's leave them 0/NULL.

    ULONG bytesDone = 0;
    if (encrypt) {
        status = BCryptEncrypt(hKey, (PUCHAR)in, (ULONG)in_len, &authInfo, NULL, 0, out, (ULONG)in_len, &bytesDone, 0);
    } else {
        status = BCryptDecrypt(hKey, (PUCHAR)in, (ULONG)in_len, &authInfo, NULL, 0, out, (ULONG)in_len, &bytesDone, 0);
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return status;
}

MLCORE_API int mlcore_aead_encrypt(const uint8_t* key, 
                                   const uint8_t* nonce, size_t nonce_len,
                                   const uint8_t* pt, size_t pt_len,
                                   const uint8_t* aad, size_t aad_len,
                                   uint8_t* ct_out, uint8_t* tag_out) {
    NTSTATUS status = bc_aes_gcm(1, key, nonce, nonce_len, pt, pt_len, aad, aad_len, ct_out, tag_out);
    return NT_SUCCESS(status) ? 0 : -1;
}

MLCORE_API int mlcore_aead_decrypt(const uint8_t* key, 
                                   const uint8_t* nonce, size_t nonce_len,
                                   const uint8_t* ct, size_t ct_len,
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* tag,
                                   uint8_t* pt_out) {
    // We pass the expected tag into bc_aes_gcm
    uint8_t tag_copy[16];
    memcpy(tag_copy, tag, 16);

    NTSTATUS status = bc_aes_gcm(0, key, nonce, nonce_len, ct, ct_len, aad, aad_len, pt_out, tag_copy);
    return NT_SUCCESS(status) ? 0 : -1;
}


// --- SHA256 & HMAC-SHA256 ---
MLCORE_API int mlcore_sha256(const uint8_t* data, size_t data_len, uint8_t* out_hash) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return status;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
        if (NT_SUCCESS(status)) {
            status = BCryptFinishHash(hHash, out_hash, 32, 0);
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(status) ? 0 : -1;
}

static int hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out_mac) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return status;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hHash, (PUCHAR)data, (ULONG)data_len, 0);
        if (NT_SUCCESS(status)) {
            status = BCryptFinishHash(hHash, out_mac, 32, 0);
        }
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(status) ? 0 : -1;
}

// --- HKDF-SHA256 ---
MLCORE_API int mlcore_hkdf(const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* salt, size_t salt_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out_key, size_t out_len) {
    uint8_t prk[32];
    uint8_t zeros[32] = {0};
    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = 32;
    }
    
    // Extract: PRK = HMAC-Hash(salt, IKM)
    if (hmac_sha256(salt, salt_len, ikm, ikm_len, prk) != 0) return -1;
    
    // Expand: 
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t out_pos = 0;
    
    while (out_pos < out_len) {
        // T(i) = HMAC(PRK, T(i-1) | info | counter)
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return -1;
        if (!NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, prk, 32, 0))) { BCryptCloseAlgorithmProvider(hAlg, 0); return -1; }
        
        if (t_len > 0) BCryptHashData(hHash, t, (ULONG)t_len, 0);
        if (info_len > 0) BCryptHashData(hHash, (PUCHAR)info, (ULONG)info_len, 0);
        BCryptHashData(hHash, &counter, 1, 0);
        
        BCryptFinishHash(hHash, t, 32, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        
        t_len = 32;
        size_t copy_len = (out_len - out_pos) < 32 ? (out_len - out_pos) : 32;
        memcpy(out_key + out_pos, t, copy_len);
        out_pos += copy_len;
        counter++;
    }
    
    SecureZeroMemory(prk, sizeof(prk));
    SecureZeroMemory(t, sizeof(t));
    return 0;
}
