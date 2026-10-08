#ifndef MLCORE_CRYPTO_H
#define MLCORE_CRYPTO_H

#include "mlcore.h"

#ifdef __cplusplus
extern "C" {
#endif

// Argon2id KDF
MLCORE_API int mlcore_kdf(const uint8_t* password, size_t pwd_len,
                          const uint8_t* salt, size_t salt_len,
                          uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                          uint8_t* out_key, size_t out_len);

// AES-256-GCM
// ct_out will receive pt_len bytes. tag_out will receive 16 bytes.
MLCORE_API int mlcore_aead_encrypt(const uint8_t* key, 
                                   const uint8_t* nonce, size_t nonce_len,
                                   const uint8_t* pt, size_t pt_len,
                                   const uint8_t* aad, size_t aad_len,
                                   uint8_t* ct_out, uint8_t* tag_out);

// ct and tag must be provided. pt_out will receive ct_len bytes if successful.
MLCORE_API int mlcore_aead_decrypt(const uint8_t* key, 
                                   const uint8_t* nonce, size_t nonce_len,
                                   const uint8_t* ct, size_t ct_len,
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* tag,
                                   uint8_t* pt_out);

// Secure random bytes
MLCORE_API int mlcore_randombytes(uint8_t* buf, size_t len);

// SHA-256
MLCORE_API int mlcore_sha256(const uint8_t* data, size_t data_len, uint8_t* out_hash);

// HKDF-SHA256
MLCORE_API int mlcore_hkdf(const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* salt, size_t salt_len,
                           const uint8_t* info, size_t info_len,
                           uint8_t* out_key, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif // MLCORE_CRYPTO_H
