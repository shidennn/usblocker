#include "blob.h"
#include <windows.h>
#include <string.h>
#include <bcrypt.h>

#define BLOB_MAGIC "MLFILE\0\0"
#define BLOB_VERSION 1
#define ALG_AES256GCM 1
#define WRAP_DERIVED 1

static const char L_FILE[] = "MyLocker/v1/file";
static const char L_CONTENT[] = "MyLocker/v1/content";
static const char L_COMMIT[] = "MyLocker/v1/commit";

struct mlcore_blob_ctx {
    uint8_t content_key[32];
    uint8_t commit_key[32];
    uint8_t header_hash[32];
    uint64_t chunk_idx;
    uint8_t chunk_log2;
    BCRYPT_ALG_HANDLE hAlgHash;
    BCRYPT_HASH_HANDLE pt_hash; // for encrypt only
    int is_encrypt;
};

static void derive_file_keys(const uint8_t* vmk, const uint8_t* vault_id, const uint8_t* file_id, uint8_t* content_key, uint8_t* commit_key) {
    uint8_t info_file[32]; // "MyLocker/v1/file" (16) + vault_id (16)
    memcpy(info_file, L_FILE, 16);
    memcpy(info_file + 16, vault_id, 16);
    
    uint8_t fk[32];
    mlcore_hkdf(vmk, 32, file_id, 32, info_file, 32, fk, 32);
    
    mlcore_hkdf(fk, 32, NULL, 0, (const uint8_t*)L_CONTENT, 19, content_key, 32);
    mlcore_hkdf(fk, 32, NULL, 0, (const uint8_t*)L_COMMIT, 18, commit_key, 32);
    
    SecureZeroMemory(fk, 32);
}

static void pack_uint16(uint8_t* p, uint16_t v) { p[0] = v & 0xff; p[1] = v >> 8; }
static void pack_uint64(uint8_t* p, uint64_t v) { for(int i=0; i<8; i++) { p[i] = v & 0xff; v >>= 8; } }
static uint16_t unpack_uint16(const uint8_t* p) { return p[0] | (p[1] << 8); }

MLCORE_API mlcore_blob_ctx_t* mlcore_blob_enc_init(const uint8_t* vmk, const uint8_t* vault_id, const uint8_t* file_id, uint8_t chunk_log2, uint8_t* hdr_out) {
    mlcore_blob_ctx_t* ctx = (mlcore_blob_ctx_t*)mlcore_malloc(sizeof(mlcore_blob_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->is_encrypt = 1;
    ctx->chunk_log2 = chunk_log2;
    derive_file_keys(vmk, vault_id, file_id, ctx->content_key, ctx->commit_key);
    
    memset(hdr_out, 0, MLCORE_BLOB_HDR_LEN);
    memcpy(hdr_out, BLOB_MAGIC, 8);
    pack_uint16(hdr_out + 8, BLOB_VERSION);
    hdr_out[10] = ALG_AES256GCM;
    hdr_out[11] = chunk_log2;
    hdr_out[12] = WRAP_DERIVED;
    memcpy(hdr_out + 16, vault_id, 16);
    memcpy(hdr_out + 32, file_id, 32);
    memcpy(hdr_out + 64, ctx->commit_key, 32);
    
    mlcore_sha256(hdr_out, MLCORE_BLOB_HDR_LEN, ctx->header_hash);
    
    BCryptOpenAlgorithmProvider(&ctx->hAlgHash, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(ctx->hAlgHash, &ctx->pt_hash, NULL, 0, NULL, 0, 0);
    
    return ctx;
}

static void build_aad(const uint8_t* header_hash, uint64_t chunk_idx, int is_last, uint8_t* aad) {
    memcpy(aad, header_hash, 32);
    pack_uint64(aad + 32, chunk_idx);
    aad[40] = is_last ? 1 : 0;
}

MLCORE_API int mlcore_blob_enc_update(mlcore_blob_ctx_t* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct_out, size_t* ct_len_out, int is_last) {
    if (!ctx || !ctx->is_encrypt) return -1;
    
    uint8_t nonce[MLCORE_NONCE_LEN];
    if (mlcore_randombytes(nonce, MLCORE_NONCE_LEN) != 0) return -1;
    
    uint8_t aad[41];
    build_aad(ctx->header_hash, ctx->chunk_idx, is_last, aad);
    
    uint8_t tag[MLCORE_TAG_LEN];
    if (mlcore_aead_encrypt(ctx->content_key, nonce, MLCORE_NONCE_LEN, pt, pt_len, aad, sizeof(aad), ct_out + MLCORE_NONCE_LEN, tag) != 0) {
        return -1;
    }
    
    memcpy(ct_out, nonce, MLCORE_NONCE_LEN);
    memcpy(ct_out + MLCORE_NONCE_LEN + pt_len, tag, MLCORE_TAG_LEN);
    *ct_len_out = MLCORE_NONCE_LEN + pt_len + MLCORE_TAG_LEN;
    
    if (ctx->pt_hash) {
        BCryptHashData(ctx->pt_hash, (PUCHAR)pt, (ULONG)pt_len, 0);
    }
    
    ctx->chunk_idx++;
    return 0;
}

MLCORE_API void mlcore_blob_enc_get_plain_sha256(mlcore_blob_ctx_t* ctx, uint8_t* hash_out) {
    if (ctx && ctx->pt_hash) {
        BCryptFinishHash(ctx->pt_hash, hash_out, 32, 0);
    }
}

MLCORE_API mlcore_blob_ctx_t* mlcore_blob_dec_init(const uint8_t* vmk, const uint8_t* vault_id, uint8_t expected_chunk_log2, const uint8_t* hdr_in, const uint8_t* expected_file_id) {
    if (memcmp(hdr_in, BLOB_MAGIC, 8) != 0) return NULL;
    if (unpack_uint16(hdr_in + 8) != BLOB_VERSION) return NULL;
    if (hdr_in[10] != ALG_AES256GCM) return NULL;
    if (hdr_in[11] != expected_chunk_log2) return NULL;
    if (hdr_in[12] != WRAP_DERIVED) return NULL;
    if (memcmp(hdr_in + 16, vault_id, 16) != 0) return NULL;
    
    const uint8_t* file_id = hdr_in + 32;
    if (expected_file_id && memcmp(file_id, expected_file_id, 32) != 0) return NULL;
    
    mlcore_blob_ctx_t* ctx = (mlcore_blob_ctx_t*)mlcore_malloc(sizeof(mlcore_blob_ctx_t));
    if (!ctx) return NULL;
    memset(ctx, 0, sizeof(*ctx));
    
    ctx->is_encrypt = 0;
    ctx->chunk_log2 = expected_chunk_log2;
    derive_file_keys(vmk, vault_id, file_id, ctx->content_key, ctx->commit_key);
    
    if (memcmp(hdr_in + 64, ctx->commit_key, 32) != 0) {
        mlcore_free(ctx, sizeof(*ctx));
        return NULL; // key commitment mismatch
    }
    
    mlcore_sha256(hdr_in, MLCORE_BLOB_HDR_LEN, ctx->header_hash);
    return ctx;
}

MLCORE_API int mlcore_blob_dec_update(mlcore_blob_ctx_t* ctx, const uint8_t* ct_chunk, size_t ct_len, uint8_t* pt_out, size_t* pt_len_out, int is_last) {
    if (!ctx || ctx->is_encrypt) return -1;
    if (ct_len < MLCORE_NONCE_LEN + MLCORE_TAG_LEN) return -1;
    
    size_t pt_len = ct_len - MLCORE_NONCE_LEN - MLCORE_TAG_LEN;
    const uint8_t* nonce = ct_chunk;
    const uint8_t* ct = ct_chunk + MLCORE_NONCE_LEN;
    const uint8_t* tag = ct_chunk + MLCORE_NONCE_LEN + pt_len;
    
    uint8_t aad[41];
    build_aad(ctx->header_hash, ctx->chunk_idx, is_last, aad);
    
    if (mlcore_aead_decrypt(ctx->content_key, nonce, MLCORE_NONCE_LEN, ct, pt_len, aad, sizeof(aad), tag, pt_out) != 0) {
        return -1;
    }
    
    *pt_len_out = pt_len;
    ctx->chunk_idx++;
    return 0;
}

MLCORE_API void mlcore_blob_free(mlcore_blob_ctx_t* ctx) {
    if (ctx) {
        if (ctx->pt_hash) { BCryptDestroyHash(ctx->pt_hash); }
        if (ctx->hAlgHash) { BCryptCloseAlgorithmProvider(ctx->hAlgHash, 0); }
        mlcore_free(ctx, sizeof(*ctx));
    }
}
