#ifndef MLCORE_BLOB_H
#define MLCORE_BLOB_H

#include "mlcore.h"
#include "crypto.h"

#define MLCORE_BLOB_HDR_LEN 96
#define MLCORE_NONCE_LEN 12
#define MLCORE_TAG_LEN 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mlcore_blob_ctx mlcore_blob_ctx_t;

// hdr_out must be MLCORE_BLOB_HDR_LEN bytes.
// chunk_log2 typically 12 to 24 (4KB to 16MB).
MLCORE_API mlcore_blob_ctx_t* mlcore_blob_enc_init(const uint8_t* vmk, const uint8_t* vault_id, const uint8_t* file_id, uint8_t chunk_log2, uint8_t* hdr_out);

// pt_len must be <= (1<<chunk_log2).
// ct_out must have space for MLCORE_NONCE_LEN + pt_len + MLCORE_TAG_LEN bytes.
// *ct_len_out receives the length written.
MLCORE_API int mlcore_blob_enc_update(mlcore_blob_ctx_t* ctx, const uint8_t* pt, size_t pt_len, uint8_t* ct_out, size_t* ct_len_out, int is_last);

// returns the accumulated hash of the plaintext (SHA256). hash_out must be 32 bytes.
MLCORE_API void mlcore_blob_enc_get_plain_sha256(mlcore_blob_ctx_t* ctx, uint8_t* hash_out);

MLCORE_API void mlcore_blob_free(mlcore_blob_ctx_t* ctx);


// expected_file_id can be NULL if not known
// hdr_in must be MLCORE_BLOB_HDR_LEN bytes.
MLCORE_API mlcore_blob_ctx_t* mlcore_blob_dec_init(const uint8_t* vmk, const uint8_t* vault_id, uint8_t expected_chunk_log2, const uint8_t* hdr_in, const uint8_t* expected_file_id);

// ct_chunk is a full chunk (nonce + pt + tag).
// pt_out must have space for (ct_len - NONCE_LEN - TAG_LEN).
MLCORE_API int mlcore_blob_dec_update(mlcore_blob_ctx_t* ctx, const uint8_t* ct_chunk, size_t ct_len, uint8_t* pt_out, size_t* pt_len_out, int is_last);

#ifdef __cplusplus
}
#endif

#endif
