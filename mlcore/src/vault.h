#ifndef MLCORE_VAULT_H
#define MLCORE_VAULT_H

#include "mlcore.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MLCORE_VAULT_HDR_LEN 48

typedef struct mlcore_vault_hdr {
    uint8_t vault_id[16];
    uint64_t created;
    uint64_t epoch;
    uint16_t version;
    uint16_t flags;
    uint8_t alg;
    uint8_t clog;
} mlcore_vault_hdr_t;

// Parse the vault header from buf (must be at least 48 bytes).
// Returns 0 on success, negative on error.
MLCORE_API int mlcore_vault_parse_hdr(const uint8_t* buf, size_t buf_len, mlcore_vault_hdr_t* out_hdr);

#ifdef __cplusplus
}
#endif

#endif
