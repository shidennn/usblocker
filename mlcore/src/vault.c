#include "vault.h"
#include <string.h>

#define VAULT_MAGIC "MLVAULT\0"

static uint16_t unpack_uint16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint64_t unpack_uint64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i=0; i<8; i++) v |= ((uint64_t)p[i]) << (i*8);
    return v;
}

MLCORE_API int mlcore_vault_parse_hdr(const uint8_t* buf, size_t buf_len, mlcore_vault_hdr_t* out_hdr) {
    if (buf_len < MLCORE_VAULT_HDR_LEN) return -1;
    if (memcmp(buf, "MLVAULT\0", 8) != 0) return -1;
    
    uint16_t version = unpack_uint16(buf + 8);
    if (version != 1) return -1; // Only version 1 supported
    
    if (out_hdr) {
        out_hdr->version = version;
        out_hdr->flags = unpack_uint16(buf + 10);
        memcpy(out_hdr->vault_id, buf + 12, 16);
        out_hdr->created = unpack_uint64(buf + 28);
        out_hdr->epoch = unpack_uint64(buf + 36);
        out_hdr->alg = buf[44];
        out_hdr->clog = buf[45];
    }
    return 0;
}
