#include "manifest.h"
#include <string.h>

#define TLV_HDR_LEN 6
#define FILE_FIXED_LEN 84 // 32 + 8 + 8 + 4 + 32
#define DIR_FIXED_LEN 12 // 8 + 4

static uint16_t unpack_uint16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t unpack_uint32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }
static uint64_t unpack_uint64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i=0; i<8; i++) v |= ((uint64_t)p[i]) << (i*8);
    return v;
}

MLCORE_API int mlcore_manifest_parse_item(const uint8_t* buf, size_t buf_len, 
                                          mlcore_manifest_file_t* out_file,
                                          mlcore_manifest_dir_t* out_dir,
                                          size_t* consumed_out) {
    if (buf_len < TLV_HDR_LEN) return -1;
    
    uint16_t type = unpack_uint16(buf);
    uint32_t len = unpack_uint32(buf + 2);
    
    if (len > 65536 || len > buf_len - TLV_HDR_LEN) return -1;
    
    const uint8_t* val = buf + TLV_HDR_LEN;
    *consumed_out = TLV_HDR_LEN + len;
    
    if (type == MLCORE_TLV_INFO) {
        // Just skip INFO records
        return type;
    } else if (type == MLCORE_TLV_FILE) {
        if (len < FILE_FIXED_LEN) return -1;
        if (out_file) {
            memcpy(out_file->file_id, val, 32);
            out_file->size = unpack_uint64(val + 32);
            out_file->mtime_ns = unpack_uint64(val + 40);
            out_file->attrs = unpack_uint32(val + 48);
            memcpy(out_file->header_hash, val + 52, 32);
            out_file->path = (const char*)(val + FILE_FIXED_LEN);
            out_file->path_len = len - FILE_FIXED_LEN;
        }
        return type;
    } else if (type == MLCORE_TLV_DIR) {
        if (len < DIR_FIXED_LEN) return -1;
        if (out_dir) {
            out_dir->mtime_ns = unpack_uint64(val);
            out_dir->attrs = unpack_uint32(val + 8);
            out_dir->path = (const char*)(val + DIR_FIXED_LEN);
            out_dir->path_len = len - DIR_FIXED_LEN;
        }
        return type;
    } else {
        // Unrecognized type. If critical bit is set, we must fail.
        if (type & 0x8000) return -1;
        // Otherwise skip
        return type;
    }
}
