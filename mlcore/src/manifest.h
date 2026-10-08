#ifndef MLCORE_MANIFEST_H
#define MLCORE_MANIFEST_H

#include "mlcore.h"

#define MLCORE_TLV_INFO 0x8001
#define MLCORE_TLV_FILE 0x8010
#define MLCORE_TLV_DIR 0x8011

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mlcore_manifest_file {
    uint8_t file_id[32];
    uint64_t size;
    uint64_t mtime_ns;
    uint32_t attrs;
    uint8_t header_hash[32];
    const char* path;
    size_t path_len;
} mlcore_manifest_file_t;

typedef struct mlcore_manifest_dir {
    uint64_t mtime_ns;
    uint32_t attrs;
    const char* path;
    size_t path_len;
} mlcore_manifest_dir_t;

// Parses a TLV item from buf.
// If it's a FILE, *out_file is populated. If it's a DIR, *out_dir is populated.
// Returns the type parsed (e.g. MLCORE_TLV_FILE) or negative on error.
// Returns the number of bytes consumed in *consumed_out.
MLCORE_API int mlcore_manifest_parse_item(const uint8_t* buf, size_t buf_len, 
                                          mlcore_manifest_file_t* out_file,
                                          mlcore_manifest_dir_t* out_dir,
                                          size_t* consumed_out);

#ifdef __cplusplus
}
#endif

#endif
