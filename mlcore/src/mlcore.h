#ifndef MLCORE_H
#define MLCORE_H

#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
#define MLCORE_API __declspec(dllexport)
#else
#define MLCORE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Initialize mlcore
MLCORE_API int mlcore_init(void);

// Secure memory allocation (locked in physical RAM)
MLCORE_API void* mlcore_malloc(size_t size);
MLCORE_API void mlcore_free(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif // MLCORE_H
