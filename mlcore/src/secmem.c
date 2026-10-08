#include "mlcore.h"
#include <windows.h>
#include <string.h>

MLCORE_API int mlcore_init(void) {
    // Windows CNG/BCrypt doesn't require explicit global initialization here
    return 0;
}

MLCORE_API void* mlcore_malloc(size_t size) {
    if (size == 0) return NULL;
    void* ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) {
        // Attempt to lock in RAM (this can fail if size is too large or quota is reached,
        // but it's best-effort. In a real kernel driver or agent, we'd ensure working set size is increased).
        VirtualLock(ptr, size);
    }
    return ptr;
}

MLCORE_API void mlcore_free(void* ptr, size_t size) {
    if (ptr) {
        SecureZeroMemory(ptr, size);
        VirtualUnlock(ptr, size);
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}
