#include <windows.h>
#include <bcrypt.h>
__declspec(dllexport) int test() { BCRYPT_ALG_HANDLE h; return BCryptOpenAlgorithmProvider(&h, BCRYPT_AES_ALGORITHM, NULL, 0); }