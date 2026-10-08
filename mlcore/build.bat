@echo off

echo Compiling mlcore.dll with GCC...
gcc -shared -O2 -DARGON2_NO_THREADS -I src/argon2 ^
    src/secmem.c ^
    src/crypto.c ^
    src/blob.c ^
    src/manifest.c ^
    src/vault.c ^
    src/argon2/argon2.c ^
    src/argon2/core.c ^
    src/argon2/blake2/blake2b.c ^
    src/argon2/thread.c ^
    src/argon2/encoding.c ^
    src/argon2/ref.c ^
    -o mlcore.dll -lbcrypt

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b %ERRORLEVEL%
)

echo Build succeeded!
