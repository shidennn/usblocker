import ctypes
import os
import sys

def main():
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mlcore.dll'))
    if not os.path.exists(dll_path):
        print(f"DLL not found at {dll_path}")
        sys.exit(1)
        
    print(f"Loading {dll_path}...")
    mlcore = ctypes.CDLL(dll_path)
    
    # mlcore_randombytes
    mlcore.mlcore_randombytes.restype = ctypes.c_int
    mlcore.mlcore_randombytes.argtypes = [ctypes.c_void_p, ctypes.c_size_t]

    # mlcore_kdf
    mlcore.mlcore_kdf.restype = ctypes.c_int
    mlcore.mlcore_kdf.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, 
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]

    # mlcore_aead_encrypt
    mlcore.mlcore_aead_encrypt.restype = ctypes.c_int
    mlcore.mlcore_aead_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]

    # mlcore_aead_decrypt
    mlcore.mlcore_aead_decrypt.restype = ctypes.c_int
    mlcore.mlcore_aead_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]

    print("Testing random bytes...")
    buf = ctypes.create_string_buffer(32)
    res = mlcore.mlcore_randombytes(buf, 32)
    if res != 0:
        print("randombytes failed!")
        sys.exit(1)
    print("randombytes ok:", buf.raw.hex())

    print("Testing Argon2id KDF...")
    pwd = b"password"
    salt = b"somesalt"
    out_key = ctypes.create_string_buffer(32)
    # t=2, m=65536, p=1
    res = mlcore.mlcore_kdf(pwd, len(pwd), salt, len(salt), 2, 65536, 1, out_key, 32)
    if res != 0:
        print("kdf failed!")
        sys.exit(1)
    print("kdf ok:", out_key.raw.hex())

    print("Testing AES-GCM...")
    key = os.urandom(32)
    nonce = os.urandom(12)
    pt = b"Hello, World! This is a test."
    aad = b"HeaderData"
    
    ct_out = ctypes.create_string_buffer(len(pt))
    tag_out = ctypes.create_string_buffer(16)
    
    res = mlcore.mlcore_aead_encrypt(key, nonce, len(nonce), pt, len(pt), aad, len(aad), ct_out, tag_out)
    if res != 0:
        print("aead_encrypt failed!")
        sys.exit(1)
    print("aead_encrypt ok.")
    
    pt_out = ctypes.create_string_buffer(len(pt))
    res = mlcore.mlcore_aead_decrypt(key, nonce, len(nonce), ct_out, len(pt), aad, len(aad), tag_out, pt_out)
    if res != 0:
        print("aead_decrypt failed!")
        sys.exit(1)
        
    if pt_out.raw == pt:
        print("aead_decrypt ok, plaintext matches!")
    else:
        print("aead_decrypt failed, plaintext mismatch!")
        sys.exit(1)

    print("All tests passed.")

if __name__ == '__main__':
    main()
