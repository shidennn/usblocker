import ctypes
import os
import sys

# Add parent dir to path so we can import mlref
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mlref.blob

def main():
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mlcore.dll'))
    mlcore = ctypes.CDLL(dll_path)
    
    mlcore.mlcore_blob_enc_init.restype = ctypes.c_void_p
    mlcore.mlcore_blob_enc_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p]
    
    mlcore.mlcore_blob_enc_update.restype = ctypes.c_int
    mlcore.mlcore_blob_enc_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_int]
    
    mlcore.mlcore_blob_enc_get_plain_sha256.restype = None
    mlcore.mlcore_blob_enc_get_plain_sha256.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    mlcore.mlcore_blob_free.restype = None
    mlcore.mlcore_blob_free.argtypes = [ctypes.c_void_p]
    
    vmk = os.urandom(32)
    vault_id = os.urandom(16)
    file_id = os.urandom(32)
    chunk_log2 = 12
    
    # 1. Encrypt with mlcore
    hdr_out = ctypes.create_string_buffer(96)
    ctx = mlcore.mlcore_blob_enc_init(vmk, vault_id, file_id, chunk_log2, hdr_out)
    if not ctx:
        print("enc_init failed")
        sys.exit(1)
        
    pt = b"Hello, mlcore blob!"
    ct_out = ctypes.create_string_buffer(12 + len(pt) + 16)
    ct_len = ctypes.c_size_t(0)
    
    res = mlcore.mlcore_blob_enc_update(ctx, pt, len(pt), ct_out, ctypes.byref(ct_len), 1)
    if res != 0:
        print("enc_update failed")
        sys.exit(1)
        
    hash_out = ctypes.create_string_buffer(32)
    mlcore.mlcore_blob_enc_get_plain_sha256(ctx, hash_out)
    
    mlcore.mlcore_blob_free(ctx)
    
    blob_data = hdr_out.raw + ct_out.raw[:ct_len.value]
    
    # 2. Decrypt with mlref
    try:
        from mlref.blob import _HDR
        print("Header unpacked:", _HDR.unpack(hdr_out.raw))
        pt_dec = mlref.blob.decrypt_bytes(blob_data, vmk=vmk, vault_id=vault_id, chunk_log2=chunk_log2, content_alg=1)
        if pt_dec == pt:
            print("Blob differential test PASSED!")
        else:
            print("Blob mismatch:", pt_dec)
    except Exception as e:
        print("mlref decrypt failed:", e)
        sys.exit(1)

if __name__ == '__main__':
    main()
