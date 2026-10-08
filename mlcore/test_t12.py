import os
import sys

# Add parent directory to path so we can import mlref
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mlref.blob
from mlcore import MLCore

def main():
    print("Starting T-12 Differential Tests (Phase 2 completion)...")
    
    mc = MLCore()
    
    vmk = os.urandom(32)
    vault_id = os.urandom(16)
    file_id = os.urandom(32)
    chunk_log2 = 12
    pt = os.urandom(10000) # about 2.5 chunks
    
    print("\n[Test 1] Python Encrypt -> C Decrypt")
    py_blob, py_res = mlref.blob.encrypt_bytes(pt, vmk=vmk, vault_id=vault_id, chunk_log2=chunk_log2)
    
    try:
        c_pt = mc.blob_decrypt(vmk, vault_id, chunk_log2, py_blob, expected_file_id=py_res.file_id)
        assert c_pt == pt, "C failed to correctly decrypt Python blob"
        print("  -> PASSED")
    except Exception as e:
        print("  -> FAILED:", e)
        sys.exit(1)
        
    print("\n[Test 2] C Encrypt -> Python Decrypt")
    try:
        c_blob, c_hash = mc.blob_encrypt(vmk, vault_id, py_res.file_id, chunk_log2, pt)
        
        py_pt = mlref.blob.decrypt_bytes(c_blob, vmk=vmk, vault_id=vault_id, chunk_log2=chunk_log2, content_alg=1)
        assert py_pt == pt, "Python failed to correctly decrypt C blob"
        print("  -> PASSED")
    except Exception as e:
        print("  -> FAILED:", e)
        sys.exit(1)
        
    print("\n[Test 3] Tamper Detection (C Decrypt catches tampered Python blob)")
    tampered_blob = bytearray(py_blob)
    tampered_blob[-1] ^= 1 # flip last bit of tag
    try:
        mc.blob_decrypt(vmk, vault_id, chunk_log2, bytes(tampered_blob), expected_file_id=py_res.file_id)
        print("  -> FAILED: C failed to catch tampered blob!")
        sys.exit(1)
    except RuntimeError as e:
        if "auth failed" in str(e):
            print("  -> PASSED (Caught modification)")
        else:
            print("  -> FAILED: Wrong error", e)
            sys.exit(1)
            
    print("\n===============================")
    print("All T-12 Differential Tests PASSED!")
    print("Phase 2 is fully complete.")

if __name__ == '__main__':
    main()
