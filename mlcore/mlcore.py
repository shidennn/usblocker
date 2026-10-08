import ctypes
import os

class ManifestFile(ctypes.Structure):
    _fields_ = [
        ("file_id", ctypes.c_uint8 * 32),
        ("size", ctypes.c_uint64),
        ("mtime_ns", ctypes.c_uint64),
        ("attrs", ctypes.c_uint32),
        ("header_hash", ctypes.c_uint8 * 32),
        ("path", ctypes.c_char_p),
        ("path_len", ctypes.c_size_t),
    ]

class VaultHdr(ctypes.Structure):
    _fields_ = [
        ("vault_id", ctypes.c_uint8 * 16),
        ("created", ctypes.c_uint64),
        ("epoch", ctypes.c_uint64),
        ("version", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("alg", ctypes.c_uint8),
        ("clog", ctypes.c_uint8),
    ]

class MLCore:
    def __init__(self, dll_path=None):
        if dll_path is None:
            dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mlcore.dll'))
        
        self.lib = ctypes.CDLL(dll_path)
        
        # Crypto
        self.lib.mlcore_kdf.restype = ctypes.c_int
        self.lib.mlcore_kdf.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t]
        
        # Blob
        self.lib.mlcore_blob_enc_init.restype = ctypes.c_void_p
        self.lib.mlcore_blob_enc_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p]
        
        self.lib.mlcore_blob_enc_update.restype = ctypes.c_int
        self.lib.mlcore_blob_enc_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_int]
        
        self.lib.mlcore_blob_enc_get_plain_sha256.restype = None
        self.lib.mlcore_blob_enc_get_plain_sha256.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.lib.mlcore_blob_dec_init.restype = ctypes.c_void_p
        self.lib.mlcore_blob_dec_init.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint8, ctypes.c_void_p, ctypes.c_void_p]
        
        self.lib.mlcore_blob_dec_update.restype = ctypes.c_int
        self.lib.mlcore_blob_dec_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_int]

        self.lib.mlcore_blob_free.restype = None
        self.lib.mlcore_blob_free.argtypes = [ctypes.c_void_p]
        
        # Manifest
        self.lib.mlcore_manifest_parse_item.restype = ctypes.c_int
        self.lib.mlcore_manifest_parse_item.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ManifestFile), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]

        # Vault
        self.lib.mlcore_vault_parse_hdr.restype = ctypes.c_int
        self.lib.mlcore_vault_parse_hdr.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(VaultHdr)]

    def kdf(self, password: bytes, salt: bytes, t_cost: int, m_cost: int, parallelism: int, out_len: int = 32) -> bytes:
        out = ctypes.create_string_buffer(out_len)
        res = self.lib.mlcore_kdf(password, len(password), salt, len(salt), t_cost, m_cost, parallelism, out, out_len)
        if res != 0:
            raise RuntimeError("mlcore_kdf failed")
        return out.raw
        
    def blob_encrypt(self, vmk: bytes, vault_id: bytes, file_id: bytes, chunk_log2: int, plaintext: bytes) -> tuple[bytes, bytes]:
        """Encrypts full plaintext in one go for testing. Returns (blob_data, plain_hash)"""
        hdr_out = ctypes.create_string_buffer(96)
        ctx = self.lib.mlcore_blob_enc_init(vmk, vault_id, file_id, chunk_log2, hdr_out)
        if not ctx:
            raise RuntimeError("mlcore_blob_enc_init failed")
            
        try:
            csize = 1 << chunk_log2
            out_blob = bytearray(hdr_out.raw)
            off = 0
            while True:
                chunk = plaintext[off:off+csize]
                is_last = 1 if off + len(chunk) == len(plaintext) else 0
                
                ct_out = ctypes.create_string_buffer(12 + len(chunk) + 16)
                ct_len = ctypes.c_size_t(0)
                
                res = self.lib.mlcore_blob_enc_update(ctx, chunk, len(chunk), ct_out, ctypes.byref(ct_len), is_last)
                if res != 0:
                    raise RuntimeError("mlcore_blob_enc_update failed")
                    
                out_blob.extend(ct_out.raw[:ct_len.value])
                off += len(chunk)
                if is_last:
                    break
                    
            hash_out = ctypes.create_string_buffer(32)
            self.lib.mlcore_blob_enc_get_plain_sha256(ctx, hash_out)
            return bytes(out_blob), hash_out.raw
        finally:
            self.lib.mlcore_blob_free(ctx)

    def blob_decrypt(self, vmk: bytes, vault_id: bytes, chunk_log2: int, blob_data: bytes, expected_file_id: bytes = None) -> bytes:
        """Decrypts full blob. Returns plaintext."""
        if len(blob_data) < 96:
            raise RuntimeError("Blob too small")
            
        ctx = self.lib.mlcore_blob_dec_init(vmk, vault_id, chunk_log2, blob_data[:96], expected_file_id)
        if not ctx:
            raise RuntimeError("mlcore_blob_dec_init failed (bad header or key)")
            
        try:
            full_chunk_len = 12 + (1 << chunk_log2) + 16
            out_pt = bytearray()
            off = 96
            while True:
                chunk_data = blob_data[off:off+full_chunk_len]
                if not chunk_data:
                    break
                is_last = 1 if off + len(chunk_data) == len(blob_data) else 0
                
                pt_out = ctypes.create_string_buffer(len(chunk_data) - 12 - 16)
                pt_len = ctypes.c_size_t(0)
                
                res = self.lib.mlcore_blob_dec_update(ctx, chunk_data, len(chunk_data), pt_out, ctypes.byref(pt_len), is_last)
                if res != 0:
                    raise RuntimeError("mlcore_blob_dec_update failed (auth failed)")
                    
                out_pt.extend(pt_out.raw[:pt_len.value])
                off += len(chunk_data)
                if is_last:
                    break
            return bytes(out_pt)
        finally:
            self.lib.mlcore_blob_free(ctx)
