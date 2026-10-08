import ctypes
import os
import sys
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mlref.manifest
import mlref.vault

def main():
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mlcore.dll'))
    mlcore = ctypes.CDLL(dll_path)
    
    # test manifest
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
        
    mlcore.mlcore_manifest_parse_item.restype = ctypes.c_int
    mlcore.mlcore_manifest_parse_item.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ManifestFile), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]

    # create a mock python manifest file record
    d = mlref.manifest.DirEntry("test", 123456789, 0)
    f = mlref.manifest.FileEntry("test/file.txt", b"x"*32, 1024, 123456789, 0, b"y"*32)
    m = mlref.manifest.Manifest({"test/file.txt": f}, {"test": d})
    data = m.encode()
    
    off = 0
    while off < len(data):
        consumed = ctypes.c_size_t(0)
        out_file = ManifestFile()
        res = mlcore.mlcore_manifest_parse_item(data[off:], len(data) - off, ctypes.byref(out_file), None, ctypes.byref(consumed))
        if res < 0:
            print("Failed to parse item at offset", off)
            sys.exit(1)
            
        if res == mlref.constants.TLV_FILE:
            parsed_path = ctypes.string_at(out_file.path, out_file.path_len).decode('utf-8')
            if parsed_path != "test/file.txt" or out_file.size != 1024:
                print("Manifest mismatch!")
                sys.exit(1)
        off += consumed.value

    print("Manifest parsing PASSED!")
    
    # test vault header
    class VaultHdr(ctypes.Structure):
        _fields_ = [
            ("vault_id", ctypes.c_uint8 * 16),
            ("created", ctypes.c_uint64),
            ("epoch", ctypes.c_uint64),
            ("version", ctypes.c_uint16),
            ("flags", ctypes.c_uint16),
        ]
        
    mlcore.mlcore_vault_parse_hdr.restype = ctypes.c_int
    mlcore.mlcore_vault_parse_hdr.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(VaultHdr)]
    
    vhdr_data = struct.pack("<8sHH16sQQBB2s", b"MLVAULT\x00", 1, 0, b"v"*16, 100, 200, 1, 12, b"\x00\x00")
    out_vhdr = VaultHdr()
    res = mlcore.mlcore_vault_parse_hdr(vhdr_data, len(vhdr_data), ctypes.byref(out_vhdr))
    if res != 0 or out_vhdr.epoch != 200:
        print("Vault header parse failed")
        sys.exit(1)
        
    print("Vault header parsing PASSED!")

if __name__ == '__main__':
    main()
