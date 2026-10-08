import ctypes
import os
import sys

def main():
    dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'mlcore.dll'))
    if not os.path.exists(dll_path):
        print(f"DLL not found at {dll_path}")
        sys.exit(1)
        
    print(f"Loading {dll_path}...")
    try:
        mlcore = ctypes.CDLL(dll_path)
    except Exception as e:
        print(f"Failed to load DLL: {e}")
        sys.exit(1)
    
    mlcore.mlcore_init.restype = ctypes.c_int
    mlcore.mlcore_init.argtypes = []
    
    mlcore.mlcore_malloc.restype = ctypes.c_void_p
    mlcore.mlcore_malloc.argtypes = [ctypes.c_size_t]
    
    mlcore.mlcore_free.restype = None
    mlcore.mlcore_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    
    print("Calling mlcore_init()...")
    res = mlcore.mlcore_init()
    if res != 0:
        print("mlcore_init failed!")
        sys.exit(1)
    print("mlcore_init succeeded.")
    
    print("Testing secure memory allocation...")
    size = 32
    ptr = mlcore.mlcore_malloc(size)
    if ptr:
        print("mlcore_malloc succeeded.")
        mlcore.mlcore_free(ptr, size)
        print("mlcore_free succeeded.")
    else:
        print("mlcore_malloc failed.")
        sys.exit(1)

if __name__ == '__main__':
    main()
