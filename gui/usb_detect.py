import ctypes
import os
import glob

DRIVE_REMOVABLE = 2

def get_removable_drives() -> list[str]:
    """Returns a list of removable drive roots, e.g., ['D:\\', 'E:\\']"""
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if bitmask & 1:
            drive = f"{letter}:\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
            if drive_type == DRIVE_REMOVABLE:
                drives.append(drive)
        bitmask >>= 1
    return drives

def find_keyfiles(drive_path: str) -> list[str]:
    """Searches for .mlk keyfiles in the expected MyLocker/keys directory on the given drive."""
    keys_dir = os.path.join(drive_path, "MyLocker", "keys")
    if not os.path.isdir(keys_dir):
        return []
    
    # Return full paths to all .mlk files
    return glob.glob(os.path.join(keys_dir, "*.mlk"))

def scan_for_keys() -> list[str]:
    """Scans all removable drives and returns a list of discovered .mlk key files."""
    found_keys = []
    for drive in get_removable_drives():
        found_keys.extend(find_keyfiles(drive))
    return found_keys
