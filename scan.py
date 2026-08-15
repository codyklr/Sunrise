import ctypes
from ctypes import wintypes
import sys

kernel32 = ctypes.windll.kernel32

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD)
    ]

def scan_memory(pid, k_c, k_r):
    h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    
    k_curr = (k_c).to_bytes(4, byteorder='little', signed=True)
    k_res = (k_r).to_bytes(4, byteorder='little', signed=True)
    
    matches = []
    
    while address < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
            
        base_addr = mbi.BaseAddress or 0
        if mbi.State == MEM_COMMIT and (mbi.Protect == PAGE_READWRITE or mbi.Protect == PAGE_EXECUTE_READWRITE):
            buffer = ctypes.create_string_buffer(mbi.RegionSize)
            bytes_read = ctypes.c_size_t(0)
            if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(base_addr), buffer, mbi.RegionSize, ctypes.byref(bytes_read)):
                data = buffer.raw[:bytes_read.value]
                idx = 0
                while True:
                    idx = data.find(k_curr, idx)
                    if idx == -1: break
                    if idx % 4 == 0:
                        # Check around for the reserve ammo within +/- 256 bytes
                        start_search = max(0, idx - 256)
                        end_search = min(len(data), idx + 256)
                        res_idx = data.find(k_res, start_search, end_search)
                        if res_idx != -1 and res_idx % 4 == 0:
                            matches.append(base_addr + idx)
                            
                            # if res_idx is -48 or -104 or +128, etc... we want to track it
                            offset = res_idx - idx
                            # It's an ammo block! Let's search for energy and power near it too
                            
                            # Energy
                            e_c = (8).to_bytes(4, byteorder='little', signed=True)
                            e_r = (0).to_bytes(4, byteorder='little', signed=True)
                            p_c = (26).to_bytes(4, byteorder='little', signed=True)
                            p_r = (0).to_bytes(4, byteorder='little', signed=True)
                            
                            def find_nearby_pair(curr, res, search_s, search_e):
                                c_i = data.find(curr, search_s, search_e)
                                if c_i != -1 and c_i % 4 == 0:
                                    r_i = data.find(res, max(0, c_i - 256), min(len(data), c_i + 256))
                                    if r_i != -1 and r_i % 4 == 0:
                                        return c_i, r_i - c_i
                                return -1, 0
                                
                            e_i, e_off = find_nearby_pair(e_c, e_r, start_search, end_search)
                            p_i, p_off = find_nearby_pair(p_c, p_r, start_search, end_search)
                            
                            if e_i != -1 and p_i != -1:
                                print(f"*** FOUND AMMO CLUSTER ***")
                                print(f"  Kinetic: {hex(base_addr + idx)} (reserve offset {offset})")
                                print(f"  Energy : {hex(base_addr + e_i)} (reserve offset {e_off})")
                                print(f"  Power  : {hex(base_addr + p_i)} (reserve offset {p_off})")
                                
                    idx += 4
        address = base_addr + mbi.RegionSize

    print(f"Found {len(matches)} occurrences of {k_c}")
    kernel32.CloseHandle(h_process)

if __name__ == "__main__":
    scan_memory(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
