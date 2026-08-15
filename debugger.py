import ctypes
from ctypes import wintypes
import sys
import time

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002

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

class EXCEPTION_RECORD(ctypes.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD),
    ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ctypes.c_void_p),
    ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_size_t * 15)
]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD)
    ]

class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
    ]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION)
    ]

# CONTEXT structure for x64
class M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]

class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", wintypes.DWORD),
        ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("FltSave", M128A * 32), # Simplified
        ("VectorRegister", M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong)
    ]

def find_kinetic_ammo(pid):
    h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    
    k_curr = (44).to_bytes(4, byteorder='little', signed=True)
    k_res = (346).to_bytes(4, byteorder='little', signed=True)
    
    target_addr = None
    
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
                        res_idx = idx - 32
                        if res_idx >= 0 and data[res_idx:res_idx+4] == k_res:
                            target_addr = base_addr + idx
                            break
                    idx += 4
                if target_addr:
                    break
        address = base_addr + mbi.RegionSize
    kernel32.CloseHandle(h_process)
    return target_addr

def debug_process(pid, target_addr):
    if not kernel32.DebugActiveProcess(pid):
        print(f"Failed to attach debugger. Error: {kernel32.GetLastError()}")
        return

    print("Debugger attached. Waiting for threads...")
    
    # We must set HWBP on all threads
    # For simplicity, wait a moment for initial debug events, then suspend all threads and apply
    
    debug_event = DEBUG_EVENT()
    
    # Enable Hardware Breakpoint on Write (1 byte) for target_addr
    # Dr0 = target_addr
    # Dr7 = 1 (Local Dr0) | (1 << 16) (Write only) | (0 << 18) (1 byte length)
    DR7_ENABLE = 1 | (1 << 16)
    CONTEXT_DEBUG_REGISTERS = 0x100000 | 0x10
    
    threads = set()
    
    while True:
        if kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
            event_code = debug_event.dwDebugEventCode
            
            if event_code == 2: # CREATE_THREAD_DEBUG_EVENT
                threads.add(debug_event.dwThreadId)
            elif event_code == 3: # CREATE_PROCESS_DEBUG_EVENT
                threads.add(debug_event.dwThreadId)
            elif event_code == 4: # EXIT_THREAD_DEBUG_EVENT
                threads.discard(debug_event.dwThreadId)
            
            if event_code == 1: # EXCEPTION_DEBUG_EVENT
                exc_code = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                if exc_code == 0x80000004: # EXCEPTION_SINGLE_STEP (HWBP hit)
                    tid = debug_event.dwThreadId
                    print(f"\n[!] Hardware Breakpoint Triggered on Thread {tid}!")
                    
                    # Get Context
                    h_thread = kernel32.OpenThread(0x001F, False, tid)
                    ctx = CONTEXT64()
                    ctx.ContextFlags = 0x100000 | 0x01 # CONTEXT_CONTROL
                    kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
                    
                    rip = ctx.Rip
                    print(f"Instruction Pointer (RIP): {hex(rip)}")
                    
                    # Read instruction bytes
                    h_process = kernel32.OpenProcess(PROCESS_VM_READ, False, pid)
                    inst_buf = ctypes.create_string_buffer(16)
                    bytes_read = ctypes.c_size_t(0)
                    kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(rip), inst_buf, 16, ctypes.byref(bytes_read))
                    
                    hex_str = " ".join(f"{b:02X}" for b in inst_buf.raw[:bytes_read.value])
                    print(f"Instruction Bytes: {hex_str}")
                    
                    # We found it! Detach and exit.
                    kernel32.CloseHandle(h_process)
                    kernel32.CloseHandle(h_thread)
                    kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, 0x00010002)
                    kernel32.DebugActiveProcessStop(pid)
                    return
            
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, 0x00010002) # DBG_CONTINUE
        else:
            # No events for 100ms. If we haven't set HWBP yet, let's set it on all known threads.
            if getattr(debug_process, 'hwbp_set', False) == False and threads:
                for tid in threads:
                    h_thread = kernel32.OpenThread(0x001F, False, tid)
                    if h_thread:
                        kernel32.SuspendThread(h_thread)
                        ctx = CONTEXT64()
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS
                        kernel32.GetThreadContext(h_thread, ctypes.byref(ctx))
                        
                        ctx.Dr0 = target_addr
                        ctx.Dr7 = DR7_ENABLE
                        
                        kernel32.SetThreadContext(h_thread, ctypes.byref(ctx))
                        kernel32.ResumeThread(h_thread)
                        kernel32.CloseHandle(h_thread)
                print(f"Hardware Breakpoint set on {len(threads)} threads for address {hex(target_addr)}.")
                print(">>> SHOOT YOUR KINETIC WEAPON NOW <<<")
                debug_process.hwbp_set = True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)
    
    pid = int(sys.argv[1])
    addr = find_kinetic_ammo(pid)
    
    if addr:
        print(f"Kinetic Ammo found at {hex(addr)}. Attaching debugger...")
        debug_process(pid, addr)
    else:
        print("Kinetic Ammo not found.")
