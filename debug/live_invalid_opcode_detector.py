import socket
import sys
import ctypes
from ctypes import wintypes
import os

DWORD64 = ctypes.c_uint64
HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
PCSTR = ctypes.c_char_p
ULONG = wintypes.ULONG
ULONG64 = ctypes.c_uint64
CHAR = ctypes.c_char

dbghelp = ctypes.windll.dbghelp
kernel32 = ctypes.windll.kernel32
h_process = kernel32.GetCurrentProcess()

dbghelp.SymInitialize.argtypes = [HANDLE, PCSTR, BOOL]
dbghelp.SymInitialize.restype = BOOL
dbghelp.SymLoadModuleEx.argtypes = [HANDLE, HANDLE, PCSTR, PCSTR, DWORD64, DWORD, ctypes.c_void_p, DWORD]
dbghelp.SymLoadModuleEx.restype = DWORD64

class SYMBOL_INFO(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG), ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2), ("Index", ULONG),
        ("Size", ULONG), ("ModBase", ULONG64),
        ("Flags", ULONG), ("Value", ULONG64),
        ("Address", ULONG64), ("Register", ULONG),
        ("Scope", ULONG), ("Tag", ULONG),
        ("NameLen", ULONG), ("MaxNameLen", ULONG),
        ("Name", CHAR * 2048)
    ]

EnumSymCallback = ctypes.WINFUNCTYPE(BOOL, ctypes.POINTER(SYMBOL_INFO), ULONG, ctypes.c_void_p)
symbols = []

def callback(p_sym, size, ctx):
    s = p_sym.contents
    name = s.Name[:s.NameLen].decode('utf-8', errors='ignore')
    symbols.append((s.Address, name))
    return True

print("Loading ntoskrnl symbols...")
curr_dir = os.path.abspath(os.path.dirname(__file__))
pdb_new_dir = os.path.join(curr_dir, "pdb_new")
pe_path = os.path.join(curr_dir, "ntoskrnl.exe")
pe_size = os.path.getsize(pe_path)

dbghelp.SymCleanup(h_process)
dbghelp.SymInitialize(h_process, pdb_new_dir.encode('utf-8'), False)
dbghelp.SymSetOptions(0x2 | 0x4)
base_addr = dbghelp.SymLoadModuleEx(h_process, None, pe_path.encode('utf-8'), None, 0x140000000, pe_size, None, 0)

if not base_addr:
    print("Failed to load symbols!")
    sys.exit(1)

dbghelp.SymEnumSymbols.argtypes = [HANDLE, ULONG64, PCSTR, EnumSymCallback, ctypes.c_void_p]
dbghelp.SymEnumSymbols(h_process, ctypes.c_uint64(base_addr), b"*", EnumSymCallback(callback), None)
print(f"Loaded {len(symbols)} symbols.")

def parse_gdb_packet(packet):
    if not packet.startswith(b'$') or b'#' not in packet:
        return b''
    content = packet.split(b'#')[0][1:]
    return content

def make_gdb_packet(data):
    checksum = sum(data) % 256
    return f"${data.decode('latin1')}#{checksum:02X}".encode('latin1')

def send_and_receive(sock, command):
    sock.sendall(make_gdb_packet(command))
    sock.recv(1)
    response = b''
    while True:
        char = sock.recv(1)
        response += char
        if char == b'#':
            response += sock.recv(2)
            break
    return parse_gdb_packet(response)

def get_symbol_at(target_va):
    closest_name = "Unknown"
    closest_addr = 0
    closest_diff = 0xFFFFFFFFFFFFFFFF
    for addr, name in symbols:
        diff = target_va - addr
        if diff >= 0 and diff < closest_diff:
            closest_diff = diff
            closest_addr = addr
            closest_name = name
    return closest_name, closest_diff

def debug_live():
    print("Connecting to QEMU GDB stub...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('127.0.0.1', 1234))
    except Exception as e:
        print(f"Could not connect to QEMU GDB: {e}")
        return

    print("Connected! Pausing VM to find kernel base...")
    # Send interrupt packet to stop the VM wherever it is currently running
    sock.sendall(b'\x03')
    
    stop_response = b''
    while True:
        char = sock.recv(1)
        stop_response += char
        if char == b'#':
            stop_response += sock.recv(2)
            break
            
    print(f"Target stopped: {stop_response}")

    # Read registers to find current RIP
    regs_hex = send_and_receive(sock, b'g')
    
    def get_reg(idx):
        start = idx * 16
        end = start + 16
        b = bytes.fromhex(regs_hex[start:end].decode('latin1'))
        return int.from_bytes(b, 'little')

    rip = get_reg(16)
    print(f"Interrupted at RIP: 0x{rip:X}")

    # Resolve RIP to find kernel base
    # Kernel addresses start with 0xFFFFF80...
    if (rip & 0xFFFFF80000000000) != 0xFFFFF80000000000:
        print("Error: CPU was interrupted in user-mode or bootloader. Please let it boot for a few seconds, then try again.")
        sock.close()
        return

    # Find closest symbol in ntoskrnl.exe to calculate base
    closest_name = "Unknown"
    closest_addr = 0
    closest_diff = 0xFFFFFFFFFFFFFFFF
    
    # We guess a candidate base. Since RIP is near kernel space, we test base addresses
    # alignment at 2MB boundaries.
    # Standard KASLR base is between 0xFFFFF80000000000 and 0xFFFFF80FFFFFFFFF
    # Let's align RIP to 2MB boundary and search down
    candidate_base = (rip & 0xFFFFFFFFFFE00000)
    kernel_base = 0
    
    # Brute-force lookup for base:
    # A correct base will align RIP such that (RIP - base) + 0x140000000 points to a valid function
    # and has a small offset.
    print("Resolving live kernel base...")
    for offset_check in range(0, 16 * 1024 * 1024, 2 * 1024 * 1024):
        test_base = candidate_base - offset_check
        test_pe_va = 0x140000000 + (rip - test_base)
        name, diff = get_symbol_at(test_pe_va)
        if diff < 0x50000: # Found a valid function within 320KB
            kernel_base = test_base
            print(f"Found Kernel Base: 0x{kernel_base:X} (based on symbol: {name} + 0x{diff:X})")
            break
            
    if not kernel_base:
        # Try searching further up
        for offset_check in range(2 * 1024 * 1024, 64 * 1024 * 1024, 2 * 1024 * 1024):
            test_base = candidate_base + offset_check
            test_pe_va = 0x140000000 + (rip - test_base)
            name, diff = get_symbol_at(test_pe_va)
            if diff < 0x50000:
                kernel_base = test_base
                print(f"Found Kernel Base: 0x{kernel_base:X} (based on symbol: {name} + 0x{diff:X})")
                break

    if not kernel_base:
        print("Error: Could not determine kernel base address. Try interrupting again.")
        sock.close()
        return

    # KiInvalidOpcodeFault RVA is 0x6B7B40
    fault_address = kernel_base + 0x6B7B40
    print(f"Setting Software Breakpoint at KiInvalidOpcodeFault (0x{fault_address:X})...")
    
    # GDB Software Breakpoint command: Z0,addr,kind
    # Kind is 1 for x86-64 software breakpoints
    bp_cmd = f"Z0,{fault_address:x},1".encode('latin1')
    bp_response = send_and_receive(sock, bp_cmd)
    print(f"Breakpoint Response: {bp_response}")

    print("\nResuming execution... GDB will break when an invalid instruction is hit!")
    sock.sendall(make_gdb_packet(b'c'))
    sock.recv(1) # Ack

    # Wait for the breakpoint to hit
    stop_reason = b''
    while True:
        char = sock.recv(1)
        stop_reason += char
        if char == b'#':
            stop_reason += sock.recv(2)
            break

    print(f"\n==============================================================")
    print(f"ILLEGAL INSTRUCTION DETECTED!")
    print(f"==============================================================")
    print(f"Debugger stopped: {stop_reason}")

    # Read registers at the breakpoint
    regs_hex = send_and_receive(sock, b'g')
    rsp = get_reg(7)
    
    # Read the hardware-pushed Trap Frame
    # RSP points to the exception RIP (8 bytes)
    mem_cmd = f"m{rsp:x},8".encode('latin1')
    faulting_rip_hex = send_and_receive(sock, mem_cmd)
    faulting_rip = int.from_bytes(bytes.fromhex(faulting_rip_hex.decode('latin1')), 'little')
    print(f"Faulting Instruction RIP: 0x{faulting_rip:X}")

    # Dump the invalid instruction bytes from VM memory (15 bytes maximum instruction size)
    mem_cmd = f"m{faulting_rip:x},f".encode('latin1')
    inst_hex = send_and_receive(sock, mem_cmd)
    inst_bytes = bytes.fromhex(inst_hex.decode('latin1'))
    
    # Format instruction bytes
    hex_str = " ".join(f"{b:02X}" for b in inst_bytes)
    print(f"Faulting Opcode Bytes:   {hex_str}")

    # Let's read a bit more stack to get the user-mode stack context
    mem_cmd = f"m{rsp:x},28".encode('latin1')
    frame_hex = send_and_receive(sock, mem_cmd)
    frame_bytes = bytes.fromhex(frame_hex.decode('latin1'))
    cs = int.from_bytes(frame_bytes[8:16], 'little')
    rflags = int.from_bytes(frame_bytes[16:24], 'little')
    user_rsp = int.from_bytes(frame_bytes[24:32], 'little')
    
    print(f"CS: 0x{cs:X} | RFLAGS: 0x{rflags:X} | User RSP: 0x{user_rsp:X}")

    # Clean up breakpoint before exiting
    print("\nRemoving breakpoint...")
    remove_bp_cmd = f"z0,{fault_address:x},1".encode('latin1')
    send_and_receive(sock, remove_bp_cmd)

    sock.close()
    dbghelp.SymCleanup(h_process)

if __name__ == '__main__':
    debug_live()
