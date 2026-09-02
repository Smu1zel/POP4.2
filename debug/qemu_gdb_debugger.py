import socket
import sys
import ctypes
from ctypes import wintypes
import os
import pefile

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
pe_path = os.path.join(curr_dir, "ntoskrnl.exe")
pe_size = os.path.getsize(pe_path)

dbghelp.SymCleanup(h_process)
dbghelp.SymInitialize(h_process, curr_dir.encode('utf-8'), False)
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

def debug_qemu():
    print("Connecting to QEMU GDB stub...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('127.0.0.1', 1234))
    except Exception as e:
        print(f"Could not connect: {e}")
        return
        
    print("Connected! Initializing status query...")
    status = send_and_receive(sock, b'?')
    print(f"Initial Status Response: {status}")
    
    print("\nResuming QEMU execution to boot Windows...")
    sock.sendall(make_gdb_packet(b'c'))
    sock.recv(1) # Read '+' ack
    
    print("==============================================================")
    print("QEMU IS NOW BOOTING!")
    print("Please let it boot until it crashes / freezes (infinite loop).")
    print("Press [Enter] in this terminal when it is frozen to dump stack.")
    print("==============================================================")
    
    input()
    
    print("Sending interrupt (Ctrl-C / 0x03) to target CPU...")
    sock.sendall(b'\x03')
    stop_response = b''
    while True:
        char = sock.recv(1)
        stop_response += char
        if char == b'#':
            stop_response += sock.recv(2)
            break
            
    print(f"Target stopped: {stop_response}")
    
    # Read registers
    regs_hex = send_and_receive(sock, b'g')
    
    def get_reg(idx):
        start = idx * 16
        end = start + 16
        b = bytes.fromhex(regs_hex[start:end].decode('latin1'))
        return int.from_bytes(b, 'little')
        
    rsp = get_reg(7)  # RSP
    rip = get_reg(16) # RIP
    rsi = get_reg(4)  # Live RSI register!
    
    # RVA of KeBugCheckEx is 0x4F6880
    kernel_base = rip - 0x4F6880
    print(f"RIP: 0x{rip:X}")
    print(f"RSP: 0x{rsp:X}")
    print(f"Live RSI: 0x{rsi:X}")
    print(f"Calculated Kernel Base: 0x{kernel_base:X}")
    
    # Dump 320 bytes from stack (40 QWORDS) to capture saved registers
    length = 320
    mem_cmd = f"m{rsp:x},{length:x}".encode('latin1')
    stack_hex = send_and_receive(sock, mem_cmd)
    stack_bytes = bytes.fromhex(stack_hex.decode('latin1'))
    
    print("\nCall Stack Resolution (RSP Frame):")
    print("==============================================================")
    for i in range(0, len(stack_bytes), 8):
        curr_addr = rsp + i
        qword = int.from_bytes(stack_bytes[i:i+8], 'little')
        
        if kernel_base <= qword <= kernel_base + 15 * 1024 * 1024:
            rva = qword - kernel_base
            pe_va = 0x140000000 + rva
            name, diff = get_symbol_at(pe_va)
            print(f"  RSP+0x{i:03X}: 0x{qword:016X} -> {name} + 0x{diff:X} (RVA: 0x{rva:X})")
        else:
            print(f"  RSP+0x{i:03X}: 0x{qword:016X}")
            
    # Read 40 bytes of memory directly from the VM at (live rsi - 4)
    # The structure layout starts 4 bytes before rsi
    entry_addr = rsi - 4
    mem_cmd = f"m{entry_addr:x},28".encode('latin1') # 0x28 = 40 bytes
    entry_hex = send_and_receive(sock, mem_cmd)
    
    if entry_hex:
        entry_bytes = bytes.fromhex(entry_hex.decode('latin1'))
        
        # Parse the 40-byte entry directly from live memory
        leaf = int.from_bytes(entry_bytes[0:4], 'little', signed=True)
        subleaf = int.from_bytes(entry_bytes[4:8], 'little', signed=True)
        mask = int.from_bytes(entry_bytes[8:12], 'little', signed=False)
        reg_idx = int.from_bytes(entry_bytes[12:16], 'little', signed=True)
        flags = int.from_bytes(entry_bytes[16:20], 'little', signed=True)
        features1 = int.from_bytes(entry_bytes[20:28], 'little', signed=False)
        features2 = int.from_bytes(entry_bytes[28:36], 'little', signed=False)
        
        reg_names = ["EAX", "EBX", "ECX", "EDX"]
        reg_name = reg_names[reg_idx] if 0 <= reg_idx < 4 else f"Reg{reg_idx}"
        
        print(f"\nFailed CPUID Requirement Details (Read from VM Memory):")
        print(f"==============================================================")
        print(f"  CPUID Leaf:     0x{leaf:X}")
        print(f"  CPUID Subleaf:  0x{subleaf:X}")
        print(f"  Register:       {reg_name}")
        print(f"  Required Mask:  0x{mask:08X}")
        print(f"  Flags:          0x{flags:X}")
        print(f"  Features 1:     0x{features1:016X}")
        print(f"  Features 2:     0x{features2:016X}")
    else:
        print("Error: Could not read requirements entry memory from QEMU.")
            
    sock.close()
    dbghelp.SymCleanup(h_process)

if __name__ == '__main__':
    debug_qemu()
