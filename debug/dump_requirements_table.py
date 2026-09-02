import pefile
import struct

pe_path = "ntoskrnl.exe"
pe = pefile.PE(pe_path)

# Table starts at RVA 0x87D0 (4 bytes before 0x87D4)
# There are 59 entries, each 40 bytes (0x28)
table_rva = 0x87D0
table_offset = pe.get_offset_from_rva(table_rva)

print(f"CPUID Requirements Table at RVA 0x{table_rva:X} (File Offset 0x{table_offset:X}):")
print("==============================================================")
print(f"Index | Leaf     | Subleaf  | Reg | Required Mask | Flags | Features 1         | Features 2")
print("--------------------------------------------------------------")

reg_names = ["EAX", "EBX", "ECX", "EDX"]

with open(pe_path, "rb") as f:
    f.seek(table_offset)
    for idx in range(59):
        entry_bytes = f.read(40)
        if len(entry_bytes) < 40:
            break
            
        leaf = struct.unpack("<i", entry_bytes[0:4])[0]
        subleaf = struct.unpack("<i", entry_bytes[4:8])[0]
        mask = struct.unpack("<I", entry_bytes[8:12])[0]
        reg_idx = struct.unpack("<i", entry_bytes[12:16])[0]
        flags = struct.unpack("<i", entry_bytes[16:20])[0]
        f1 = struct.unpack("<Q", entry_bytes[20:28])[0]
        f2 = struct.unpack("<Q", entry_bytes[28:36])[0]
        
        reg_name = reg_names[reg_idx] if 0 <= reg_idx < 4 else f"Reg{reg_idx}"
        
        # Highlight interesting requirements (like SSE4.1, SSE4.2, Popcnt, etc.)
        # Leaf 1 ECX:
        #   Bit 19: SSE4.1 (0x80000)
        #   Bit 20: SSE4.2 (0x100000)
        #   Bit 23: POPCNT (0x800000)
        #   Bit 13: CMPXCHG16B (0x2000)
        # Leaf 1 EDX:
        #   Bit 25: SSE (0x2000000)
        #   Bit 26: SSE2 (0x4000000)
        note = ""
        if leaf == 1 and reg_name == "ECX":
            if mask & 0x100000: note = " [SSE4.2]"
            elif mask & 0x80000: note = " [SSE4.1]"
            elif mask & 0x800000: note = " [POPCNT]"
            elif mask & 0x2000: note = " [CMPXCHG16B]"
            
        print(f"{idx:5d} | 0x{leaf:08X} | 0x{subleaf:08X} | {reg_name:3s} | 0x{mask:08X}    | 0x{flags:04X} | 0x{f1:016X} | 0x{f2:016X}{note}")

pe.close()
