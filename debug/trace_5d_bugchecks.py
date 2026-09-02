import pefile
from capstone import *
from capstone.x86 import *

pe = pefile.PE("done/ntoskrnl.exe")
base = pe.OPTIONAL_HEADER.ImageBase

# Find all occurrences of mov ecx, 0x5D (BugCheck 0x5D)
with open("done/ntoskrnl.exe", "rb") as f:
    data = f.read()

target_bytes = b"\xB9\x5D\x00\x00\x00"
occurrences = []
offset = -1
while True:
    offset = data.find(target_bytes, offset + 1)
    if offset == -1:
        break
    occurrences.append(offset)

print(f"Found {len(occurrences)} BugCheck 0x5D locations. Scanning backwards to find CPU feature masks...")

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for off in occurrences:
    rva = pe.get_rva_from_offset(off)
    
    # We will disassemble 100 bytes BEFORE the BugCheck 0x5D to see what was being checked
    start_rva = max(0, rva - 100)
    code = pe.get_data(pe.get_offset_from_rva(start_rva), rva - start_rva + 5)
    
    # We want to see cmp, test, and masks
    instructions = list(md.disasm(code, base + start_rva))
    if not instructions:
        continue
        
    print(f"\n--- BugCheck 0x5D at offset 0x{off:X} (RVA 0x{rva:X}) ---")
    for i in instructions[-15:]:  # Show last 15 instructions before BugCheck
        print(f"0x{i.address:X}:\t{i.mnemonic}\t{i.op_str}")
