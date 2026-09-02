import struct
import sys
import os

def get_pdb_info(pe_path):
    with open(pe_path, 'rb') as f:
        # Read DOS header
        dos_header = f.read(64)
        if len(dos_header) < 64 or dos_header[0:2] != b'MZ':
            print("Not a valid PE file (DOS header)")
            return None
        
        # Get PE signature offset
        pe_offset = struct.unpack('<I', dos_header[0x3C:0x40])[0]
        
        # Seek to PE signature
        f.seek(pe_offset)
        pe_sig = f.read(4)
        if pe_sig != b'PE\x00\x00':
            print("Not a valid PE file (PE signature)")
            return None
        
        # Read COFF header
        coff_header = f.read(20)
        machine, num_sections, _, _, _, size_optional_header, _ = struct.unpack('<HHIIIHH', coff_header)
        
        # Read Magic from optional header to check 32/64 bit
        magic = struct.unpack('<H', f.read(2))[0]
        is_64bit = magic == 0x20b
        
        # Find offset to Data Directories
        # For 64-bit, the data directories start at offset 112 from the optional header start (magic is 2 bytes, so 110 bytes remaining)
        # For 32-bit, they start at offset 96 (magic is 2 bytes, so 94 bytes remaining)
        if is_64bit:
            f.seek(pe_offset + 24 + 112)
        else:
            f.seek(pe_offset + 24 + 96)
            
        # Debug directory is at index 6 in the data directories
        # Each data directory is 8 bytes (VirtualAddress, Size)
        f.seek(8 * 6, 1)
        debug_dir_va, debug_dir_size = struct.unpack('<II', f.read(8))
        
        if debug_dir_va == 0 or debug_dir_size == 0:
            print("No debug directory found")
            return None
            
        # Now we need to map debug_dir_va to file offset
        # Let's read section headers
        f.seek(pe_offset + 24 + size_optional_header)
        sections = []
        for _ in range(num_sections):
            sec_header = f.read(40)
            name = sec_header[0:8].rstrip(b'\x00').decode('latin1')
            misc, va, size_raw, ptr_raw, _, _, _, _, _, _ = struct.unpack('<IIIIIIHHHH', sec_header[8:])
            sections.append({
                'name': name,
                'va': va,
                'size_raw': size_raw,
                'ptr_raw': ptr_raw
            })
            
        # Find which section contains debug_dir_va
        debug_sec = None
        for sec in sections:
            if sec['va'] <= debug_dir_va < sec['va'] + sec['size_raw']:
                debug_sec = sec
                break
                
        if not debug_sec:
            # Maybe virtual size is larger than raw size, but let's assume raw size for simplicity
            print("Could not map Debug Directory VA to file offset")
            return None
            
        file_offset = debug_sec['ptr_raw'] + (debug_dir_va - debug_sec['va'])
        f.seek(file_offset)
        
        # Loop through debug directory entries
        # Each entry is 28 bytes: Characteristics(4), TimeDateStamp(4), MajorVersion(2), MinorVersion(2), Type(4), SizeOfData(4), AddressOfRawData(4), PointerToRawData(4)
        num_entries = debug_dir_size // 28
        for _ in range(num_entries):
            entry = f.read(28)
            if len(entry) < 28:
                break
            char, timestamp, major, minor, type_, size_data, addr_raw, ptr_raw = struct.unpack('<IIHHIIII', entry)
            
            if type_ == 2: # CodeView
                # Seek to CodeView data
                saved_pos = f.tell()
                f.seek(ptr_raw)
                cv_sig = f.read(4)
                if cv_sig == b'RSDS':
                    # RSDS structure: GUID (16 bytes), Age (4 bytes), PDB Path (null-terminated)
                    guid_bytes = f.read(16)
                    # GUID format: Data1 (4), Data2 (2), Data3 (2), Data4 (8)
                    d1, d2, d3, d4 = struct.unpack('<IHH8s', guid_bytes)
                    guid_str = f"{d1:08X}{d2:04X}{d3:04X}{d4.hex().upper()}"
                    age = struct.unpack('<I', f.read(4))[0]
                    pdb_path = f.read(size_data - 24).rstrip(b'\x00').decode('latin1')
                    pdb_name = os.path.basename(pdb_path)
                    
                    print(f"PDB Name: {pdb_name}")
                    print(f"GUID:     {guid_str}")
                    print(f"Age:      {age}")
                    print(f"Download: https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid_str}{age}/{pdb_name}")
                    return {
                        'name': pdb_name,
                        'guid': guid_str,
                        'age': age,
                        'url': f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid_str}{age}/{pdb_name}"
                    }
                f.seek(saved_pos)
        print("No CodeView debug entry found")
        return None

if __name__ == '__main__':
    if len(sys.argv) > 1:
        pe_path = sys.argv[1]
    else:
        pe_path = r"c:\Users\Lynden\WorkFolder\11_4.2\ntoskrnl.exe"
    get_pdb_info(pe_path)
