import os
import pefile
import urllib.request
import gzip

pe = pefile.PE("done/ntoskrnl.exe")
guid = ""
age = 0
pdb_name = ""

for d in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    if d.name == "IMAGE_DIRECTORY_ENTRY_DEBUG":
        for entry in pe.parse_debug_directory(d.VirtualAddress, d.Size):
            if hasattr(entry.entry, "PdbFileName"):
                pdb_name = entry.entry.PdbFileName.strip(b'\0').decode('utf-8')
                guid = f"{entry.entry.Signature_Data1:08X}{entry.entry.Signature_Data2:04X}{entry.entry.Signature_Data3:04X}{bytes(entry.entry.Signature_Data4).hex().upper()}"
                age = entry.entry.Age
                break
        break

if not pdb_name:
    print("Could not find PDB info in ntoskrnl.exe")
    exit()

print(f"PDB Name: {pdb_name}, GUID: {guid}, Age: {age}")

pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid}{age:x}/{pdb_name}"
print(f"Downloading PDB from: {pdb_url}")

req = urllib.request.Request(pdb_url, headers={'User-Agent': 'Microsoft-Symbol-Server/10.0.0.0'})
try:
    with urllib.request.urlopen(req) as response:
        pdb_data = response.read()
    
    # It might be compressed as a cab or uncompressed. Check signature.
    if pdb_data.startswith(b"MSCF"):
        print("PDB is CAB compressed. We'll just save it as .cab and extract it.")
        with open("ntoskrnl.cab", "wb") as f:
            f.write(pdb_data)
        os.system("expand ntoskrnl.cab ntoskrnl.pdb")
    else:
        with open("ntoskrnl.pdb", "wb") as f:
            f.write(pdb_data)
        print("Saved ntoskrnl.pdb")
except Exception as e:
    print(f"Failed to download PDB: {e}")
