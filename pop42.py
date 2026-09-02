#!/usr/bin/env python3
"""
================================================================================
POP4.2: Windows 11 SSE4.2 Requirements Patcher & ISO Builder
================================================================================
This tool allows CPUs with POPCNT but WITHOUT SSE4.2 (such as AMD Phenom II,
Athlon II, and K10 family CPUs) to install and boot Windows 11 24H2 and beyond.

How it works:
1. Windows 11 24H2 introduced hard CPU instruction requirements checked by
   ntoskrnl.exe and winload.exe via RtlDetectProcessorFeatures.
2. In the Windows kernel, a 59-entry CPUID Requirements Table in .rdata defines
   mandatory CPU features. Entry #6 corresponds to CPUID Leaf 1, Subleaf 0, ECX
   Bit 20 (SSE4.2) with Flags set to 0x0000000D (Mandatory).
3. Flipping this Flags value from 0x0D to 0x0C converts the check into an
   optional feature, bypassing the unsupported processor check without breaking
   kernel stability (since the kernel itself does not execute SSE4.2).
4. WindowsCodecs.dll is replaced with a 23H2 build to prevent crashes on
   SSE4.1 PMOVSXBW instructions during Windows Setup execution.
5. The offline registry and BCD stores are configured with DISABLE_INTEGRITY_CHECKS
   and TESTSIGNING to allow running the modified kernel with driver signature
   enforcement disabled (via the legacy F8 boot menu).
================================================================================
"""

import os
import sys
import subprocess
import shutil
import ctypes
from ctypes import wintypes
import struct
import re
import argparse
import xml.etree.ElementTree as ET
import urllib.request

try:
    import pefile
except ImportError:
    print("Error: 'pefile' module is required. Install it using: pip install pefile")
    sys.exit(1)


# ==============================================================================
# 1. ELEVATION & PERMISSION MANAGEMENT
# ==============================================================================

def is_windows8_or_newer():
    if sys.platform == "win32":
        ver = sys.getwindowsversion()
        return (ver.major, ver.minor) >= (6, 2)
    return False

if not is_windows8_or_newer():
    print("Error: Windows 8 or newer is required.")
    sys.exit(1)

def is_admin() -> bool:
    """
    Checks if the current process is running with elevated Administrator privileges.
    Returns True if elevated, False otherwise.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def require_admin():
    """
    Ensures the script is running with elevated Administrator privileges.
    If running as standard user, triggers a UAC prompt to re-launch itself elevated.
    """
    if not is_admin():
        print("[*] Administrator privileges required for DISM and registry operations.")
        print("[*] Requesting UAC elevation...")
        params = " ".join([f'"{arg}"' if " " in arg else arg for arg in sys.argv])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        if ret > 32:
            # Successfully launched elevated child process; terminate standard instance
            sys.exit(0)
        else:
            print("[-] Error: UAC elevation was denied or failed. Please run this script as Administrator.")
            sys.exit(1)


def take_ownership_and_grant(file_path: str):
    """
    Takes ownership of protected Windows system files (TrustedInstaller) and grants
    Full Control permissions to the Administrators group.
    
    Uses the locale-independent SID '*S-1-5-32-544:F' (BUILTIN\\Administrators) to ensure
    compatibility across non-English Windows installations (e.g. German, French, Russian).
    """
    if os.path.exists(file_path):
        # /a grants ownership to Administrators group rather than the current user
        subprocess.run(["takeown", "/f", file_path, "/a"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # *S-1-5-32-544 is the universal SID for Administrators
        subprocess.run(["icacls", file_path, "/grant", "*S-1-5-32-544:F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def clear_readonly(path: str):
    """Recursively removes the Read-Only attribute (FILE_ATTRIBUTE_READONLY) from files and directories."""
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            for d in dirs:
                full_d = os.path.join(root, d)
                try:
                    os.chmod(full_d, 0o777)
                    ctypes.windll.kernel32.SetFileAttributesW(full_d, 0x80) # FILE_ATTRIBUTE_NORMAL
                except Exception:
                    pass
            for f in files:
                full_f = os.path.join(root, f)
                try:
                    os.chmod(full_f, 0o777)
                    ctypes.windll.kernel32.SetFileAttributesW(full_f, 0x80)
                except Exception:
                    pass
    elif os.path.exists(path):
        try:
            os.chmod(path, 0o777)
            ctypes.windll.kernel32.SetFileAttributesW(path, 0x80)
        except Exception:
            pass


def safe_replace_file(src: str, dst: str):
    """Safely moves src to dst, clearing read-only attributes and overwriting any existing destination file."""
    clear_readonly(dst)
    if os.path.exists(dst):
        try:
            os.remove(dst)
        except Exception:
            pass
    shutil.move(src, dst)
    clear_readonly(dst)


# ==============================================================================
# 2. PE CHECKSUM & PATCHER REGISTRY
# ==============================================================================

# Global registry mapping patcher routine names (from badblobs.xml) to Python functions
PATCHER_REGISTRY = {}

def register_patcher(name: str):
    """
    Decorator to register a custom patch handler function.
    Enables plug-and-play extensibility for custom XML profiles and future patch routines
    (e.g., Windows 10 without NX, Windows 11 without CMPXCHG16B).
    """
    def decorator(fn):
        PATCHER_REGISTRY[name] = fn
        return fn
    return decorator


def fix_pe_checksum(file_path: str) -> bool:
    """
    Calculates and updates the PE OptionalHeader.CheckSum using Microsoft imagehlp.dll
    (MapFileAndCheckSumW). Windows kernel-mode binaries (ntoskrnl.exe, drivers, hal.dll)
    require a valid PE CheckSum; otherwise, the Windows Boot Manager (winload.exe)
    will refuse to load the image and trigger a 0xc0000221 STATUS_IMAGE_CHECKSUM_MISMATCH.
    """
    try:
        # Load imagehlp.dll from system32
        imagehlp = ctypes.windll.imagehlp
        imagehlp.MapFileAndCheckSumW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong)
        ]
        imagehlp.MapFileAndCheckSumW.restype = ctypes.c_ulong
        
        orig_sum = ctypes.c_ulong(0)
        new_sum = ctypes.c_ulong(0)
        
        # CHECKSUM_SUCCESS is 0
        status = imagehlp.MapFileAndCheckSumW(file_path, ctypes.byref(orig_sum), ctypes.byref(new_sum))
        
        if status == 0:
            # Write calculated checksum directly to OptionalHeader.CheckSum in PE header
            with open(file_path, "r+b") as f:
                f.seek(0x3C) # e_lfanew offset in DOS header
                pe_offset = int.from_bytes(f.read(4), "little")
                f.seek(pe_offset)
                sig = f.read(4)
                if sig == b'PE\x00\x00':
                    # OptionalHeader.CheckSum is at offset 64 (0x40) from start of OptionalHeader
                    # PE signature (4) + FileHeader (20) + 64 = pe_offset + 88
                    checksum_offset = pe_offset + 24 + 64
                    f.seek(checksum_offset)
                    f.write(new_sum.value.to_bytes(4, "little"))
                    return True
    except Exception as e:
        print(f"[-] imagehlp.dll checksum calculation failed ({e}). Attempting pefile fallback...")

    # Fallback using pefile library if imagehlp is unavailable
    try:
        pe = pefile.PE(file_path)
        pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()
        pe.write(file_path)
        pe.close()
        return True
    except Exception as e:
        print(f"[-] Failed to update PE CheckSum: {e}")
        return False


def patch_kernel_bytes(data: bytearray, patch_cpuid: bool = True, patch_kiset: bool = False, enable_debug: bool = False) -> tuple:
    """
    Applies the core POP4.2 kernel modifications to a raw ntoskrnl.exe bytearray:
    
    1. CPUID Requirements Table Patch (SSE4.2 Flags 0x0D -> 0x0C):
       - Leaf: 1, Subleaf: 0, Mask: 0x00100000 (Bit 20: SSE4.2), Register: 2 (ECX), Flags: 0x0000000D
       - Patching Flags from 0x0D (Mandatory) to 0x0C (Optional) tells RtlDetectProcessorFeatures
         to continue booting even if CPUID does not report SSE4.2 support.
    
    2. KiSetFeatureBits Conditional Jumps Patch (Optional, disabled by default):
       - NOPs out hardcoded conditional branches in KiSetFeatureBits that guard processor feature bits.
       - Disabled by default since the CPUID table patch is sufficient for modern 24H2 builds.
    
    3. KeBugCheckEx Debug Loop Patch (Optional, disabled by default):
       - Overwrites the first 2 bytes of KeBugCheckEx with 'EB FE' (jmp $, infinite loop).
       - Allows attaching QEMU GDB debugger (via qemu_gdb_debugger.py) when a BugCheck 0x5D occurs
         to inspect live guest registers, walk the call stack, and read the failed requirement entry.
    """
    report = {
        "cpuid_patched": False,
        "kiset_patched": False,
        "debug_loop_patched": False
    }

    # 1. CPUID Requirements Table Patch (Index 6: SSE4.2 Flags 0x0D -> 0x0C)
    if patch_cpuid:
        # 20-byte signature: Leaf=1, Subleaf=0, Mask=0x00100000, Reg=2 (ECX), Flags=0x0D
        req_sig = bytes.fromhex("010000000000000000001000020000000D000000")
        req_idx = data.find(req_sig)
        if req_idx != -1:
            # Overwrite Flags byte at offset 16 from 0x0D to 0x0C
            data[req_idx + 16] = 0x0C
            report["cpuid_patched"] = True
            print(f"[+] Patched CPUID requirements table entry at offset 0x{req_idx:X} (Flags: 0x0D -> 0x0C).")
        else:
            print("[-] Warning: Mandatory SSE4.2 CPUID requirement table entry (0x0D) not found in binary.")

    # 2. KiSetFeatureBits CPU branch jump checks (Disabled by default)
    if patch_kiset:
        # Signature matching the 4 primary branch comparisons in KiSetFeatureBits
        pattern = re.compile(
            b'\x3B\xC1' +               # cmp eax, ecx
            b'\x0F\x85.{4}' +           # jne rel32
            b'\x41\x0F\xBA\xE6\x0B' +   # bt r14d, 0Bh
            b'\x0F\x83.{4}' +           # jnb/jae rel32
            b'\x41\x0F\xBA\xE6\x14' +   # bt r14d, 14h
            b'\x0F\x83.{4}' +           # jnb/jae rel32
            b'\x41\x0F\xBA\xE5\x0D' +   # bt r13d, 0Dh
            b'\x0F\x83.{4}',            # jnb/jae rel32
            re.DOTALL
        )
        matches = list(pattern.finditer(data))
        if matches:
            start = matches[0].start()
            # NOP out the 4 main 6-byte jumps
            data[start + 2 : start + 8] = b'\x90' * 6
            data[start + 13 : start + 19] = b'\x90' * 6
            data[start + 24 : start + 30] = b'\x90' * 6
            data[start + 35 : start + 41] = b'\x90' * 6

            # NOP out 5th and 6th jumps if they match standard offsets
            if data[start + 50] == 0x0F and data[start + 51] == 0x84:
                data[start + 50 : start + 56] = b'\x90' * 6
            if data[start + 63] == 0x0F and data[start + 64] == 0x85:
                data[start + 63 : start + 69] = b'\x90' * 6
            report["kiset_patched"] = True
            print(f"[+] Patched KiSetFeatureBits conditional jumps at offset 0x{start:X}.")
        else:
            print("[-] Warning: KiSetFeatureBits CPU check signature not found.")

    # 3. Optional KeBugCheckEx infinite loop patch (EB FE) for QEMU GDB debugging
    if enable_debug:
        try:
            pe = pefile.PE(data=bytes(data))
            kbc_rva = None
            # Resolve exported KeBugCheckEx function dynamically from Export Directory
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name and exp.name.decode('latin1', errors='ignore') == 'KeBugCheckEx':
                        kbc_rva = exp.address
                        break
            if not kbc_rva:
                kbc_rva = 0x4F6880 # Standard RVA fallback
                
            kbc_offset = pe.get_offset_from_rva(kbc_rva)
            pe.close()
            # Write JMP $ (EB FE) at the start of KeBugCheckEx
            data[kbc_offset : kbc_offset + 2] = b'\xEB\xFE'
            report["debug_loop_patched"] = True
            print(f"[+] Patched KeBugCheckEx at offset 0x{kbc_offset:X} (RVA 0x{kbc_rva:X}) to EB FE infinite loop.")
        except Exception as e:
            print(f"[-] Warning: Failed to patch KeBugCheckEx debug loop: {e}")

    return data, report


@register_patcher("kernel_sse42")
def patch_kernel_file(input_path: str, output_path: str = None, patch_cpuid: bool = True, patch_kiset: bool = False, enable_debug: bool = False) -> bool:
    """
    Registered patch routine for Windows Kernel ('kernel_sse42').
    Reads the input binary, applies byte patches, writes output, and recalculates PE checksum.
    """
    if not os.path.exists(input_path):
        print(f"[-] Error: Kernel file not found: {input_path}")
        return False

    if output_path is None:
        output_path = input_path

    print(f"[*] Reading kernel binary: {input_path}")
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    modified_data, report = patch_kernel_bytes(data, patch_cpuid, patch_kiset, enable_debug)

    with open(output_path, "wb") as f:
        f.write(modified_data)

    print(f"[+] Written patched binary to: {output_path}")
    if fix_pe_checksum(output_path):
        print("[+] Recalculated and updated PE Checksum successfully.")
    return True


# ==============================================================================
# 3. BADBLOBS DATABASE & VALIDATION
# ==============================================================================

class BlobItem:
    """Represents a single binary item tracked in badblobs.xml."""
    def __init__(self, blob_id: str, action: str, target: str, description: str = "", filename: str = None, patcher: str = None, enabled: bool = True, options: dict = None):
        self.id = blob_id
        self.action = action # 'patch', 'replace', 'ignore'
        self.target = target # Relative target path inside mounted WIM (e.g. Windows/System32/ntoskrnl.exe)
        self.description = description
        self.filename = filename # Filename inside blobs/ directory (for action="replace")
        self.patcher = patcher # Registered patch handler name (for action="patch")
        self.enabled = enabled
        self.options = options or {}


class BlobDatabase:
    """Loads and validates badblobs.xml configuration."""
    def __init__(self, xml_path: str, blobs_dir: str):
        self.xml_path = xml_path
        self.blobs_dir = blobs_dir
        self.blobs: dict[str, BlobItem] = {}
        self.load()

    def load(self):
        """Parses the badblobs.xml database file."""
        if not os.path.exists(self.xml_path):
            raise FileNotFoundError(f"badblobs configuration not found at: {self.xml_path}")

        tree = ET.parse(self.xml_path)
        root = tree.getroot()

        for blob_elem in root.findall("Blob"):
            b_id = blob_elem.get("id")
            action = blob_elem.get("action", "").lower()
            enabled = blob_elem.get("enabled", "true").lower() == "true"
            patcher = blob_elem.get("patcher")
            filename = blob_elem.get("file")

            target_elem = blob_elem.find("Target")
            target = target_elem.text.strip().replace("\\", "/") if target_elem is not None and target_elem.text else ""

            desc_elem = blob_elem.find("Description")
            desc = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else ""

            # Parse optional key-value parameters for the patcher
            options = {}
            opts_elem = blob_elem.find("Options")
            if opts_elem is not None:
                for opt in opts_elem.findall("Option"):
                    opt_name = opt.get("name")
                    opt_val = opt.get("value")
                    if opt_name:
                        options[opt_name] = opt_val.lower() == "true" if opt_val in ("true", "false") else opt_val

            blob = BlobItem(
                blob_id=b_id,
                action=action,
                target=target,
                description=desc,
                filename=filename,
                patcher=patcher,
                enabled=enabled,
                options=options
            )
            self.blobs[b_id] = blob

    def validate(self, allow_missing: bool = False) -> bool:
        """
        Enforces fail-fast integrity checking:
        - action="replace": Verifies the replacement file exists inside the blobs/ directory.
        - action="patch": Verifies the routine is registered in PATCHER_REGISTRY.
        - action="ignore": Explicitly skipped.
        
        If validation fails, halts execution immediately unless allow_missing=True.
        """
        errors = []
        for b_id, blob in self.blobs.items():
            if not blob.enabled:
                continue

            if blob.action == "replace":
                if not blob.filename:
                    errors.append(f"Blob '{b_id}' action is 'replace' but no 'file' attribute is specified.")
                else:
                    blob_file_path = os.path.join(self.blobs_dir, blob.filename)
                    if not os.path.exists(blob_file_path):
                        errors.append(f"Missing replacement file '{blob.filename}' for blob '{b_id}' in '{self.blobs_dir}'.")
            elif blob.action == "patch":
                if blob.patcher not in PATCHER_REGISTRY:
                    errors.append(f"Blob '{b_id}' specifies unknown patch routine '{blob.patcher}'. Registered patchers: {list(PATCHER_REGISTRY.keys())}")
            elif blob.action == "ignore":
                pass
            else:
                errors.append(f"Blob '{b_id}' has invalid action '{blob.action}'. Must be 'patch', 'replace', or 'ignore'.")

        if errors:
            print("\n[!] BADBLOBS VALIDATION FAILED:")
            for err in errors:
                print(f"  [-] {err}")
            if allow_missing:
                print("[!] Warning: --allow-missing-blobs specified. Proceeding with warnings.\n")
                return True
            return False
        return True


# ==============================================================================
# 4. DISM & WIM CONTEXT MANAGERS
# ==============================================================================

class WimMountSession:
    """
    Robust context manager for DISM WIM operations.
    Guarantees that mounted images and offline registry hives are safely cleaned up
    (unmounted with /Discard or /Commit and registry unhooked), even upon exceptions,
    keyboard interrupts (Ctrl+C), or fatal errors.
    """

    def __init__(self, wim_path: str, index: int, mount_dir: str):
        self.wim_path = wim_path
        self.index = index
        self.mount_dir = mount_dir
        self.mounted = False
        self.committed = False
        self.reg_loaded = False

    def __enter__(self):
        os.makedirs(self.mount_dir, exist_ok=True)
        print(f"[*] Mounting {os.path.basename(self.wim_path)} (Index {self.index}) -> {self.mount_dir}...")
        cmd = ["dism.exe", "/Mount-Image", f"/ImageFile:{self.wim_path}", f"/Index:{self.index}", f"/MountDir:{self.mount_dir}"]
        res = subprocess.run(cmd)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to mount WIM: {self.wim_path} (Index {self.index})")
        self.mounted = True
        return self

    def apply_blobs(self, db: BlobDatabase, blobs_dir: str, patch_cpuid: bool = True, patch_kiset: bool = False, debug_loop: bool = False):
        """Applies all enabled blobs to the mounted WIM filesystem."""
        for b_id, blob in db.blobs.items():
            if not blob.enabled:
                continue

            target_full_path = os.path.join(self.mount_dir, blob.target.replace("/", "\\"))

            if blob.action == "patch":
                if blob.patcher in PATCHER_REGISTRY:
                    if os.path.exists(target_full_path):
                        print(f"  [+] Executing patch handler '{blob.patcher}' on '{b_id}' at {blob.target}...")
                        take_ownership_and_grant(target_full_path)
                        handler = PATCHER_REGISTRY[blob.patcher]
                        
                        if blob.patcher == "kernel_sse42":
                            opt_cpuid = patch_cpuid and blob.options.get("patch_cpuid", True)
                            opt_kiset = patch_kiset or blob.options.get("patch_kiset", False)
                            opt_debug = debug_loop or blob.options.get("debug_loop", False)
                            handler(target_full_path, target_full_path, opt_cpuid, opt_kiset, opt_debug)
                        else:
                            handler(target_full_path, target_full_path)
                    else:
                        print(f"  [-] Target '{blob.target}' not found in this image index. Skipping.")
                else:
                    print(f"  [-] Error: Unregistered patcher '{blob.patcher}' for blob '{b_id}'.")

            elif blob.action == "replace":
                replacement_path = os.path.join(blobs_dir, blob.filename)
                if not os.path.exists(replacement_path):
                    print(f"  [-] Warning: Replacement blob '{blob.filename}' missing. Skipping '{b_id}'.")
                    continue

                if os.path.exists(target_full_path):
                    print(f"  [+] Replacing blob '{b_id}' with {blob.filename} -> {blob.target}...")
                    take_ownership_and_grant(target_full_path)
                    shutil.copy2(replacement_path, target_full_path)
                else:
                    print(f"  [-] Target '{blob.target}' does not exist in this image index. Skipping.")

    def modify_offline_registry(self):
        """
        Loads the offline SYSTEM hive (Windows\\System32\\config\\SYSTEM) into HKLM\\POP42_OfflineSystem
        and configures SystemStartOptions with 'DISABLE_INTEGRITY_CHECKS TESTSIGNING' to allow
        the patched kernel to run with driver signature checks disabled.
        """
        system_hive = os.path.join(self.mount_dir, "Windows", "System32", "config", "SYSTEM")
        if not os.path.exists(system_hive):
            return

        print("  [+] Configuring offline registry (DISABLE_INTEGRITY_CHECKS TESTSIGNING)...")
        # Ensure any leftover hive from a prior interrupted session is unloaded
        subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        res = subprocess.run(["reg.exe", "load", "HKLM\\POP42_OfflineSystem", system_hive], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            self.reg_loaded = True
            try:
                # Set SystemStartOptions in ControlSet001\\Control
                reg_cmd = [
                    "reg.exe", "add", "HKLM\\POP42_OfflineSystem\\ControlSet001\\Control",
                    "/v", "SystemStartOptions", "/t", "REG_SZ", "/d", "DISABLE_INTEGRITY_CHECKS TESTSIGNING", "/f"
                ]
                subprocess.run(reg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            finally:
                # Unload hive to release file locks on the mount folder
                subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.reg_loaded = False

    def commit(self):
        """Commits modified changes back to the WIM image and dismounts."""
        if self.mounted and not self.committed:
            print(f"[*] Committing and dismounting {os.path.basename(self.wim_path)} (Index {self.index})...")
            cmd = ["dism.exe", "/Unmount-Image", f"/MountDir:{self.mount_dir}", "/Commit"]
            res = subprocess.run(cmd)
            if res.returncode != 0:
                raise RuntimeError("Failed to commit and unmount WIM image.")
            self.committed = True
            self.mounted = False

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Guarantee offline registry hive is unloaded
        if self.reg_loaded:
            subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.reg_loaded = False

        # If an error occurred or commit() was not called, safely discard changes to prevent mount poisoning
        if self.mounted:
            print(f"[!] Exception or abort detected. Discarding changes for {self.mount_dir}...")
            subprocess.run(["dism.exe", "/Unmount-Image", f"/MountDir:{self.mount_dir}", "/Discard"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.mounted = False


# ==============================================================================
# 5. ISO BUILD PIPELINE
# ==============================================================================

def get_oscdimg_version(bin_path: str) -> float:
    """
    Returns the oscdimg version as a float (e.g. 2.56, 2.55) or 0.0 if cannot be determined.
    v2.55 or higher is strictly required for El Torito multi-platform UEFI + BIOS bootdata.
    """
    if not bin_path or not os.path.exists(bin_path):
        return 0.0
    try:
        res = subprocess.run([bin_path], capture_output=True, text=True)
        m = re.search(r"(?i)OSCDIMG\s+([0-9]+\.[0-9]+)", res.stdout)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return 0.0


def download_adk_oscdimg(target_dir: str) -> str:
    """
    Downloads the official Microsoft ADK oscdimg cabinet (~74 KB) directly from
    Microsoft CDN and extracts oscdimg.exe (x64 v2.56) using Windows built-in expand.exe.
    
    This eliminates the need to bundle third-party copyrighted binaries or install
    the full 5 GB Windows ADK suite.
    """
    os.makedirs(target_dir, exist_ok=True)
    out_exe = os.path.join(target_dir, "oscdimg.exe")

    # Check if already present and valid
    if os.path.exists(out_exe) and get_oscdimg_version(out_exe) >= 2.55:
        return out_exe

    cab_url = "http://download.microsoft.com/download/2/d/9/2d9c8902-3fcd-48a6-a22a-432b08bed61e/ADK/Installers/bbf55224a0290f00676ddc410f004498.cab"
    temp_cab = os.path.join(target_dir, "oscdimg_adk.cab")
    temp_extract = os.path.join(target_dir, "temp_expand")

    print("[*] Compatible oscdimg (v2.55+) not found locally.")
    print("[*] Downloading official Microsoft ADK Deployment payload (~74 KB) from Microsoft CDN...")

    req = urllib.request.Request(cab_url, headers={"User-Agent": "Burn"})
    try:
        with urllib.request.urlopen(req) as resp, open(temp_cab, "wb") as f:
            f.write(resp.read())
        print("[+] Download complete. Extracting oscdimg.exe using expand.exe...")

        os.makedirs(temp_extract, exist_ok=True)
        subprocess.run(["expand.exe", temp_cab, "-F:*", temp_extract], check=True, stdout=subprocess.DEVNULL)

        # Raw payload filename inside Microsoft ADK cabinet
        raw_payload = os.path.join(temp_extract, "fild40c79d789d460e48dc1cbd485d6fc2e")
        if os.path.exists(raw_payload):
            safe_replace_file(raw_payload, out_exe)
            ver = get_oscdimg_version(out_exe)
            print(f"[+] Successfully extracted and configured: {out_exe} (v{ver})")
            return out_exe
        else:
            raise RuntimeError("Expected payload binary not found in extracted cabinet.")
    except Exception as e:
        print(f"[-] Failed to download/extract ADK oscdimg from Microsoft CDN: {e}")
        return None
    finally:
        # Clean up temporary cabinet and extraction files
        if os.path.exists(temp_cab):
            try: os.remove(temp_cab)
            except Exception: pass
        if os.path.exists(temp_extract):
            shutil.rmtree(temp_extract, ignore_errors=True)


def find_oscdimg(custom_path: str = None) -> str:
    """
    Locates the Microsoft CD/DVD mastering utility (oscdimg.exe).
    
    1. Validates custom_path if specified (must be >= 2.55).
    2. Checks local ./tools/oscdimg.exe directory.
    3. Searches Windows ADK installations, MiniTool, and system PATH.
    4. If found version is < 2.55, warns the user that El Torito dual-boot is unsupported.
    5. If not found or too old, automatically downloads the 74 KB ADK payload from Microsoft.
    """
    script_dir = os.path.abspath(os.path.dirname(__file__))
    tools_dir = os.path.join(script_dir, "tools")
    local_tool = os.path.join(tools_dir, "oscdimg.exe")

    # 1. User-supplied custom path
    if custom_path and os.path.exists(custom_path):
        ver = get_oscdimg_version(custom_path)
        if ver >= 2.55:
            return custom_path
        print(f"[-] Warning: Custom oscdimg at '{custom_path}' is version {ver} (< 2.55).")

    # 2. Local tools directory
    if os.path.exists(local_tool):
        ver = get_oscdimg_version(local_tool)
        if ver >= 2.55:
            return local_tool

    # 3. Standard system locations
    candidates = [
        r"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe",
        r"C:\Program Files\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe",
        r"C:\Program Files (x86)\Windows Kits\11\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg.exe",
        r"C:\Program Files\MiniTool Partition Wizard 13\oscdimg.exe",
        r"C:\Program Files\MiniTool Partition Wizard 12\oscdimg.exe"
    ]
    path_which = shutil.which("oscdimg.exe")
    if path_which and path_which not in candidates:
        candidates.append(path_which)

    for p in candidates:
        if os.path.exists(p):
            ver = get_oscdimg_version(p)
            if ver >= 2.55:
                return p
            else:
                print(f"[-] Notice: Found oscdimg at '{p}' but version {ver} is too old (< 2.55). UEFI dual-boot requires v2.55+.")

    # 4. Automatic on-demand download from Microsoft CDN
    return download_adk_oscdimg(tools_dir)


def modify_bcd_stores(iso_files_dir: str):
    """
    Configures both BIOS (boot\\bcd) and UEFI (efi\\microsoft\\boot\\bcd) BCD stores on the ISO:
    1. Disables integrity checks and enables testsigning for the boot loader ({default}).
    2. Enables the legacy F8 boot menu (bootmenupolicy legacy) so users can select
       'Disable driver signature enforcement' at boot time.
    """
    bcd_paths = [
        os.path.join(iso_files_dir, "boot", "bcd"),
        os.path.join(iso_files_dir, "efi", "microsoft", "boot", "bcd")
    ]
    for bcd in bcd_paths:
        if os.path.exists(bcd):
            print(f"[+] Patching BCD store: {bcd}")
            try:
                # Clear Read-Only file attribute copied from the source media
                os.chmod(bcd, 0o777)
            except Exception:
                pass

            commands = [
                ["bcdedit.exe", "/store", bcd, "/set", "{default}", "nointegritychecks", "Yes"],
                ["bcdedit.exe", "/store", bcd, "/set", "{default}", "testsigning", "Yes"],
                ["bcdedit.exe", "/store", bcd, "/set", "{default}", "recoveryenabled", "Yes"],
                ["bcdedit.exe", "/store", bcd, "/set", "{default}", "advancedoptions", "Yes"],
                ["bcdedit.exe", "/store", bcd, "/set", "{default}", "bootmenupolicy", "legacy"]
            ]
            for c in commands:
                subprocess.run(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def build_iso(
    input_iso: str,
    output_iso: str,
    work_dir: str,
    db: BlobDatabase,
    blobs_dir: str,
    selected_index: int = None,
    boot_only: bool = False,
    patch_cpuid: bool = True,
    patch_kiset: bool = False,
    debug_loop: bool = False,
    oscdimg_path: str = None
):
    """
    Orchestrates the complete automated ISO build pipeline:
    1. Elevates process privileges if needed.
    2. Mounts or extracts the source Windows 11 ISO.
    3. Patches boot.wim (Index 2: Setup environment) with badblobs and offline registry tweaks.
    4. Patches install.wim / install.esd (Main OS + nested winre.wim recovery environment).
    5. Modifies ISO BCD stores for legacy F8 menu and testsigning.
    6. Rebuilds dual-boot (UEFI + BIOS) bootable ISO using oscdimg.
    """
    require_admin()

    oscdimg_bin = find_oscdimg(oscdimg_path)
    if not oscdimg_bin:
        print("[-] Error: 'oscdimg.exe' not found! Please install the Windows ADK or specify --oscdimg-path.")
        sys.exit(1)

    print(f"[+] Using oscdimg: {oscdimg_bin}")

    iso_files_dir = os.path.join(work_dir, "iso_files")
    mount_dir = os.path.join(work_dir, "mount")
    re_mount_dir = os.path.join(work_dir, "mountRE")
    local_boot_wim = os.path.join(work_dir, "boot.wim")
    local_install_wim = os.path.join(work_dir, "install.wim")

    os.makedirs(work_dir, exist_ok=True)
    os.makedirs(mount_dir, exist_ok=True)
    os.makedirs(re_mount_dir, exist_ok=True)

    # Clean up any lingering mountpoints and registry handles from previous runs
    subprocess.run(["dism.exe", "/Cleanup-Mountpoints"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["reg.exe", "unload", "HKLM\\POP42_OfflineSystem"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Extract or copy source ISO media
    sources_dir = os.path.join(iso_files_dir, "sources")
    has_install = os.path.exists(os.path.join(sources_dir, "install.wim")) or os.path.exists(os.path.join(sources_dir, "install.esd"))

    if not has_install:
        if input_iso.endswith(".iso") and os.path.exists(input_iso):
            print(f"[*] Mounting source ISO: {input_iso}...")
            ps_cmd = f"(Mount-DiskImage -ImagePath '{os.path.abspath(input_iso)}' -PassThru | Get-Volume).DriveLetter"
            res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
            drive_letter = res.stdout.strip()
            if not drive_letter or len(drive_letter) != 1:
                print(f"[-] Error: Failed to mount source ISO: {input_iso}")
                sys.exit(1)
            
            source_drive = f"{drive_letter}:\\"
            print(f"[+] ISO mounted at drive {source_drive}. Copying files with Robocopy...")
            os.makedirs(iso_files_dir, exist_ok=True)
            # Multi-threaded copy of ISO filesystem
            subprocess.run(["robocopy", source_drive, iso_files_dir, "/E", "/MT:8", "/R:1", "/W:1"], stdout=subprocess.DEVNULL)
            
            # Dismount source ISO image
            subprocess.run(["powershell", "-NoProfile", "-Command", f"Dismount-DiskImage -ImagePath '{os.path.abspath(input_iso)}'"], stdout=subprocess.DEVNULL)
            
            # Clear read-only attributes inherited from ISO filesystem
            clear_readonly(iso_files_dir)
        elif os.path.isdir(input_iso):
            print(f"[*] Copying ISO directory structure from: {input_iso}...")
            os.makedirs(iso_files_dir, exist_ok=True)
            subprocess.run(["robocopy", input_iso, iso_files_dir, "/E", "/MT:8", "/R:1", "/W:1"], stdout=subprocess.DEVNULL)
            clear_readonly(iso_files_dir)
        else:
            print(f"[-] Error: Invalid input ISO path: {input_iso}")
            sys.exit(1)

    # -------------------------------------------------------------------------
    # PART 1: PATCH BOOT.WIM (Index 2 for Windows Setup Wizard)
    # -------------------------------------------------------------------------
    src_boot_wim = os.path.join(iso_files_dir, "sources", "boot.wim")
    if not os.path.exists(src_boot_wim):
        raise FileNotFoundError(f"boot.wim not found in {src_boot_wim}")

    print("\n" + "="*70)
    print("STEP 1: Patching boot.wim (Setup Environment)")
    print("="*70)
    clear_readonly(src_boot_wim)
    shutil.copy2(src_boot_wim, local_boot_wim)
    clear_readonly(local_boot_wim)

    with WimMountSession(local_boot_wim, index=2, mount_dir=mount_dir) as session:
        session.apply_blobs(db, blobs_dir, patch_cpuid, patch_kiset, debug_loop)
        session.modify_offline_registry()
        session.commit()

    safe_replace_file(local_boot_wim, src_boot_wim)
    print("[+] boot.wim patched successfully.")

    # -------------------------------------------------------------------------
    # PART 2: PATCH INSTALL IMAGE (install.wim / install.esd)
    # -------------------------------------------------------------------------
    if not boot_only:
        print("\n" + "="*70)
        print("STEP 2: Patching Main OS Image (install.wim / install.esd)")
        print("="*70)
        
        is_esd = False
        install_img = os.path.join(iso_files_dir, "sources", "install.wim")
        if not os.path.exists(install_img):
            install_img = os.path.join(iso_files_dir, "sources", "install.esd")
            is_esd = True

        if not os.path.exists(install_img):
            raise FileNotFoundError("Could not find install.wim or install.esd in sources!")

        clear_readonly(install_img)

        # Query all image indexes using DISM
        info_res = subprocess.run(["dism.exe", "/Get-ImageInfo", f"/ImageFile:{install_img}"], capture_output=True, text=True)
        found_indexes = [int(m.group(1)) for m in re.finditer(r"(?i)Index\s*:\s*(\d+)", info_res.stdout)]

        if not found_indexes:
            raise RuntimeError(f"No indexes found in {install_img}")

        target_indexes = [selected_index] if selected_index else found_indexes
        print(f"[+] Target OS Indexes to patch: {target_indexes}")

        if is_esd:
            print("[*] Detected read-only install.esd. Converting selected indexes to local install.wim...")
            if os.path.exists(local_install_wim):
                clear_readonly(local_install_wim)
                os.remove(local_install_wim)
            for idx in target_indexes:
                print(f"  [+] Exporting Index {idx}...")
                subprocess.run(["dism.exe", "/Export-Image", f"/SourceImageFile:{install_img}", f"/SourceIndex:{idx}", f"/DestinationImageFile:{local_install_wim}", "/Compress:max"], check=True)
            wim_indexes = list(range(1, len(target_indexes) + 1))
        else:
            shutil.copy2(install_img, local_install_wim)
            clear_readonly(local_install_wim)
            wim_indexes = target_indexes

        # Mount and patch each selected OS index
        for idx in wim_indexes:
            print(f"\n[*] Mounting and patching install.wim Index {idx}...")
            with WimMountSession(local_install_wim, index=idx, mount_dir=mount_dir) as session:
                session.apply_blobs(db, blobs_dir, patch_cpuid, patch_kiset, debug_loop)
                session.modify_offline_registry()

                # Patch nested WinRE (Windows Recovery Environment) inside the OS image
                winre_path = os.path.join(mount_dir, "Windows", "System32", "Recovery", "winre.wim")
                if os.path.exists(winre_path):
                    take_ownership_and_grant(winre_path)
                    clear_readonly(winre_path)
                    print(f"  [*] Patching nested Recovery Image (winre.wim)...")
                    with WimMountSession(winre_path, index=1, mount_dir=re_mount_dir) as re_session:
                        re_session.apply_blobs(db, blobs_dir, patch_cpuid, patch_kiset, debug_loop)
                        re_session.modify_offline_registry()
                        re_session.commit()

                session.commit()

        # Replace the original install image in the ISO folder
        if is_esd:
            clear_readonly(install_img)
            os.remove(install_img) # Remove original install.esd
        dest_install_wim = os.path.join(iso_files_dir, "sources", "install.wim")
        safe_replace_file(local_install_wim, dest_install_wim)
        print("[+] Install image patch complete.")

    # -------------------------------------------------------------------------
    # PART 3: BCD STORES CONFIGURATION
    # -------------------------------------------------------------------------
    print("\n" + "="*70)
    print("STEP 3: Modifying ISO BCD Stores")
    print("="*70)
    modify_bcd_stores(iso_files_dir)

    # -------------------------------------------------------------------------
    # PART 4: REBUILD BOOTABLE ISO
    # -------------------------------------------------------------------------
    print("\n" + "="*70)
    print("STEP 4: Rebuilding Dual-Boot (UEFI + BIOS) ISO")
    print("="*70)
    etfsboot = os.path.join(iso_files_dir, "boot", "etfsboot.com")
    efisys = os.path.join(iso_files_dir, "efi", "microsoft", "boot", "efisys.bin")

    # oscdimg arguments for El Torito multi-boot specification:
    # -bootdata:2#p0 (BIOS boot via etfsboot.com) #pEF (UEFI boot via efisys.bin)
    # -u2 -udfver102 (UDF 1.02 filesystem standard for Windows installation media)
    oscdimg_args = [
        oscdimg_bin,
        "-m",
        "-o",
        "-u2",
        "-udfver102",
        f"-bootdata:2#p0,e,b{etfsboot}#pEF,e,b{efisys}",
        iso_files_dir,
        output_iso
    ]

    print(f"[*] Running oscdimg to generate: {output_iso}...")
    subprocess.run(oscdimg_args, check=True)

    # Clean up temporary folders
    shutil.rmtree(mount_dir, ignore_errors=True)
    shutil.rmtree(re_mount_dir, ignore_errors=True)

    print("\n" + "="*70)
    print(f"SUCCESS: Patched ISO built successfully!")
    print(f"Output File: {os.path.abspath(output_iso)}")
    print("="*70)


# ==============================================================================
# 6. CLI INTERFACE & ENTRY POINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="POP4.2: Windows 11 SSE4.2 Requirements Patcher & ISO Builder",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Patch a standalone kernel file:
  python pop42.py patch ntoskrnl -i C:\\path\\to\\ntoskrnl.exe

  # 2. Build a full patched Windows 11 ISO:
  python pop42.py build -i Win11_24H2.iso -o Win11_Patched.iso

  # 3. Build with custom XML profile and options:
  python pop42.py build -i Win11_24H2.iso -c badblobs.xml --debug-loop --allow-missing-blobs
        """
    )

    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    # Mode 1: PATCH (Standalone binary patcher)
    patch_parser = subparsers.add_parser("patch", help="Directly patch a binary file by shorthand or path")
    patch_parser.add_argument("shorthand", nargs="?", default="ntoskrnl", help="Blob shorthand from badblobs.xml (default: ntoskrnl)")
    patch_parser.add_argument("-i", "--input", required=True, help="Path to input binary (e.g. ntoskrnl.exe)")
    patch_parser.add_argument("-o", "--output", default=None, help="Path to output patched binary (default: overwrite input)")
    patch_parser.add_argument("--no-cpuid", action="store_true", help="Skip CPUID requirements table patch")
    patch_parser.add_argument("--kiset", action="store_true", help="Enable KiSetFeatureBits conditional jump NOPs (disabled by default)")
    patch_parser.add_argument("--debug-loop", action="store_true", help="Enable KeBugCheckEx infinite loop (EB FE) for QEMU GDB debugging")

    # Mode 2: BUILD (Full ISO pipeline)
    build_parser = subparsers.add_parser("build", help="Build an end-to-end bootable patched Windows 11 ISO")
    build_parser.add_argument("-i", "--input-iso", required=True, help="Path to source Windows 11 ISO or extracted directory")
    build_parser.add_argument("-o", "--output-iso", default="patched_install.iso", help="Path for output ISO (default: patched_install.iso)")
    build_parser.add_argument("-w", "--work-dir", default=None, help="Temporary workspace directory")
    build_parser.add_argument("-c", "--config", default=None, help="Path to badblobs.xml configuration")
    build_parser.add_argument("-b", "--blobs-dir", default=None, help="Path to blobs replacement directory (default: ./blobs)")
    build_parser.add_argument("--index", default=None, help="Specific OS index in install.wim to patch (e.g. 6 for Pro, 'all', or 'none' for boot.wim only)")
    build_parser.add_argument("--boot-only", action="store_true", help="Only patch boot.wim (skip install.wim)")
    build_parser.add_argument("--no-cpuid", action="store_true", help="Skip CPUID requirements table patch")
    build_parser.add_argument("--kiset", action="store_true", help="Enable KiSetFeatureBits conditional jump NOPs (disabled by default)")
    build_parser.add_argument("--debug-loop", action="store_true", help="Enable KeBugCheckEx EB FE infinite loop for QEMU GDB debugging")
    build_parser.add_argument("--allow-missing-blobs", action="store_true", help="Downgrade missing replacement blobs from fatal error to warning")
    build_parser.add_argument("--oscdimg-path", default=None, help="Explicit path to oscdimg.exe")

    # Interactive prompt fallback when run with no arguments or double-clicked
    if len(sys.argv) == 1:
        print("="*70)
        print("POP4.2 - Windows 11 SSE4.2 Requirements Patcher")
        print("="*70)
        print("1. Build Patched ISO (Automated)")
        print("2. Patch standalone ntoskrnl.exe")
        print("3. Exit")
        choice = input("\nSelect an option [1-3]: ").strip()

        if choice == "1":
            iso_input = input("Enter path to Windows 11 ISO: ").strip().strip('"')
            if not iso_input or not os.path.exists(iso_input):
                print("[-] Error: ISO file not found.")
                sys.exit(1)

            idx_input = input("Enter OS Index to patch (e.g. 6 for Pro, 'all' for all editions, or 'none' for boot.wim only) [default: 1]: ").strip()
            if not idx_input:
                idx_input = "1"

            sys.argv = ["pop42.py", "build", "-i", iso_input, "--index", idx_input]
        elif choice == "2":
            k_input = input("Enter path to ntoskrnl.exe: ").strip().strip('"')
            if not k_input or not os.path.exists(k_input):
                print("[-] Error: Kernel file not found.")
                sys.exit(1)
            sys.argv = ["pop42.py", "patch", "ntoskrnl", "-i", k_input]
        else:
            sys.exit(0)

    args = parser.parse_args()
    script_dir = os.path.abspath(os.path.dirname(__file__))

    # -------------------------------------------------------------------------
    # Execute Mode 1: PATCH
    # -------------------------------------------------------------------------
    if args.mode == "patch":
        patch_cpuid = not args.no_cpuid
        patch_kiset = args.kiset
        debug_loop = args.debug_loop
        out_file = args.output if args.output else args.input

        print("="*70)
        print(f"POP4.2 Standalone Patch Mode: '{args.shorthand}'")
        print(f"  Target:     {args.input}")
        print(f"  CPUID:      {'Enabled (0x0D -> 0x0C)' if patch_cpuid else 'Disabled'}")
        print(f"  KiSet Jumps:{'Enabled' if patch_kiset else 'Disabled (Default)'}")
        print(f"  GDB Loop:   {'Enabled (EB FE)' if debug_loop else 'Disabled'}")
        print("="*70)

        success = patch_kernel_file(args.input, out_file, patch_cpuid, patch_kiset, debug_loop)
        sys.exit(0 if success else 1)

    # -------------------------------------------------------------------------
    # Execute Mode 2: BUILD
    # -------------------------------------------------------------------------
    elif args.mode == "build":
        xml_path = args.config if args.config else os.path.join(script_dir, "badblobs.xml")
        blobs_dir = args.blobs_dir if args.blobs_dir else os.path.join(script_dir, "blobs")
        work_dir = args.work_dir if args.work_dir else os.path.join(script_dir, "build_workspace")

        db = BlobDatabase(xml_path, blobs_dir)
        print(f"[*] Loaded {len(db.blobs)} blob entries from {xml_path}.")

        # Enforce fail-fast integrity validation
        if not db.validate(allow_missing=args.allow_missing_blobs):
            print("[-] Build aborted due to validation errors. Use --allow-missing-blobs to bypass.")
            sys.exit(1)

        patch_cpuid = not args.no_cpuid
        patch_kiset = args.kiset
        debug_loop = args.debug_loop

        # Resolve index and boot_only mode
        selected_index = None
        boot_only = args.boot_only

        if args.index is not None:
            idx_str = str(args.index).strip().lower()
            if idx_str in ("none", "0", "bootonly", "boot-only"):
                boot_only = True
                selected_index = None
            elif idx_str in ("all", "*"):
                selected_index = None
            else:
                try:
                    selected_index = int(idx_str)
                except ValueError:
                    print(f"[-] Error: Invalid index '{args.index}'. Must be a number (e.g. 6), 'all', or 'none'.")
                    sys.exit(1)

        build_iso(
            input_iso=args.input_iso,
            output_iso=args.output_iso,
            work_dir=work_dir,
            db=db,
            blobs_dir=blobs_dir,
            selected_index=selected_index,
            boot_only=boot_only,
            patch_cpuid=patch_cpuid,
            patch_kiset=patch_kiset,
            debug_loop=debug_loop,
            oscdimg_path=args.oscdimg_path
        )


if __name__ == '__main__':
    main()
