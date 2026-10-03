#!/usr/bin/env python3
"""
================================================================================
POP4.2 Packaging Script
================================================================================
Compiles pop42.py into a standalone onefile Windows executable using Python 3.8
(to make Windows 8 work) and Nuitka, then bundles it into a release zip archive
containing:
  - pop42.exe
  - badblobs.xml
  - LICENSE
  - LICENSE.PEFILE
  - blobs/README.txt
================================================================================
"""

import os
import sys
import shutil
import subprocess
import argparse
import zipfile
from pathlib import Path


def find_python_38() -> str:
    """
    Locates the Python 3.8 executable.
    Checks:
      1. Currently running interpreter (if 3.8)
      2. Windows 'py' launcher (-3.8)
      3. PATH (python3.8, python)
      4. Common Windows installation directories
    """
    if sys.version_info[:2] == (3, 8):
        return sys.executable

    # Try py launcher
    py_launcher = shutil.which("py")
    if py_launcher:
        try:
            res = subprocess.run(
                [py_launcher, "-3.8", "-c", "import sys; print(sys.executable)"],
                capture_output=True,
                text=True,
                check=True,
            )
            exe = res.stdout.strip()
            if exe and os.path.isfile(exe):
                return exe
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

    # Try PATH python3.8
    py38_path = shutil.which("python3.8")
    if py38_path:
        return py38_path

    # Try standard Windows install locations
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_app_data, r"Programs\Python\Python38\python.exe"),
        r"C:\Python38\python.exe",
        r"C:\Program Files\Python38\python.exe",
    ]
    for cand in candidates:
        if os.path.isfile(cand):
            return cand

    return ""


def check_dependencies(python_exe: str):
    """
    Ensures nuitka and pefile are installed in the target Python 3.8 environment.
    """
    missing = []
    for pkg in ["nuitka", "pefile", "zstandard"]:
        try:
            subprocess.run(
                [python_exe, "-c", f"import {pkg}"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            missing.append(pkg)

    if missing:
        print("[-] Missing required packages in Python 3.8 environment:")
        for m in missing:
            print(f"    - {m}")
        print("\nPlease install them using:")
        print(f"    \"{python_exe}\" -m pip install {' '.join(missing)}")
        sys.exit(1)


def build_executable(python_exe: str, root_dir: Path, build_dir: Path) -> Path:
    """
    Compiles pop42.py using Nuitka.
    """
    script_path = root_dir / "pop42.py"
    if not script_path.is_file():
        print(f"[-] Error: Script not found: {script_path}")
        sys.exit(1)

    print(f"[*] Compiling {script_path.name} with Nuitka ({python_exe})...")
    
    cmd = [
        python_exe,
        "-m",
        "nuitka",
        "--onefile",
        "--assume-yes-for-downloads",
        "--include-package=pefile",
        f"--output-dir={build_dir}",
        "--remove-output",
        "--python-flag=-O",
        "--python-flag=no_site",
        "--mingw64",
        "--lto=yes",
        "--windows-uac-admin",
        "--noinclude-setuptools-mode=nofollow",
        "--noinclude-pytest-mode=nofollow",
        str(script_path),
    ]

    print("[*] Running command:")
    print("    " + " ".join(cmd))
    
    res = subprocess.run(cmd, cwd=root_dir)
    if res.returncode != 0:
        print(f"[-] Nuitka build failed with return code {res.returncode}")
        sys.exit(res.returncode)

    exe_path = build_dir / "pop42.exe"
    if not exe_path.is_file():
        # Fallback check directly in root_dir or build_dir
        cand = root_dir / "pop42.exe"
        if cand.is_file():
            exe_path = cand
        else:
            print(f"[-] Error: Expected executable not found at {exe_path}")
            sys.exit(1)

    print(f"[+] Successfully built: {exe_path} ({exe_path.stat().st_size:,} bytes)")
    return exe_path


def create_release_zip(root_dir: Path, exe_path: Path, output_zip: Path):
    """
    Packages the executable and required assets into a zip file.
    """
    required_files = [
        (exe_path, "pop42.exe"),
        (root_dir / "badblobs.xml", "badblobs.xml"),
        (root_dir / "LICENSE", "LICENSE"),
        (root_dir / "LICENSE.PEFILE", "LICENSE.PEFILE"),
        (root_dir / "blobs" / "README.txt", "blobs/README.txt"),
    ]

    for file_path, arcname in required_files:
        if not file_path.is_file():
            print(f"[-] Error: Required file missing for package: {file_path}")
            sys.exit(1)

    output_zip.parent.mkdir(parents=True, exist_ok=True)
    if output_zip.exists():
        output_zip.unlink()

    print(f"[*] Creating release archive: {output_zip}...")
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path, arcname in required_files:
            print(f"    + Adding {arcname} ({file_path.stat().st_size:,} bytes)")
            zf.write(file_path, arcname=arcname)

    print(f"[+] Release package created successfully: {output_zip} ({output_zip.stat().st_size:,} bytes)")


def main():
    parser = argparse.ArgumentParser(description="Build and package POP4.2 into a release zip archive.")
    parser.add_argument(
        "-o",
        "--output",
        default="dist/pop42-release.zip",
        help="Path for output zip file (default: dist/pop42-release.zip)",
    )
    parser.add_argument(
        "--build-dir",
        default="build",
        help="Temporary build directory for Nuitka output (default: build)",
    )
    parser.add_argument(
        "--python",
        default=None,
        help="Explicit path to Python 3.8 executable",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip Nuitka compilation and package existing pop42.exe from build-dir",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent
    build_dir = (root_dir / args.build_dir).resolve()
    output_zip = (root_dir / args.output).resolve()

    if args.skip_build:
        exe_path = build_dir / "pop42.exe"
        if not exe_path.is_file():
            exe_path = root_dir / "pop42.exe"
        if not exe_path.is_file():
            print(f"[-] Error: --skip-build specified but executable not found at {build_dir / 'pop42.exe'}")
            sys.exit(1)
    else:
        python_exe = args.python or find_python_38()
        if not python_exe:
            print("[-] Error: Python 3.8 executable could not be found.")
            print("    Please install Python 3.8 or specify path using --python <path_to_python.exe>")
            sys.exit(1)

        print(f"[+] Using Python 3.8: {python_exe}")
        check_dependencies(python_exe)
        exe_path = build_executable(python_exe, root_dir, build_dir)

    create_release_zip(root_dir, exe_path, output_zip)


if __name__ == "__main__":
    main()
