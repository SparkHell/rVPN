"""Validate the native dependencies of an executable before packaging it."""

import argparse
import os
import re
import subprocess
from pathlib import Path

TARGETS = (
    "linux-x86_64", "linux-aarch64", "windows-x86_64",
    "macos-x86_64", "macos-aarch64",
)
WINDOWS_SYSTEM_DLLS = {
    # Windows bindings can import CoTaskMemFree directly from combase.dll.
    "advapi32.dll", "bcrypt.dll", "bcryptprimitives.dll", "cfgmgr32.dll", "combase.dll",
    "crypt32.dll", "dbghelp.dll", "iphlpapi.dll", "kernel32.dll",
    "ntdll.dll", "ole32.dll", "secur32.dll", "setupapi.dll", "shell32.dll",
    "user32.dll", "userenv.dll", "version.dll", "ws2_32.dll",
}


def inspect(*args):
    return subprocess.check_output(args, text=True, env={**os.environ, "LC_ALL": "C"})


def verify(target, path):
    platform, arch = target.split("-", 1)
    header = inspect("llvm-readobj", "--file-header", path)
    if not re.search(rf"^Arch: {arch}$", header, re.MULTILINE):
        raise ValueError(f"expected {arch} architecture")
    if platform == "linux":
        if not re.search(r"^Format: elf64-", header, re.MULTILINE):
            raise ValueError("expected a Linux ELF executable")
        segments = inspect("readelf", "--wide", "--program-headers", path)
        dynamic = inspect("readelf", "--wide", "--dynamic", path)
        if re.search(r"^\s*INTERP\s", segments, re.MULTILINE) or "(NEEDED)" in dynamic:
            raise ValueError("executable has an ELF interpreter or shared library dependencies")
        return

    if platform == "windows":
        if "IMAGE_FILE_EXECUTABLE_IMAGE" not in header or "ImageOptionalHeader" not in header:
            raise ValueError("expected a Windows PE executable")
        # llvm-readobj inspects the ordinary and delay-load import tables.
        imports = inspect("llvm-readobj", "--coff-imports", path)
        libraries = {
            name.lower() for name in re.findall(r"^\s+Name: (\S+\.dll)\s*$", imports, re.MULTILINE | re.IGNORECASE)
        }
        if not libraries:
            raise ValueError("no Windows system imports found")
        unexpected = {name for name in libraries if name not in WINDOWS_SYSTEM_DLLS
                      and not name.startswith(("api-ms-win-core-", "ext-ms-win-"))}
    else:
        if not re.search(r"^Format: Mach-O", header, re.MULTILINE) or "FileType: Executable" not in header:
            raise ValueError("expected a macOS Mach-O executable")
        libraries = {
            line.strip().split(" (compatibility version ", 1)[0]
            for line in inspect("llvm-objdump", "--macho", "--dylibs-used", path).splitlines()
            if line.startswith("\t")
        }
        if "/usr/lib/libSystem.B.dylib" not in libraries:
            raise ValueError("expected the macOS system runtime import")
        unexpected = {name for name in libraries
                      if not name.startswith(("/usr/lib/", "/System/Library/Frameworks/"))}
    if unexpected:
        raise ValueError("unexpected dynamic libraries: " + ", ".join(sorted(unexpected)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=TARGETS)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    try:
        verify(args.target, args.binary)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.exit(1, f"{args.binary}: {error}\n")
    print(f"{args.binary}: {args.target} linkage verified")


if __name__ == "__main__":
    main()
