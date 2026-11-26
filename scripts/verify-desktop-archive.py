#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

import pathlib
import plistlib
import stat
import struct
import sys
import tarfile
import unicodedata
import zipfile


BINARIES = {
    "linux": ("pipe",),
    "darwin": ("pipe", "Pipe.app/Contents/MacOS/Pipe"),
    "windows": ("pipe-cli.exe", "Pipe.exe"),
}
EXPECTED_FILES = {
    "linux": {"pipe", "README.txt"},
    "darwin": {
        "pipe",
        "Pipe.app/Contents/MacOS/Pipe",
        "Pipe.app/Contents/Info.plist",
        "Pipe.app/Contents/Resources/Pipe.icns",
    },
    "windows": {"pipe-cli.exe", "Pipe.exe", "README.txt"},
}
MAC_PLIST = "Pipe.app/Contents/Info.plist"
MACH_CPU = {"amd64": 0x01000007, "arm64": 0x0100000C}
ELF_CPU = {"amd64": 62, "arm64": 183}
MAX_BINARY_SIZE = 256 << 20
IDENTITY = b"\0pipe-desktop-release-v1 "
WINDOWS_DEVICES = {"aux", "con", "nul", "prn", "conin$", "conout$"} | {
    f"{prefix}{suffix}" for prefix in ("com", "lpt") for suffix in "123456789¹²³"
}
ZIP_LINK_OR_PATH_FIELDS = {0x000D, 0x756E, 0x7075}  # PKWARE Unix, ASi Unix, Unicode path


def matches_platform(binary, platform, abi):
    if platform == "linux":
        return (len(binary) >= 64 and binary[:6] == b"\x7fELF\x02\x01"
                and binary[7] in (0, 3)
                and struct.unpack_from("<HH", binary, 16) in ((2, ELF_CPU[abi]), (3, ELF_CPU[abi])))
    if platform == "darwin":
        return (len(binary) >= 32 and binary[:4] == b"\xcf\xfa\xed\xfe"
                and struct.unpack_from("<I", binary, 4)[0] == MACH_CPU[abi]
                and struct.unpack_from("<I", binary, 12)[0] == 2)
    if platform == "windows" and abi == "amd64" and binary[:2] == b"MZ" and len(binary) >= 64:
        pe = struct.unpack_from("<I", binary, 60)[0]
        if pe < 64 or pe + 26 > len(binary) or binary[pe:pe+4] != b"PE\0\0":
            return False
        machine = struct.unpack_from("<H", binary, pe + 4)[0]
        flags, optional = struct.unpack_from("<HH", binary, pe + 22)
        return machine == 0x8664 and flags & 0x0002 != 0 and flags & 0x2000 == 0 and optional == 0x020B
    return False


def verify_binary(binary, name, platform, abi, version):
    if not matches_platform(binary, platform, abi):
        raise ValueError(f"{name} has the wrong executable platform or CPU")
    expected = IDENTITY + f"{platform} {abi} {version}".encode("ascii") + b"\0"
    if binary.count(IDENTITY) != 1 or expected not in binary:
        raise ValueError(f"{name} has the wrong release version or build identity")


def destination_path(name, platform, directory):
    if platform == "windows":
        name = name.replace("\\", "/")
    if directory:
        name = name.removesuffix("/")
    parts = name.split("/")
    if (any(part in ("", ".", "..") for part in parts) or "\\" in name
            or any(unicodedata.category(ch) in ("Cc", "Cs") for ch in name)
            or (len(name) > 1 and name[0].isascii() and name[0].isalpha() and name[1] == ":")):
        raise ValueError(f"invalid archive path {name!r}")
    if platform == "windows":
        for part in parts:
            stem = part.split(".", 1)[0].rstrip(" ").casefold()
            if part.endswith((".", " ")) or stem in WINDOWS_DEVICES or any(ch in '<>:"|?*' for ch in part):
                raise ValueError(f"invalid Windows archive path {name!r}")
        return name.casefold()
    if platform == "darwin":
        return unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())
    return name


def checked_files(entries, platform):
    files, destinations = {}, {}
    for name, directory, entry in entries:
        path = destination_path(name, platform, directory)
        if path in destinations:
            raise ValueError(f"duplicate archive destination {name!r}")
        destinations[path] = directory
        if not directory:
            files[name] = entry
    for path in destinations:
        parent, _, _ = path.rpartition("/")
        while parent:
            if destinations.get(parent) is False:
                raise ValueError(f"archive path {path!r} has a file as a parent")
            parent, _, _ = parent.rpartition("/")
    return files


def tar_entries(archive):
    for entry in archive:
        if (entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                or entry.sparse is not None or entry.linkname or (entry.isdir() and entry.size != 0)):
            raise ValueError(f"unsupported archive entry {entry.name!r}")
        yield entry.name, entry.isdir(), entry
    # tarfile may stop iteration at a bad header or the first zero block.
    # A signed archive must end with the two zero blocks and any zero padding.
    archive.fileobj.seek(archive.offset)
    if archive.fileobj.read(2 * tarfile.BLOCKSIZE) != b"\0" * (2 * tarfile.BLOCKSIZE):
        raise ValueError("invalid TAR end marker")
    for block in iter(lambda: archive.fileobj.read(65536), b""):
        if block.strip(b"\0"):
            raise ValueError("unexpected data after TAR end marker")


def check_zip_extra(raw, name):
    while raw:
        if len(raw) < 4:
            raise ValueError(f"invalid ZIP metadata for {name!r}")
        kind, size = struct.unpack_from("<HH", raw)
        if kind in ZIP_LINK_OR_PATH_FIELDS or size > len(raw) - 4:
            raise ValueError(f"unsupported ZIP metadata for {name!r}")
        raw = raw[4+size:]


def zip_entries(archive, platform):
    for entry in archive.infolist():
        name = entry.orig_filename
        directory = name.endswith("/") or (platform == "windows" and name.endswith("\\"))
        mode = stat.S_IFMT(entry.external_attr >> 16)
        dos_attrs = entry.external_attr & 0xFFFF
        if (mode not in (0, stat.S_IFDIR if directory else stat.S_IFREG)
                or dos_attrs & 0x408  # reparse point or volume label
                or (directory and entry.file_size != 0) or (not directory and dos_attrs & 0x10)):
            raise ValueError(f"unsupported archive entry {name!r}")
        check_zip_extra(entry.extra, name)
        archive.fp.seek(entry.header_offset)
        header = archive.fp.read(30)
        if len(header) != 30 or header[:4] != b"PK\x03\x04":
            raise ValueError(f"invalid ZIP header for {name!r}")
        name_size, extra_size = struct.unpack_from("<HH", header, 26)
        archive.fp.seek(name_size, 1)
        extra = archive.fp.read(extra_size)
        if len(extra) != extra_size:
            raise ValueError(f"truncated ZIP metadata for {name!r}")
        check_zip_extra(extra, name)
        yield name, directory, entry


def read_zip_member(archive, files, name, limit):
    entry = files.get(name)
    if entry is None or not 0 < entry.file_size <= limit:
        raise ValueError(f"{name} must be a regular packaged file")
    with archive.open(entry) as member:
        return member.read()


def verify(path, platform, abi, version):
    expected = EXPECTED_FILES[platform]
    if platform == "linux":
        with tarfile.open(path, "r:gz") as archive:
            files = checked_files(tar_entries(archive), platform)
            if set(files) != expected:
                raise ValueError(f"archive file list {sorted(files)} does not match {sorted(expected)}")
            entry = files["pipe"]
            if not 0 < entry.size <= MAX_BINARY_SIZE:
                raise ValueError("pipe must occur once as a regular packaged executable")
            with archive.extractfile(entry) as member:
                verify_binary(member.read(), "pipe", platform, abi, version)
        return
    with zipfile.ZipFile(path) as archive:
        files = checked_files(zip_entries(archive, platform), platform)
        if set(files) != expected:
            raise ValueError(f"archive file list {sorted(files)} does not match {sorted(expected)}")
        for name in BINARIES[platform]:
            verify_binary(read_zip_member(archive, files, name, MAX_BINARY_SIZE), name, platform, abi, version)
        if platform == "darwin":
            plist = plistlib.loads(read_zip_member(archive, files, MAC_PLIST, 65536))
            if (plist.get("CFBundleExecutable") != "Pipe" or plist.get("CFBundleVersion") != version
                    or plist.get("CFBundleShortVersionString") != version):
                raise ValueError("the app bundle has the wrong version or executable")
        if bad := archive.testzip():
            raise ValueError(f"{bad} failed archive verification")


def main():
    path, platform, abi, version = sys.argv[1:]
    try:
        verify(path, platform, abi, version)
    except (OSError, ValueError, EOFError, tarfile.TarError, zipfile.BadZipFile, plistlib.InvalidFileException) as error:
        sys.exit(f"Invalid release archive {pathlib.Path(path).name}: {error}.")


if __name__ == "__main__":
    main()
