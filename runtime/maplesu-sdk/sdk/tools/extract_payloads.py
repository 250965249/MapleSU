#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""extract_payloads.py -- R-PROGRAMS: extract & fingerprint the binary payloads that are
embedded (as static byte arrays) inside the four large `maplesu_*_install.o` members of
the MapleSU SDK kernel-module-kit static archive.

Why this exists
---------------
`runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a` (residual reference) contains four members
whose object size is far above every other member.  They are ET_REL AArch64 objects that
carry a whole userland program as a `static const unsigned char[]` in `.data`:

    member                               symbol (mangled)                            size
    maplesu_unsafe_su_install.o           _ZN10skroot_envL7su_dataE                   0x0b5218  (742424)
    maplesu_unsafe_resetprop_install.o    _ZN10skroot_envL19resetprop_file_dataE      0x061cb8  (400568)
    maplesu_unsafe_webui_loader_install.o _ZN10skroot_envL17webui_loader_dataE        0x0bb170  (766320)
    maplesu_autorun_bootstrap_install.o   _ZN10skroot_envL27autorun_bootstrap_file_dataE 0x1491b0 (1348016)

The script does *not* shell out to `ar`/`readelf`: it parses the System V `ar` archive and
the ELF64 container itself, so every reported number is byte-exact and reproducible:

  * archive member byte offset / size
  * payload symbol -> st_value / st_size -> owning section -> file offset
  * payload sha256, container magic
  * if the payload is ELF: class/data/type/machine, section count, PT_LOAD layout,
    DT_NEEDED, undefined-dynsym imports, stripped-ness, PIE/NX/RELRO-ish flags
  * if the payload is gzip/xz/bzip2/zstd: decompressed size + sha256
  * identity markers (resetprop / magisk / webui / kernelsu / ...) found in printable strings

Usage
-----
    py tools/extract_payloads.py                       # analyse + write report only
    py tools/extract_payloads.py --out DIR --emit      # also write the raw .bin payloads
    py tools/extract_payloads.py --archive PATH ...    # point at another archive

Default archive is the frozen snapshot (read-only), which is byte-identical to the
production archive:

    maintenance/freeze/freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114/archive/libkernel_module_kit_static.a

Exit codes: 0 = every target found and extracted, 1 = at least one target failed.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import os
import struct
import sys

# --------------------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------------------

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", ".."))

def report_path(path: str) -> str:
    """Keep existing relative labels and allow build output on another drive."""
    try:
        return os.path.relpath(path, REPO_ROOT)
    except ValueError:
        return os.path.abspath(path)


DEFAULT_ARCHIVE = os.path.join(
    REPO_ROOT,
    "runtime", "maplesu-sdk", "maintenance", "freeze",
    "freeze-maplesu-pro-5.2.0-su-uid-isolation-20261114-20261114",
    "archive", "libkernel_module_kit_static.a",
)

DEFAULT_OUT = os.path.join(REPO_ROOT, "runtime", "maplesu-sdk", "sdk", "notes", "recon", "payloads")

# member name -> (mangled symbol, short name, human label)
TARGETS = [
    ("skroot_unsafe_su_install.o", "_ZN10skroot_envL7su_dataE", "su", "su"),
    ("skroot_unsafe_resetprop_install.o", "_ZN10skroot_envL19resetprop_file_dataE", "resetprop", "resetprop"),
    ("skroot_unsafe_webui_loader_install.o", "_ZN10skroot_envL17webui_loader_dataE", "webui_loader", "webui_loader"),
    ("skroot_autorun_bootstrap_install.o", "_ZN10skroot_envL27autorun_bootstrap_file_dataE", "autorun_bootstrap", "autorun_bootstrap"),
]

INSTALLER_NAMES = {old: old.replace("skroot_", "maplesu_", 1) for old, *_ in TARGETS}
PAYLOAD_SYMBOLS = {old: old.replace("_ZN10skroot_envL", "_ZN7maplesu3sdkL", 1)
                   for _, old, *_ in TARGETS}

# identity markers we look for in the payload's printable strings
MARKERS = [
    "resetprop", "magisk", "Magisk", "MAGISK", "webui", "WebUI", "WEBUI",
    "kernelsu", "KernelSU", "ksu", "KSU", "maplesu_assets", "MapleSU", "SKROOT",
    "zygisk", "Zygisk", "post-fs-data", "service.d", "module.prop", "boot-completed",
    "setprop", "getprop", "persist.sys", "shamiko", "denylist", "sulog", "su_daemon",
    "libc.so", "ld-android.so", "linker64", "/system/bin/sh", "u:r:su:s0", "magiskpolicy",
]

ELF_MAGIC = b"\x7fELF"
MAGICS = [
    (b"\x7fELF", "ELF"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x04\x22\x4d\x18", "lz4-frame"),
    (b"PK\x03\x04", "zip"),
    (b"dex\n", "dex"),
    (b"#!", "script"),
    (b"\x00asm", "wasm"),
]

ET = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
EM = {0: "NONE", 40: "ARM", 183: "AARCH64", 62: "X86_64", 3: "X86", 243: "RISCV"}

SHT = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 8: "NOBITS",
       9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY", 23: "INIT_ARRAY? ",
       6: "DYNAMIC", 7: "NOTE"}

DT = {0: "NULL", 1: "NEEDED", 5: "STRTAB", 6: "SYMTAB", 10: "STRSZ", 12: "INIT",
      13: "FINI", 14: "SONAME", 15: "RPATH", 23: "JMPREL", 25: "INIT_ARRAY", 29: "RUNPATH",
      30: "FLAGS", 0x6ffffffb: "FLAGS_1"}


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o, limit=4096):
    e = b.find(b"\x00", o, o + limit if limit else len(b))
    if e < 0:
        e = min(len(b), o + (limit or 256))
    return b[o:e]


def detect_magic(data: bytes) -> str:
    for magic, name in MAGICS:
        if data.startswith(magic):
            return name
    return "unknown"


def printable_strings(data: bytes, minlen=6):
    out, cur = [], bytearray()
    for ch in data:
        if 0x20 <= ch <= 0x7E or ch == 0x09:
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out


# --------------------------------------------------------------------------------------
# System V ar archive parser (GNU long-name table + BSD #1/ names)
# --------------------------------------------------------------------------------------

class ArMember:
    __slots__ = ("name", "header_offset", "data_offset", "size", "raw")

    def __init__(self, name, header_offset, data_offset, size, raw):
        self.name = name
        self.header_offset = header_offset
        self.data_offset = data_offset
        self.size = size
        self.raw = raw


def parse_ar_members(blob: bytes):
    """Return ordered members, preserving duplicate names and excluding ar metadata."""
    if not blob.startswith(b"!<arch>\n"):
        raise ValueError("not a System V ar archive (bad global magic)")
    members = []
    longnames = b""
    off = 8
    n = len(blob)
    while off + 60 <= n:
        hdr = blob[off:off + 60]
        if hdr[58:60] != b"`\n":
            raise ValueError(f"bad ar member header magic at offset {off}: {hdr[58:60]!r}")
        raw_name = hdr[0:16].decode("ascii", "replace").rstrip()
        size = int(hdr[48:58].decode("ascii").strip() or "0")
        data_off = off + 60
        if data_off + size > n:
            raise ValueError(f"truncated ar member {raw_name!r} at offset {off}")
        payload = blob[data_off:data_off + size]

        name = raw_name
        real_size = size
        if raw_name == "//":
            longnames = payload
            name = "//"
        elif raw_name in ("/", "/SYM64/"):
            name = raw_name
        elif raw_name.startswith("#1/"):
            ln = int(raw_name[3:])
            name = payload[:ln].decode("ascii", "replace")
            real_size = size - ln
            payload = payload[ln:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit() and longnames:
            lo = int(raw_name[1:])
            end = longnames.find(b"/\n", lo)
            if end < 0:
                end = longnames.find(b"\x00", lo)
            name = longnames[lo:end].decode("ascii", "replace")
        elif raw_name.endswith("/"):
            name = raw_name[:-1]

        if name not in ("/", "//", "/SYM64/"):
            members.append(ArMember(name, off, data_off, real_size, payload))
        off = data_off + size + (size & 1)
    return members


def parse_ar(blob: bytes):
    """Name lookup for the unique installer members; use parse_ar_members for counts."""
    return installer_member_lookup(parse_ar_members(blob))


def installer_member_lookup(member_list):
    members = {}
    installer_names = set(INSTALLER_NAMES) | set(INSTALLER_NAMES.values())
    for member in member_list:
        if member.name in installer_names and member.name in members:
            raise ValueError("duplicate installer member: " + member.name)
        members[member.name] = member
    return members


# --------------------------------------------------------------------------------------
# ELF parser (enough for ET_REL objects and for static/dynamic executables)
# --------------------------------------------------------------------------------------

class ElfSection:
    __slots__ = ("index", "name", "type", "flags", "addr", "offset", "size", "link", "entsize")

    def __init__(self, index, name, type_, flags, addr, offset, size, link, entsize):
        self.index = index
        self.name = name
        self.type = type_
        self.flags = flags
        self.addr = addr
        self.offset = offset
        self.size = size
        self.link = link
        self.entsize = entsize


class ElfFile:
    def __init__(self, data: bytes):
        self.data = data
        if not data.startswith(ELF_MAGIC):
            raise ValueError("not an ELF file")
        self.ei_class = data[4]
        self.ei_data = data[5]
        if self.ei_class != 2:
            raise ValueError(f"only ELFCLASS64 supported, got class {self.ei_class}")
        if self.ei_data != 1:
            raise ValueError(f"only little-endian supported, got data {self.ei_data}")
        self.e_type = u16(data, 16)
        self.e_machine = u16(data, 18)
        self.e_entry = u64(data, 24)
        self.e_phoff = u64(data, 0x20)
        self.e_shoff = u64(data, 0x28)
        self.e_flags = u32(data, 0x30)
        self.e_phnum = u16(data, 0x38)
        self.e_phentsize = u16(data, 0x36)
        self.e_shnum = u16(data, 0x3C)
        self.e_shentsize = u16(data, 0x3A)
        self.e_shstrndx = u16(data, 0x3E)
        self.sections = []
        self._parse_sections()
        self.phdrs = []
        self._parse_phdrs()

    # -- sections ---------------------------------------------------------------
    def _parse_sections(self):
        if not self.e_shoff or not self.e_shnum:
            return
        raw = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            raw.append((u32(self.data, o), u32(self.data, o + 4), u64(self.data, o + 8),
                        u64(self.data, o + 0x10), u64(self.data, o + 0x18), u64(self.data, o + 0x20),
                        u32(self.data, o + 0x28), u64(self.data, o + 0x38)))
        shstr = b""
        if self.e_shstrndx < len(raw):
            # raw tuple layout: (name, type, flags, addr, offset, size, link, entsize)
            _sh_off, _sh_size = raw[self.e_shstrndx][4], raw[self.e_shstrndx][5]
            shstr = self.data[_sh_off:_sh_off + _sh_size]
        for i, (nameoff, type_, flags, addr, off, size, link, entsize) in enumerate(raw):
            nm = cstr(shstr, nameoff).decode("ascii", "replace") if nameoff < len(shstr) else ""
            self.sections.append(ElfSection(i, nm, type_, flags, addr, off, size, link, entsize))

    def section(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def section_bytes(self, s: ElfSection):
        if s.type == 8:  # NOBITS
            return b""
        return self.data[s.offset:s.offset + s.size]

    # -- program headers --------------------------------------------------------
    def _parse_phdrs(self):
        for i in range(self.e_phnum):
            o = self.e_phoff + i * self.e_phentsize
            p_type = u32(self.data, o)
            p_flags = u32(self.data, o + 4)
            p_offset = u64(self.data, o + 8)
            p_vaddr = u64(self.data, o + 0x10)
            p_filesz = u64(self.data, o + 0x20)
            p_memsz = u64(self.data, o + 0x28)
            self.phdrs.append(dict(type=p_type, flags=p_flags, offset=p_offset,
                                   vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz))

    def vaddr_to_off(self, va):
        for ph in self.phdrs:
            if ph["type"] == 1 and ph["vaddr"] <= va < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (va - ph["vaddr"])
        return None

    # -- symbols ----------------------------------------------------------------
    def symbols(self, s: ElfSection):
        """Yield (name, value, size, info, shndx) for SYMTAB/DYNSYM section."""
        if s.type not in (2, 11) or not s.entsize:
            return
        strtab = self.sections[s.link] if s.link < len(self.sections) else None
        strdata = self.section_bytes(strtab) if strtab else b""
        blob = self.section_bytes(s)
        for i in range(s.size // s.entsize):
            o = i * s.entsize
            st_name = u32(blob, o)
            st_info = blob[o + 4]
            st_shndx = u16(blob, o + 6)
            st_value = u64(blob, o + 8)
            st_size = u64(blob, o + 0x10)
            yield (cstr(strdata, st_name).decode("ascii", "replace"),
                   st_value, st_size, st_info, st_shndx)

    def find_symbol(self, name):
        for s in self.sections:
            if s.type in (2, 11):
                for sym in self.symbols(s):
                    if sym[0] == name:
                        return sym
        return None

    def imports(self, limit=400):
        """Undefined symbols from .dynsym (or .symtab as fallback)."""
        out = []
        for s in self.sections:
            if s.type == 11:
                for nm, val, size, info, shndx in self.symbols(s):
                    if shndx == 0 and nm:
                        out.append(nm)
                if out:
                    return sorted(set(out))[:limit]
        for s in self.sections:
            if s.type == 2:
                for nm, val, size, info, shndx in self.symbols(s):
                    if shndx == 0 and nm:
                        out.append(nm)
        return sorted(set(out))[:limit]

    def needed(self):
        """DT_NEEDED sonames."""
        out = []
        dyn = self.section(".dynamic")
        if dyn is not None and dyn.entsize:
            strtab = self.sections[dyn.link] if dyn.link < len(self.sections) else None
            strdata = self.section_bytes(strtab) if strtab else b""
            blob = self.section_bytes(dyn)
            for i in range(dyn.size // dyn.entsize):
                o = i * dyn.entsize
                tag = u64(blob, o)
                val = u64(blob, o + 8)
                if tag == 0:
                    break
                if tag == 1:
                    out.append(cstr(strdata, val).decode("ascii", "replace"))
        else:
            # fall back to PT_DYNAMIC + PT_LOAD mapping
            for ph in self.phdrs:
                if ph["type"] != 2:
                    continue
                base = ph["offset"]
                strtab_va = strsz = None
                entries = []
                for i in range(ph["filesz"] // 16):
                    o = base + i * 16
                    tag = u64(self.data, o)
                    val = u64(self.data, o + 8)
                    if tag == 0:
                        break
                    entries.append((tag, val))
                for tag, val in entries:
                    if tag == 5:
                        strtab_va = val
                    elif tag == 10:
                        strsz = val
                if strtab_va is not None:
                    stroff = self.vaddr_to_off(strtab_va)
                    if stroff is not None:
                        for tag, val in entries:
                            if tag == 1:
                                out.append(cstr(self.data, stroff + val).decode("ascii", "replace"))
        return out

    def summary(self):
        sec_names = [s.name for s in self.sections]
        prog = [p for p in self.phdrs if p["type"] == 1]
        has_interp = any(p["type"] == 3 for p in self.phdrs)
        has_dynamic = any(p["type"] == 2 for p in self.phdrs) or ".dynamic" in sec_names
        return dict(
            ei_class=self.ei_class,
            ei_data=self.ei_data,
            e_type=self.e_type,
            e_type_name=ET.get(self.e_type, f"UNKNOWN({self.e_type})"),
            e_machine=self.e_machine,
            e_machine_name=EM.get(self.e_machine, f"UNKNOWN({self.e_machine})"),
            e_entry=f"0x{self.e_entry:x}",
            e_flags=f"0x{self.e_flags:x}",
            section_count=len(self.sections),
            section_names=[n for n in sec_names if n][:40],
            has_symtab=any(s.type == 2 for s in self.sections),
            has_dynsym=any(s.type == 11 for s in self.sections),
            phdr_count=len(self.phdrs),
            pt_load_count=len(prog),
            pt_load_total_filesz=sum(p["filesz"] for p in prog),
            interpreter=has_interp,
            dynamic=has_dynamic,
            imported_symbol_count=None,  # filled by caller
            dt_needed=self.needed(),
            rwx_segments=[p["vaddr"] for p in prog if (p["flags"] & 7) == 7],
        )


# --------------------------------------------------------------------------------------
# payload extraction
# --------------------------------------------------------------------------------------

def find_magic_offsets(data: bytes, magic_list, max_hits=16):
    hits = []
    for magic, name in magic_list:
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            hits.append((i, name))
            start = i + 1
            if len(hits) >= max_hits:
                break
    return sorted(hits)


def extract_one(member_name, symbol, short, label, archive_blob, members, emit_dir=None,
                expected_assets=None):
    rec = {"member": member_name, "symbol": symbol, "short": short, "label": label}
    candidates = next(([old, current] for old, current in INSTALLER_NAMES.items()
                       if member_name in (old, current)), [member_name])
    present = [name for name in candidates if name in members]
    if len(present) > 1:
        rec["error"] = "ambiguous installer members: " + ", ".join(present)
        return rec
    m = members.get(present[0]) if present else None
    if m is None:
        rec["error"] = "member not present in archive"
        return rec
    if m.name != member_name:
        rec["requested_member"] = member_name
        rec["member"] = m.name
    rec["member_offset_in_archive"] = m.data_offset
    rec["member_size"] = m.size
    rec["member_sha256"] = sha256(m.raw)

    elf = ElfFile(m.raw)
    rec["object"] = elf.summary()
    sec_names = [s.name for s in elf.sections]
    # the big .data section is the payload container
    data_sec = None
    for s in elf.sections:
        if s.name == ".data":
            data_sec = s
            break
    rec["object_rodata_note"] = [
        {"name": s.name, "size": s.size, "offset": s.offset}
        for s in elf.sections
        if s.name in (".rodata", ".data") or s.name.startswith("_ZL") ]

    # Install-time "feature token" constants: the vendor build embeds a fixed-length placeholder
    # string into the payload and patches it in place with the runtime root key at install time
    # (see .research/MapleSU/Lite_version/.../jni/rootkit_su_install.cpp -> replace_feature_string_in_buf).
    rec["feature_tokens"] = []
    for s in elf.sections:
        if s.type not in (2, 11):
            continue
        for nm, val, size, info, shndx in elf.symbols(s):
            if "rootkey" not in nm and "root_key" not in nm:
                continue
            if shndx == 0 or shndx >= len(elf.sections) or not size:
                continue
            sec = elf.sections[shndx]
            blob = m.raw[sec.offset + val: sec.offset + val + size]
            nul = blob.find(b"\x00")
            text = blob[:nul] if nul >= 0 else blob
            rec["feature_tokens"].append({
                "symbol": nm,
                "section": sec.name,
                "offset_in_member": sec.offset + val,
                "declared_size": size,
                "text_len": len(text),
                "text": text.decode("ascii", "replace"),
                "sha256": sha256(blob),
            })

    candidates = next(([old, current] for old, current in PAYLOAD_SYMBOLS.items()
                       if symbol in (old, current)), [symbol])
    found = [value for name in candidates if (value := elf.find_symbol(name)) is not None]
    if len(found) > 1:
        rec["error"] = "ambiguous payload symbols: " + ", ".join(candidates)
        return rec
    sym = found[0] if found else None
    if sym is None:
        rec["error"] = f"symbol {symbol!r} not found in .symtab"
        return rec
    if sym[0] != symbol:
        rec["requested_symbol"] = symbol
        rec["symbol"] = sym[0]
    _, st_value, st_size, st_info, st_shndx = sym
    rec["symbol_value"] = st_value
    rec["symbol_size"] = st_size
    rec["symbol_shndx"] = st_shndx
    rec["payload_size"] = st_size
    if st_shndx == 0 or st_shndx >= len(elf.sections):
        rec["error"] = f"symbol shndx {st_shndx} not a real section"
        return rec
    own = elf.sections[st_shndx]
    rec["symbol_section"] = own.name
    rec["symbol_section_size"] = own.size
    rec["symbol_section_offset"] = own.offset
    rec["payload_fills_whole_section"] = (st_value == 0 and st_size == own.size)
    payload = m.raw[own.offset + st_value: own.offset + st_value + st_size]
    rec["payload_sha256"] = sha256(payload)
    rec["payload_magic"] = detect_magic(payload)
    rec["payload_head_hex"] = payload[:64].hex()
    if expected_assets is not None:
        asset = "resetprop_file.bin" if short == "resetprop" else f"{short}.bin"
        expected_path = os.path.join(expected_assets, asset)
        if not os.path.isfile(expected_path):
            rec["error"] = f"selected asset missing: {asset}"
        else:
            with open(expected_path, "rb") as handle:
                expected = handle.read()
            rec["expected_asset"] = {"path": report_path(expected_path),
                                     "bytes": len(expected), "sha256": sha256(expected),
                                     "matches": payload == expected}
            if payload != expected:
                rec["error"] = f"embedded payload differs from selected asset: {asset}"

    # container magics anywhere in the member (a payload could be a container of >1 blob)
    rec["magic_scan_in_member"] = [
        {"offset": off, "magic": nm} for off, nm in find_magic_offsets(m.raw, MAGICS)
    ][:16]

    # nested analysis
    if payload.startswith(ELF_MAGIC):
        try:
            pe = ElfFile(payload)
            s = pe.summary()
            s["imported_symbol_count"] = len(pe.imports())
            s["imports_sample"] = pe.imports(limit=60)
            rec["payload_elf"] = s
        except Exception as exc:  # noqa: BLE001
            rec["payload_elf_error"] = repr(exc)
    else:
        for name, fn in (("gzip", gzip.decompress), ("xz", lzma.decompress), ("bzip2", bz2.decompress)):
            if rec["payload_magic"] == name:
                try:
                    dec = fn(payload)
                    rec["payload_decompressed"] = {
                        "codec": name, "size": len(dec), "sha256": sha256(dec),
                        "magic": detect_magic(dec),
                    }
                except Exception as exc:  # noqa: BLE001
                    rec["payload_decompressed_error"] = repr(exc)
                break

    # identity strings
    strs = printable_strings(payload)
    rec["string_count"] = len(strs)
    hits = {}
    for mk in MARKERS:
        found = [s for s in strs if mk in s]
        if found:
            hits[mk] = {"count": len(found), "samples": found[:6]}
    rec["identity_markers"] = hits

    if emit_dir:
        os.makedirs(emit_dir, exist_ok=True)
        p = os.path.join(emit_dir, f"{short}.bin")
        with open(p, "wb") as fh:
            fh.write(payload)
        rec["emitted"] = report_path(p)
    return rec


def write_artifacts(report, out_dir):
    """Write the small, reviewable evidence files (no multi-hundred-KB binaries)."""
    os.makedirs(out_dir, exist_ok=True)
    lines = []
    for t in report["targets"]:
        if "error" in t:
            continue
        short = t["short"]
        lines.append(f'{t["payload_sha256"]}  bin/{short}.bin   # {t["payload_size"]} B  {t["payload_magic"]}'
                     f'  (regenerate: py tools/extract_payloads.py --emit --out <this dir>)')
        # 64-byte header (enough to re-identify the container without carrying the payload)
        d = os.path.join(out_dir, "heads")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{short}.head64.bin"), "wb") as fh:
            fh.write(bytes.fromhex(t["payload_head_hex"]))
        # import list
        elf = t.get("payload_elf") or {}
        d = os.path.join(out_dir, "imports")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{short}.imports.txt"), "w", encoding="utf-8") as fh:
            fh.write(f'# {short}: DT_NEEDED={elf.get("dt_needed")}\n')
            for s in elf.get("imports_sample") or []:
                fh.write(s + "\n")
        # identity markers
        d = os.path.join(out_dir, "identity")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, f"{short}.identity.txt"), "w", encoding="utf-8") as fh:
            for mk, v in sorted(t["identity_markers"].items(), key=lambda kv: -kv[1]["count"]):
                fh.write(f'{mk}\tcount={v["count"]}\n')
                for s in v["samples"]:
                    fh.write(f'\t{s}\n')
    with open(os.path.join(out_dir, "PAYLOADS.sha256"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    # feature tokens table
    with open(os.path.join(out_dir, "feature-tokens.txt"), "w", encoding="utf-8") as fh:
        fh.write("# install-time placeholder tokens found inside the 4 install objects\n")
        for t in report["targets"]:
            for tok in t.get("feature_tokens") or []:
                fh.write(f'{t["short"]}\t{tok["symbol"]}\tsection={tok["section"]}\t'
                         f'off={tok["offset_in_member"]:#x}\tdeclared={tok["declared_size"]}\t'
                         f'len={tok["text_len"]}\tsha256={tok["sha256"]}\n\t{tok["text"]}\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description="Extract embedded payloads from the MapleSU SDK archive")
    ap.add_argument("--archive", default=DEFAULT_ARCHIVE, help="path to libkernel_module_kit_static.a")
    ap.add_argument("--out", default=DEFAULT_OUT, help="directory for the report / small artifacts")
    ap.add_argument("--emit", action="store_true", help="also write the raw payload .bin files to --out/bin")
    ap.add_argument("--expected-assets", default=None,
                    help="compare each extracted payload byte-for-byte with this selected asset directory")
    ap.add_argument("--artifacts", action="store_true",
                    help="also write small evidence files (heads/, imports/, identity/, PAYLOADS.sha256, feature-tokens.txt)")
    ap.add_argument("--json", default=None, help="explicit report path (default <out>/payloads.json)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    with open(args.archive, "rb") as fh:
        blob = fh.read()
    member_list = parse_ar_members(blob)
    members = installer_member_lookup(member_list)
    counts = {}
    for member in member_list:
        counts[member.name] = counts.get(member.name, 0) + 1
    archive_sha = sha256(blob)

    emit_dir = os.path.join(args.out, "bin") if args.emit else None
    results = []
    for member, symbol, short, label in TARGETS:
        rec = extract_one(member, symbol, short, label, blob, members, emit_dir,
                          args.expected_assets)
        results.append(rec)
        if not args.quiet:
            if "error" in rec:
                print(f"[FAIL] {short}: {rec['error']}")
            else:
                print(f"[ OK ] {short:18s} {rec['payload_size']:>9d} B  {rec['payload_magic']:7s} "
                      f"sha256={rec['payload_sha256'][:16]}...")

    report = {
        "tool": "runtime/maplesu-sdk/sdk/tools/extract_payloads.py",
        "archive": {
            "path": report_path(args.archive).replace("\\", "/"),
            "size": len(blob),
            "sha256": archive_sha,
            "member_count": len(member_list),
            "unique_member_names": len(members),
            "duplicate_names": {name: count for name, count in counts.items() if count > 1},
        },
        "targets": results,
    }
    out_json = args.json or os.path.join(args.out, "payloads.json")
    os.makedirs(os.path.dirname(out_json), exist_ok=True)
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    if args.artifacts:
        write_artifacts(report, args.out)
        if not args.quiet:
            print(f"artifacts -> {report_path(args.out)}")
    if not args.quiet:
        print(f"\nreport -> {report_path(out_json)}")

    return 0 if all("error" not in r for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
