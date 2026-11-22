#!/usr/bin/env python3
"""Regenerate the MapleSU root-loader kernel ABI contract from the image itself.

The contract is a *derived* artifact. Every number in contracts/<uname>.json comes
from one of four observable sources, and this script re-reads all of them on every
run:

  1. the image's own ``.BTF`` blob   -> struct layouts (module, kprobe, selinux_state)
                                        and the set of functions the kernel was built
                                        with
  2. the image's own bytes           -> vermagic string, the KCFI init type id
                                        immediate, and the embedded IKCONFIG blob
                                        (authoritative CONFIG_* facts)
  3. the kallsyms TSV                -> symbol presence/type/address, the
                                        ``__ksymtab`` vs ``__ksymtab_gpl`` export
                                        class, and the "not exported" denials
  4. the module sources              -> the claims the C/asm actually makes, which
                                        are then compared against 1-3 (abiChecks)

There is no per-release address table anywhere in here. The only literal kernel
numbers are the ones the module source already hard-codes as *claims* (0x600,
+0x188, ...); those are checked, never trusted: BTF is the authority and a mismatch
is reported, not papered over.

One trap this script knows about: the symbol list is derived from the image *file*,
so it cannot contain a symbol whose address lies past the end of that file. Every
``.bss`` global is in that class (the .bss is not stored in the file at all). Absence
from the list therefore means "not in .text/.data/.rodata", not "not in kallsyms";
``symbolListCoverage`` and ``runtimeLookups`` say which names that affects.

Usage
    python derive_contract.py                       # regenerate, defaults below
    python derive_contract.py --out /tmp/x.json     # write elsewhere
    python derive_contract.py --inspect kprobe      # ad-hoc BTF dump, writes nothing

Exit codes
    0  contract written, every abiCheck matched
    2  contract written, at least one abiCheck MISMATCHED (a real finding: the
       contract carries the truth, the module source needs fixing)
    1  the evidence itself is unusable (missing BTF, missing struct, bad header)

Determinism: no timestamps, no absolute paths, fixed key order. Two runs on the
same inputs are byte-identical; README.md has the sha256 check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]

def display_path(path) -> str:
    """Repo-relative when possible, absolute otherwise.

    The contract records the files it was derived from so the builder can refuse a
    mismatch. Recording the *default* paths instead of the ones actually passed made a
    second release's contract claim a different image and a different symbol table -
    every gate then compared against the wrong kernel.
    """
    path = Path(path).resolve()
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


IMAGE_REL = ".analysis/ace6-20261025/boot/kernel"
SYMBOLS_REL = ".analysis/skroot-pro-20261028/scratch/symbols-gki6689.tsv"
MODULE_DIR_REL = "jailbreak-providers/root-loader/module"

# --------------------------------------------------------------------------- #
# BTF: a straight reimplementation of the kernel's own format (include/uapi/
# linux/btf.h). Type ids are 1-based; id 0 is void.
# --------------------------------------------------------------------------- #

BTF_MAGIC = b"\x9f\xeb\x01\x00"

K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION = 1, 2, 3, 4, 5
K_ENUM, K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST = 6, 7, 8, 9, 10
K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC = 11, 12, 13, 14, 15
K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64 = 16, 17, 18, 19

KIND_NAMES = {
    K_INT: "INT", K_PTR: "PTR", K_ARRAY: "ARRAY", K_STRUCT: "STRUCT",
    K_UNION: "UNION", K_ENUM: "ENUM", K_FWD: "FWD", K_TYPEDEF: "TYPEDEF",
    K_VOLATILE: "VOLATILE", K_CONST: "CONST", K_RESTRICT: "RESTRICT",
    K_FUNC: "FUNC", K_FUNC_PROTO: "FUNC_PROTO", K_VAR: "VAR",
    K_DATASEC: "DATASEC", K_FLOAT: "FLOAT", K_DECL_TAG: "DECL_TAG",
    K_TYPE_TAG: "TYPE_TAG", K_ENUM64: "ENUM64",
}


def die(message: str) -> "SystemExit":
    print("derive_contract: " + message, file=sys.stderr)
    raise SystemExit(1)


class Type:
    """One BTF type. `members` is only filled for STRUCT/UNION."""

    __slots__ = ("tid", "name", "kind", "vlen", "kflag", "size", "members", "extra")

    def __init__(self, tid, name, kind, vlen, kflag, size):
        self.tid = tid
        self.name = name
        self.kind = kind
        self.vlen = vlen
        self.kflag = kflag
        self.size = size
        self.members = []      # (name, type_id, bit_offset, bit_size)
        self.extra = None      # ARRAY: (elem, index, nelems); VAR/FUNC: type id


class Btf:
    def __init__(self, image: bytes):
        offset = image.find(BTF_MAGIC)
        if offset < 0:
            die("no .BTF magic in the image")
        (magic, version, flags, hdr_len, type_off, type_len, str_off,
         str_len) = struct.unpack_from("<HBBIIIII", image, offset)
        if magic != 0xEB9F:
            die("BTF magic bytes do not decode to 0xeb9f")
        base = offset + hdr_len
        if base + type_off + type_len > len(image):
            die("BTF type section runs past the end of the image")
        if base + str_off + str_len > len(image):
            die("BTF string section runs past the end of the image")
        self.magic_offset = offset
        self.version = version
        self.flags = flags
        self.hdr_len = hdr_len
        self.type_bytes = image[base + type_off: base + type_off + type_len]
        self.strings = image[base + str_off: base + str_off + str_len]
        self.blob_bytes = hdr_len + type_off + type_len + str_len
        self.types = self._parse()

    def string(self, off: int) -> str:
        if off == 0:
            return ""
        end = self.strings.find(b"\x00", off)
        if end < 0:
            return ""
        return self.strings[off:end].decode("utf-8", "replace")

    def _parse(self):
        out = [None]  # type id 0 == void, never a member/var type
        p, n = 0, len(self.type_bytes)
        buf = self.type_bytes
        while p < n:
            if p + 12 > n:
                die("truncated BTF type record at byte %d" % p)
            name_off, info, size_type = struct.unpack_from("<III", buf, p)
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = (info >> 31) & 1
            rec = Type(len(out), self.string(name_off), kind, vlen, kflag, size_type)
            p += 12
            if kind == K_INT:
                p += 4
            elif kind == K_ARRAY:
                elem, index, nelems = struct.unpack_from("<III", buf, p)
                rec.extra = (elem, index, nelems)
                p += 12
            elif kind in (K_STRUCT, K_UNION):
                for _ in range(vlen):
                    m_name, m_type, m_off = struct.unpack_from("<III", buf, p)
                    p += 12
                    if kflag:
                        bit_off, bit_sz = m_off & 0xFFFFFF, m_off >> 24
                    else:
                        bit_off, bit_sz = m_off, 0
                    rec.members.append(
                        (self.string(m_name), m_type, bit_off, bit_sz))
            elif kind == K_ENUM:
                p += 8 * vlen
            elif kind == K_FUNC_PROTO:
                p += 8 * vlen
            elif kind == K_VAR:
                rec.extra = size_type
                p += 4
            elif kind == K_DATASEC:
                entries = []
                for _ in range(vlen):
                    entries.append(struct.unpack_from("<III", buf, p))
                    p += 12
                rec.extra = entries
            elif kind == K_DECL_TAG:
                rec.extra = size_type
                p += 4
            elif kind == K_ENUM64:
                p += 12 * vlen
            elif kind in (K_PTR, K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST,
                          K_RESTRICT, K_FUNC, K_FLOAT, K_TYPE_TAG):
                rec.extra = size_type          # referenced type id
            else:
                die("unknown BTF kind %d at type id %d" % (kind, len(out)))
            out.append(rec)
        return out

    def named(self, name: str, kind: int | None = None):
        hits = []
        for rec in self.types:
            if rec is None or rec.name != name:
                continue
            if kind is None or rec.kind == kind:
                hits.append(rec)
        return hits

    def one_struct(self, name: str) -> Type:
        hits = self.named(name, K_STRUCT)
        if not hits:
            die("BTF has no struct %s" % name)
        first = hits[0]
        for other in hits[1:]:
            if other.size != first.size or \
                    [(m[0], m[2]) for m in other.members] != \
                    [(m[0], m[2]) for m in first.members]:
                die("struct %s has conflicting BTF layouts (ids %d and %d)"
                    % (name, first.tid, other.tid))
        return first

    def describe(self, tid: int) -> dict:
        """Shallow, deterministic description of a referenced type."""
        rec = self.types[tid] if 0 < tid < len(self.types) else None
        if rec is None:                    # id 0: void
            return {"kind": "VOID", "name": "", "typeId": tid}
        out = {"kind": KIND_NAMES.get(rec.kind, "?"), "name": rec.name,
               "typeId": tid}
        if rec.kind == K_ARRAY and rec.extra:
            elem, _index, nelems = rec.extra
            out["arrayOf"] = self.describe(elem)
            out["elements"] = nelems
        elif rec.kind in (K_PTR, K_TYPEDEF, K_CONST, K_VOLATILE, K_RESTRICT) \
                and rec.extra:
            out["refers"] = self.describe(rec.extra)
        elif rec.kind in (K_STRUCT, K_UNION, K_ENUM) and rec.size:
            out["size"] = rec.size
        return out

    def base_name(self, tid: int) -> str:
        """Walk pointers/qualifiers/typedefs/arrays to the first named type."""
        seen = 0
        while 0 < tid < len(self.types) and seen < 32:
            rec = self.types[tid]
            if rec.name:
                return rec.name
            if rec.kind == K_ARRAY and rec.extra:
                tid = rec.extra[0]
            elif rec.kind in (K_PTR, K_TYPEDEF, K_CONST, K_VOLATILE,
                              K_RESTRICT) and rec.extra:
                tid = rec.extra
            else:
                return ""
            seen += 1
        return ""

    def layout(self, struct: Type) -> list:
        members = []
        for name, tid, bit_off, bit_sz in struct.members:
            entry = {
                "name": name,
                "typeId": tid,
                "typeKind": KIND_NAMES.get(self.types[tid].kind, "?")
                if 0 < tid < len(self.types) else "VOID",
                "typeName": self.base_name(tid),
                "bitOffset": bit_off,
                "byteOffset": bit_off // 8,
                "byteOffsetHex": "0x%x" % (bit_off // 8),
            }
            if bit_sz:
                entry["bitSize"] = bit_sz
            described = self.describe(tid)
            if "elements" in described:
                entry["elements"] = described["elements"]
            members.append(entry)
        return members

    def offset_of(self, struct: Type, member: str) -> int | None:
        for name, _tid, bit_off, _bit_sz in struct.members:
            if name == member:
                return bit_off // 8
        return None

    def member_covering(self, struct: Type, byte_offset: int):
        """The member whose span contains `byte_offset`, or None."""
        best = None
        for name, _tid, bit_off, _bit_sz in struct.members:
            start = bit_off // 8
            if start <= byte_offset and (best is None or start > best[1]):
                best = (name, start)
        return best[0] if best else None


# --------------------------------------------------------------------------- #
# Image facts: vermagic, IKCONFIG, KCFI immediate.
# --------------------------------------------------------------------------- #

# kernel/module/version.c emits this section; the tail after the release is what
# same_magic() compares once a module carries __versions.
VERMAGIC_TAIL = b" SMP preempt mod_unload modversions aarch64\x00"


def read_vermagic(image: bytes) -> tuple:
    end = image.find(VERMAGIC_TAIL)
    if end < 0:
        die("vermagic tail %r not found in the image" % VERMAGIC_TAIL)
    start = end
    while start > 0 and 0x20 <= image[start - 1] <= 0x7E:
        start -= 1
    text = image[start:end + len(VERMAGIC_TAIL) - 1].decode()
    return text, {"fileOffset": start, "fileOffsetHex": "0x%x" % start,
                  "tailOccurrences": image.count(VERMAGIC_TAIL),
                  "method": "first occurrence of the ' SMP preempt mod_unload "
                            "modversions aarch64' tail, scanned back to the first "
                            "non-printable byte (same rule as "
                            "ir-loader/tests/loader_contract.py:kernel_vermagic)"}


def read_config(image: bytes) -> dict:
    """CONFIG_IKCONFIG: 'IKCFG_ST' + gzip stream + 'IKCFG_ED' inside the image."""
    start = image.find(b"IKCFG_ST")
    if start < 0:
        die("no IKCONFIG blob in the image: the CONFIG_* evidence cannot be derived")
    end = image.find(b"IKCFG_ED", start)
    if end < 0:
        die("IKCFG_ST present but IKCFG_ED missing")
    blob = image[start + 8:end]
    try:
        text = zlib.decompressobj(31).decompress(blob).decode("utf-8", "replace")
    except zlib.error as exc:
        die("embedded kernel config is not a readable gzip stream: %s" % exc)
    values = {}
    for line in text.splitlines():
        if line.startswith("# ") and line.endswith(" is not set"):
            values[line[2:-len(" is not set")].strip()] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    return {"blobOffset": start, "blobOffsetHex": "0x%x" % start,
            "compressedBytes": len(blob), "plainBytes": len(text),
            "lines": len(text.splitlines()), "values": values}


# MOVK Wd, #imm16{, LSL #shift}
def _movk(rd: int, imm: int, hw: int) -> int:
    return 0x72800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | (rd & 0x1F)


def find_kcfi_site(image: bytes) -> list:
    """Every clang kCFI type-check sequence, with the type id decoded.

    clang builds the expected type hash in w17 with two MOVKs, compares it against
    the 32-bit hash stored before the callee, and jumps over a trap:

        movk w17, #lo
        movk w17, #hi, lsl #16
        cmp  w1?, w17
        b.eq +8
        brk  #imm
        blr  xN

    Matching the whole six-instruction shape (not just the MOVK pair, which occurs
    wherever any 32-bit constant is materialised) is what makes the type id
    evidence rather than a coincidence. The id is read out of the image, never
    copied from prior evidence.
    """
    hits = []
    shape_lo = _movk(17, 0, 0) & 0xFFE0001F
    shape_hi = _movk(17, 0, 1) & 0xFFE0001F
    unpack = struct.unpack_from
    limit = len(image) - 24
    for off in range(0, limit, 4):
        lo = unpack("<I", image, off)[0]
        if (lo & 0xFFE0001F) != shape_lo:
            continue
        hi = unpack("<I", image, off + 4)[0]
        if (hi & 0xFFE0001F) != shape_hi:
            continue
        # The 3-word tail is what distinguishes a kCFI check from ordinary code.
        if unpack("<I", image, off + 12)[0] != 0x54000040:      # b.eq +8
            continue
        if (unpack("<I", image, off + 16)[0] & 0xFFE0001F) != 0xD4200000:  # brk
            continue
        if (unpack("<I", image, off + 20)[0] & 0xFFFFFC1F) != 0xD63F0000:  # blr
            continue
        imm_lo = (lo >> 5) & 0xFFFF
        imm_hi = (hi >> 5) & 0xFFFF
        compare = unpack("<I", image, off + 8)[0]
        hits.append({
            "fileOffset": off,
            "fileOffsetHex": "0x%x" % off,
            "lowImmediate": "0x%04x" % imm_lo,
            "highImmediate": "0x%04x" % imm_hi,
            "typeId": "0x%08x" % ((imm_hi << 16) | imm_lo),
            "instructions": [
                "0x%08x  movk w17, #0x%04x" % (lo, imm_lo),
                "0x%08x  movk w17, #0x%04x, lsl #16" % (hi, imm_hi),
                "0x%08x  cmp  (w1x, w17)" % compare,
                "0x%08x  b.eq +8" % unpack("<I", image, off + 12)[0],
                "0x%08x  brk  #0x%x" % (unpack("<I", image, off + 16)[0],
                                        (unpack("<I", image, off + 16)[0] >> 5) & 0xFFFF),
                "0x%08x  blr  x%d" % (unpack("<I", image, off + 20)[0],
                                      (unpack("<I", image, off + 20)[0] >> 5) & 0x1F),
            ],
        })
    return hits


# --------------------------------------------------------------------------- #
# kallsyms TSV.
# --------------------------------------------------------------------------- #

class Symbols:
    def __init__(self, path: Path):
        self.path = path
        self.entries = []
        self.by_name = {}
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            entry = {"line": lineno, "offset": int(parts[0], 10),
                     "type": parts[1], "name": "\t".join(parts[2:]),
                     "text": line}
            self.entries.append(entry)
            self.by_name.setdefault(entry["name"], []).append(entry)

    def __len__(self) -> int:
        return len(self.entries)

    def hits(self, name: str) -> list:
        return self.by_name.get(name, [])

    def first(self, name: str):
        found = self.by_name.get(name)
        return found[0] if found else None

    def names_of_type(self, symbol_type: str) -> set:
        return {e["name"] for e in self.entries if e["type"] == symbol_type}

    def max_offset(self) -> int:
        return max(e["offset"] for e in self.entries)

    def next_offset(self, offset: int):
        """The smallest listed address strictly above `offset` (function extent)."""
        best = None
        for entry in self.entries:
            if entry["offset"] > offset and (best is None or entry["offset"] < best):
                best = entry["offset"]
        return best

    def containing_text(self, offset: int):
        """Nearest TEXT symbol at or below `offset` (same address space)."""
        best = None
        for entry in self.entries:
            if entry["type"] != "TEXT" or entry["offset"] > offset:
                continue
            if best is None or entry["offset"] > best["offset"]:
                best = entry
        return best


def symbol_block(entry) -> dict | None:
    if entry is None:
        return None
    return {"address": entry["offset"],
            "addressHex": "0x%x" % entry["offset"],
            "type": entry["type"], "tsvLine": entry["line"],
            "tsvText": entry["text"]}


# --------------------------------------------------------------------------- #
# What the module needs, and why. The `symbolClass` field is the module's own
# intent (a function it calls vs a data object it writes), not a kernel fact.
# --------------------------------------------------------------------------- #

REQUIRED_SYMBOLS = [
    ("register_kprobe", True,
     "step 1: resolve kallsyms_lookup_name through a kprobe"),
    ("unregister_kprobe", True, "step 1: remove the temporary kprobe"),
    ("_printk", False, "diagnostics on every failure path"),
    ("call_usermodehelper", False,
     "step 4: start the helper as kernel-domain root"),
]

OPTIONAL_SYMBOLS = [
    ("memset", False,
     "not referenced: maplesu_root.c zeroes the probe with an explicit byte loop "
     "and the build uses -fno-builtin; carried so a future build that lowers the "
     "loop to memset still has a checked import"),
]

RUNTIME_LOOKUPS = [
    ("kallsyms_lookup_name", "function",
     "the resolver itself, obtained from kprobe.addr", "critical"),
    ("selinux_state", "data",
     "step 2: address of the enforcing byte", "critical"),
    ("call_usermodehelper_setup", "function",
     "step 4 primary: allocate the subprocess_info the exec stage consumes; it is in "
     "kallsyms but not in __ksymtab (CONFIG_TRIM_UNUSED_KSYMS), which is exactly why "
     "the two-stage handover is a lookup and not an import", "critical"),
    ("call_usermodehelper_exec", "function",
     "step 4 primary: fork the helper from the subprocess_info whose path we restored "
     "-- without this call the module cannot exec anything on this image", "critical"),
    ("aarch64_insn_patch_text", "function",
     "step 3: patch vendor handlers to return 0 (compiled out by default)", "advisory"),
    ("oplus_exe_block_ret_handler", "function", "step 3 vendor handler", "advisory"),
    ("oplus_root_check_post_handler", "function", "step 3 vendor handler",
     "advisory"),
    ("task_defex_enforce", "function", "step 3 vendor handler", "advisory"),
    ("task_defex_user_exec", "function", "step 3 vendor handler", "advisory"),
]

FORBIDDEN_SYMBOLS = [
    ("call_usermodehelper_setup",
     "must never be *imported*: it has no __ksymtab entry on this build, so an import "
     "fails with 'Unknown symbol'. The module reaches it through kallsyms instead "
     "(runtimeLookups), and the four-argument wrapper stays as the documented "
     "fallback import"),
    ("call_usermodehelper_exec",
     "same: not exported, so it is a runtime lookup, never an import"),
    ("security_setenforce",
     "flipping the byte directly is the handover path; the setter is not in this "
     "build at all"),
    ("selinux_enforcing",
     "not a symbol on this kernel at all; the state lives in struct selinux_state"),
]

CONFIG_KEYS = [
    ("cfi", "CONFIG_CFI_CLANG", True,
     "kernel control-flow integrity: init_module must carry the int(void) KCFI id"),
    ("staticUsermodehelper", "CONFIG_STATIC_USERMODEHELPER", True,
     "every usermodehelper runs through one build-time path; with the path below set "
     "to the empty string, call_usermodehelper_setup() overwrites the caller's path "
     "with \"\" and the four-argument call_usermodehelper() becomes a silent no-op"),
    ("shadowCallStack", "CONFIG_SHADOW_CALL_STACK", True,
     "return-address signing: a patched function may end in RETAA/RETAB, so the "
     "patch must not assume a plain RET"),
    ("modversions", "CONFIG_MODVERSIONS", True,
     "the loader compares vermagic and consults __versions"),
    ("trimUnusedKsyms", "CONFIG_TRIM_UNUSED_KSYMS", True,
     "unused exports are dropped at build time, which is why "
     "call_usermodehelper_setup/_exec are absent from __ksymtab"),
    ("btf", "CONFIG_DEBUG_INFO_BTF", True,
     "the image's .BTF is the layout authority this contract is built on"),
    ("kallsymsAll", "CONFIG_KALLSYMS_ALL", True,
     "data symbols are in kallsyms, so a data name can be resolved by "
     "kallsyms_lookup_name -- which is what makes the .bss blind spot below "
     "matter"),
    ("moduleSig", "CONFIG_MODULE_SIG", True,
     "modules are signed at build time (CONFIG_MODULE_SIG_ALL=y)"),
    ("moduleSigForce", "CONFIG_MODULE_SIG_FORCE", False,
     "signature enforcement is off, so an unsigned module is still loadable -- "
     "this is the fact the whole design depends on"),
    ("moduleForceLoad", "CONFIG_MODULE_FORCE_LOAD", False,
     "force-load is off: vermagic must match exactly, there is no override"),
    ("selinux", "CONFIG_SECURITY_SELINUX", True, "SELinux is built in"),
    ("selinuxDevelop", "CONFIG_SECURITY_SELINUX_DEVELOP", True,
     "struct selinux_state carries the `enforcing` bool only when this is set"),
    ("randstruct", "CONFIG_RANDSTRUCT_NONE", True,
     "member order is declaration order, so BTF offsets are stable for this build"),
    ("lto", "CONFIG_LTO_NONE", True,
     "no LTO: symbol names and function bodies are as written, not internalised"),
]

# --------------------------------------------------------------------------- #
# L2: the second, separately unloadable hook module.
#
# Design: docs/patching/maplesu-l2-hook-framework-design-2026-10-29.md (rev-2) with
# the must-fix list of docs/patching/maplesu-l2-ready-review-2026-10-29.md §11.
# The discipline is the one used above: the two struct layouts come from BTF, the
# KCFI ids are *claims* checked against the image's own compare sites, and every
# list that a gate asserts on (six imports, three lookups, three ids, the config
# facts) is enumerated here so a gate can compare against this contract.
#
# There is deliberately no per-release address in the L2 block: the three runtime
# lookups carry their kallsyms row as *evidence*, and the contract says, in the
# same field, that the module must resolve them at run time and that a literal
# address in module text is a G11 failure. This is the existing policy for
# selinux_state/call_usermodehelper_* and it is not relaxed here.
# --------------------------------------------------------------------------- #

L2_MODULE_NAME = "maplesu_l2"
L2_MODULE_FILE = "maplesu_l2.ko"
L2_MODULE_SOURCE = "module/maplesu_l2.c"
L2_GLUE_TEMPLATE = "module/root_glue_l2.S.in"

# Six imports, every one of them confirmed in __ksymtab (checked below, not assumed).
# The split from the lookups is not cosmetic: see L2_IMPORT_NO_KCFI.
L2_IMPORTS = [
    ("register_kprobe",
     "H1/H5: arm the control-channel probe and the execve entry probe"),
    ("register_kretprobe",
     "H5: arm the return probe (also L3's return-value rewrite face)"),
    ("unregister_kprobe",
     "reverse-order disarm; cleanup_module's undo step"),
    ("unregister_kretprobe", "same, for the return probe"),
    ("_printk",
     "the module's own state transitions, <= 8 lines per attempt"),
    ("copy_from_kernel_nofault",
     "H4 kread: a bad address is -EFAULT, never an oops"),
]

L2_IMPORT_NO_KCFI = (
    "none of the six carries a KCFI type signature. The 4 bytes before each entry "
    "point (recorded per import as kcfiPrefix) are not one of the type ids any "
    "compare site in this image builds, i.e. the function has no __cfi_ prefix. An "
    "indirect call to it from a *sanitised* function therefore compares garbage "
    "against garbage and takes brk #0x8228, which is a panic under "
    "CONFIG_PANIC_ON_OOPS=y. An import goes through the PLT with no type check at "
    "all, which is why these six are imports and only the three unexported names "
    "below are runtime lookups. This is the reverse direction of the __nocfi "
    "asymmetry used by the root module (callers of *resolved* pointers are "
    "__nocfi; callbacks invoked *by* the kernel keep their prefix)."
)

L2_RUNTIME_LOOKUPS = [
    ("__arm64_sys_ni_syscall", "function",
     "H1 carrier: the function the sys_call_table slots 453..461 point at. The "
     "kprobe is installed on it, and ARM re-reads sys_call_table[scno] to prove the "
     "number is still unimplemented on this boot (else -EINVAL, "
     "MA_L2_SCNO_NOT_UNIMPLEMENTED)", "critical"),
    ("sys_call_table", "data",
     "the ARM-time self-check reads one 8-byte slot of this table. The table is "
     "never written: no set_memory_rw, no text_poke, no sys_call_table store", "critical"),
    ("copy_to_user_nofault", "function",
     "the control channel returns its 32-byte result block with this; the sleeping "
     "copy_to_user cannot be used in kprobe context", "critical"),
]

# M6's cookie channel (design §3.1.2) is a *second*, documented increment on top of
# M4's six imports: the helper passes `cookie=0x<16 hex>` as finit_module's uargs, the
# module catches it with one `__param` row whose `ops` is `&param_ops_ullong`, and that
# ops object is exported. The six stay the M4 set; this one is recorded separately so
# neither review item is silently rewritten. O6 asserts the *complete* undefined set
# (six + this) and that the delta is exactly this symbol.
L2_COOKIE_CHANNEL = {
    "source": "finit_module uargs (design §3.1.2, must-fix M6)",
    "uargs": "cookie=0x<16 hex>",
    "param": "cookie",
    "paramType": "ullong",
    "paramOps": "param_ops_ullong",
    "modinfoParm": "parm=cookie:ullong",
    "section": "__param",
    "rows": 1,
    "perm": 0,
    "why": "the cookie arrives from the loader only: finit_module's uargs are supplied "
           "by the process that loads the module (the helper, inside the window), so "
           "no other process can know it and OP_ARM can require cookie == "
           "l2.load_cookie instead of accepting whoever calls first (R-L2-14)",
    "failureSemantics": "a missing or zero cookie makes init_module return -EINVAL "
                        "(nothing is armed) and the helper records MA_L2_NO_COOKIE; a "
                        "zero-cookie module that somehow loads refuses every ARM with "
                        "-EPERM",
    "notExercised": "NOT_EXERCISED on device: neither __param nor finit_module uargs "
                    "has ever run on this hardware (design §7.3)",
}

L2_COOKIE_PARAM_SYMBOL = "param_ops_ullong"

# The KCFI type ids the L2 callbacks must carry. Each is a claim checked at
# regeneration time against the compare sites inside the functions that make the
# indirect call - the id is only in the contract because the image agrees.
#   fields: key, claim, anchor functions, struct carrying the callback member,
#           member name, declaration (kernel names), meaning
L2_KCFI_CLAIMS = [
    ("preHandler", 0xA6BE5DD9, ("aggr_pre_handler", "kprobe_breakpoint_handler"),
     "kprobe", "pre_handler",
     "int (*)(struct kprobe *, struct pt_regs *)",
     "kprobe_pre_handler_t: the kprobe pre-handler the kernel indirect-calls at "
     "every probe site; l2_pre_execve and l2_pre_ctl must carry exactly this id"),
    ("postHandler", 0x6E21B9C7, ("kprobe_breakpoint_handler",),
     "kprobe", "post_handler",
     "void (*)(struct kprobe *, struct pt_regs *, unsigned long)",
     "kprobe_post_handler_t: the optional post-handler (l2_post_execve, if C1 keeps "
     "it); same dispatch site as the pre-handler"),
    ("kretprobeHandler", 0x8078BE15,
     ("__kretprobe_trampoline_handler", "pre_handler_kretprobe"),
     "kretprobe", "handler",
     "int (*)(struct kretprobe_instance *, struct pt_regs *)",
     "kretprobe_handler_t: rp->handler@+0x80 and rp->entry_handler@+0x88 share it; "
     "l2_ret_execve must carry exactly this id"),
]

# The declarations whose *compiler output* is the evidence for the ids above, plus
# the shim-named spellings the design forbids in a callback prototype. The ids in
# this block are measurements, not image facts: they are reproduced (and asserted)
# by tests/test_l2_contract.py with the repo's clang and the L2 flag set.
L2_DECLARATION_CHECK = {
    "why": "clang's KCFI type id is a hash of the function type, and a pointer to a "
           "struct contributes the *record name*. Two otherwise identical "
           "prototypes that differ only in the struct name therefore get different "
           "ids, so a callback declared with a shim struct name would compare "
           "against the wrong id and trap on its first call. That is the whole "
           "reason L2 callback prototypes must use the kernel's struct names.",
    "method": "compile one TU per case with the repo's L2 flag set, read the 4 bytes "
              "before the callback's entry point (that is the __cfi_ prefix clang "
              "emits), and compare with the image's compare-site id",
    "compiler": "Android NDK r28c clang 19.0.1 (r530567e)",
    "flags": ["--target=aarch64-linux-gnu", "-ffreestanding", "-nostdlib",
              "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-ffixed-x18",
              "-mgeneral-regs-only", "-mno-outline-atomics", "-fsanitize=kcfi",
              "-O2", "-c"],
    "reproduce": "jailbreak-providers/root-loader/tests/test_l2_contract.py "
                 "(skips when the NDK is absent)",
    "cases": [
        {"case": "preHandler.kernelNames", "typeId": "0xa6be5dd9",
         "declaration": "int (*)(struct kprobe *, struct pt_regs *)",
         "expects": "equals kcfiIds.preHandler.value"},
        {"case": "postHandler.kernelNames", "typeId": "0x6e21b9c7",
         "declaration": "void (*)(struct kprobe *, struct pt_regs *, unsigned long)",
         "expects": "equals kcfiIds.postHandler.value"},
        {"case": "kretprobeHandler.kernelNames", "typeId": "0x8078be15",
         "declaration": "int (*)(struct kretprobe_instance *, struct pt_regs *)",
         "expects": "equals kcfiIds.kretprobeHandler.value"},
        {"case": "preHandler.shimNames", "typeId": "0x2b8cdf69",
         "declaration": "int (*)(struct maplesu_kprobe *, struct maplesu_pt_regs *)",
         "expects": "must differ from kcfiIds.preHandler.value (negative sample)"},
        {"case": "kretprobeHandler.shimNames", "typeId": "0xd27489d5",
         "declaration": "int (*)(struct maplesu_kretprobe_instance *, struct pt_regs *)",
         "expects": "must differ from kcfiIds.kretprobeHandler.value (negative sample)"},
    ],
    "note": "no_sanitize(\"kcfi\") on the callee does not remove the prefix (measured "
            "on this toolchain), so G8's 'callback keeps its prefix' rule must be a "
            "source/attribute check, not a prefix test",
}

L2_CONFIG_KEYS = [
    ("kprobes", "CONFIG_KPROBES", True,
     "register_kprobe/unregister_kprobe exist and are exported: the L2 primitive"),
    ("kretprobes", "CONFIG_KRETPROBES", True,
     "register_kretprobe/unregister_kretprobe exist and are exported: the return "
     "side of H5"),
    ("panicOnOops", "CONFIG_PANIC_ON_OOPS", True,
     "any oops/trap in a callback ends the boot: a wrong KCFI id or a bad kread is "
     "not a recoverable warning, it is an attempt-ending panic"),
    ("cfi", "CONFIG_CFI_CLANG", True,
     "every callback needs a correct 4-byte type prefix, and no indirect call may "
     "be emitted from a callback body"),
    ("functionTracer", "CONFIG_FUNCTION_TRACER", False,
     "not set: there is no ftrace function-hooking primitive on this image, which "
     "is why L2 is kprobe/kretprobe-only (the symbol table has no ftrace_caller, "
     "__fentry__, _mcount or register_ftrace_function either)"),
    ("kprobesOnFtrace", "CONFIG_KPROBES_ON_FTRACE", False,
     "impossible on this image: the option depends on CONFIG_KPROBES && "
     "CONFIG_DYNAMIC_FTRACE, and CONFIG_DYNAMIC_FTRACE is not set (only "
     "CONFIG_HAVE_DYNAMIC_FTRACE is). Probes here are BRK-based, so arming one "
     "writes exactly one BRK instruction word at the probe site and unregistering "
     "restores it"),
    ("dynamicFtrace", "CONFIG_DYNAMIC_FTRACE", False,
     "recorded because kprobesOnFtrace's impossibility is derived from it"),
]

L2_PROBE_TARGETS = [
    ("__arm64_sys_ni_syscall",
     "H1 control channel: a syscall number this boot has not implemented, so "
     "there is no ordinary traffic on the probe"),
    ("do_execveat_common",
     "H5 observation: exec entry (kprobe) and return (kretprobe); the callbacks only "
     "count, they never write regs"),
]

L2_CONTROL_ABI = {
    "freeze": "design §3.1.2 (op table) and its calling convention; L3 reuses the "
              "same channel and may not re-assign the registers",
    "carrier": "__arm64_sys_ni_syscall, reached only through an unimplemented "
               "syscall number",
    "call": "syscall(scno, op, a1, a2, a3, x5=result, x6=0, x7=cookie)",
    "registers": {
        "x0": "scno (the kernel proves it from pt_regs->syscallno, not from the "
              "caller's claim)",
        "x1": "op",
        "x2": "a1", "x3": "a2", "x4": "a3",
        "x5": "user pointer to the 32-byte result block (0 = no result wanted)",
        "x6": "reserved, must be 0 (a non-zero value is refused, which leaves room "
              "for an old kernel to reject a newer call)",
        "x7": "cookie (64-bit; written into the kernel by OP_ARM, which requires the "
              "value the helper injected through finit_module uargs at load time)",
    },
    "returns": "-ENOSYS always (the carrier's real return; the module never rewrites "
               "the syscall return value)",
    "resultBlock": {
        "bytes": 32,
        "layout": [
            {"offset": "0x00", "type": "u32", "name": "magic", "value": "0x4d415032"},
            {"offset": "0x04", "type": "i32", "name": "rc", "value": "0 or -errno"},
            {"offset": "0x08", "type": "u64", "name": "value"},
            {"offset": "0x10", "type": "u64", "name": "aux"},
            {"offset": "0x18", "type": "u32", "name": "hitsTotal"},
            {"offset": "0x1c", "type": "u32", "name": "state",
             "value": "bit0 armed, bit1 disarmed, bit2 module resident"},
        ],
    },
    "ops": [
        {"op": "0x01", "name": "ARM", "args": "a1 = cookie_lo, a2 = cookie_hi"},
        {"op": "0x02", "name": "PROBE", "args": "-"},
        {"op": "0x03", "name": "KREAD", "args": "a1 = addr, a2 = len (<= 32)"},
        {"op": "0x04", "name": "KWRITE", "args": "a1 = addr, a2 = value, a3 = tag"},
        {"op": "0x05", "name": "SELFTEST", "args": "-"},
        {"op": "0x06", "name": "HITS", "args": "-"},
        {"op": "0x07", "name": "DISARM", "args": "-"},
        {"op": "0x08", "name": "STATUS", "args": "-"},
    ],
    "magic": {"probe": "0x4d41504c45535531", "result": "0x4d415032"},
    "writeWhitelist": {
        "tags": ["WL_SCRATCH", "WL_SELINUX"],
        "rules": [
            "WL_SCRATCH writes the module's own .bss scratch and reads it back",
            "WL_SELINUX may write only the byte at selinux_state.enforcing and only "
            "the value it just read (a one-byte strb after the same-value compare); "
            "writing a different value would move the policy window, which L2 does "
            "not own",
            "anything else is -EACCES; there is no arbitrary kernel write",
        ],
        "forbidden": ["set_memory_rw", "apply_to_page_range",
                      "aarch64_insn_patch_text", "text_poke",
                      "copy_to_kernel_nofault"],
    },
}

# The gate namespace is a Lead decision (2026-10-29) and is recorded, not assumed:
# the R-D1 fix owns S21, so L2 takes S26-S40 / O6-O10 and L3 takes S41-S52. The
# design document still says S21-S30; a doc correction follows, and this block is
# what the gates and the tests compare against in the meantime.
L2_GATE_NAMESPACE = {
    "decision": "Lead namespace decision, 2026-10-29: no id is renumbered; L2 uses "
                "the ids the R-D1 fix left free",
    "hookContract": {
        "v5Baseline": {"source": "S1-S20", "object": "O1-O5"},
        "rD1Fix": {"source": "S21"},
        "reservedUnassigned": {"source": "S22-S25"},
        "l2": {"source": "S26-S40", "object": "O6-O10"},
        "l3": {"source": "S41-S52"},
    },
    "buildRootModule": {
        "v5Baseline": "G1-G7 (maplesu_root.ko)",
        "l2": "G8-G14 (maplesu_l2.ko; gates-first scaffolding in C0, gate bodies "
              "with C1/C2)",
    },
    "designDocumentMapping": {
        "designSays": {"source": "S21-S30", "object": "O6-O10"},
        "implementedAs": {"source": "S26-S40", "object": "O6-O10"},
        "reason": "S21 is owned by the R-D1 fix; S22-S25 stay free; L3 takes S41-S52",
    },
    "l2SourceChecks": [
        {"id": "S26", "asserts": "hook_l2 is called after hook_stage2 and before "
                                 "hook_daemon, guarded by l2_enabled (absence keeps "
                                 "step-4 behaviour)"},
        {"id": "S27", "asserts": "hook_l2 validates the staged maplesu_l2.ko "
                                 "(regular file, dir uid, mode 0077, nlink 1, ELF "
                                 "ET_REL/AArch64) before open/finit_module, and uses "
                                 "the named MAPLESU_NR_FINIT_MODULE constant"},
        {"id": "S28", "asserts": "--l2/--l2-required are parsed only in "
                                 "hook_parse_argv, and l2_required implies "
                                 "l2_enabled"},
        {"id": "S29", "asserts": "the \"l2\" key is written exactly once, inside "
                                 "hook_write_main_json, in the same single write()"},
        {"id": "S30", "asserts": "hook_verdict has the l2 branch (l2_required && "
                                 "l2_verdict != OK => FAILED) and never upgrades a "
                                 "verdict"},
        {"id": "S31", "asserts": "hook_l2 is clean under the extended forbidden "
                                 "table (mount(, BLKROSET, /sys/fs/selinux writes, "
                                 "the stage-1 irreversible steps)"},
        {"id": "S32", "asserts": "hook_l2 deletes the module only after a successful "
                                 "disarm, and reports disarm and unload separately"},
        {"id": "S33", "asserts": "the l2 evidence block names the three probe ids "
                                 "verbatim (ctl.magic, execve.entry, execve.ret)"},
        {"id": "S34", "asserts": "the helper never references "
                                 "check_traceless_invariants.py, and the frozen "
                                 "checks=26/digest constants live in the gate"},
        {"id": "S35", "asserts": "the helper emits only MA_L2_* tokens for L2 "
                                 "failures, and the l2 block is absent (not "
                                 "zero-filled) when L2 is not enabled"},
        {"id": "S36", "asserts": "the L2 module source and glue template exist with "
                                 "the frozen identity (name maplesu_l2, .modinfo "
                                 "name=maplesu_l2, init_module/cleanup_module)"},
        {"id": "S37", "asserts": "kernel_compat.h carries the L2 shims with "
                                 "BTF-derived _Static_asserts whose numbers equal "
                                 "this contract (kretprobe 0xb0/0x80/0x88/0x98, "
                                 "pt_regs syscallno 0x118)"},
        {"id": "S38", "asserts": "the four L2 callback prototypes use kernel struct "
                                 "names, carry no no_sanitize(\"kcfi\"), and the "
                                 "resolver-calling helpers are MAPLESU_NOCFI"},
        {"id": "S39", "asserts": "l2_kwrite has exactly the two whitelist tags, a "
                                 "same-value compare before the one-byte WL_SELINUX "
                                 "strb, and no text-mutation helper anywhere"},
        {"id": "S40", "asserts": "no per-release constant in the L2 source: no magic "
                                 "scno literal, the sys_call_table self-check line "
                                 "exists, scno only from regs->syscallno or the ARM "
                                 "argument, no kernel virtual address literal"},
    ],
    "l2ObjectChecks": [
        {"id": "O6", "asserts": "the L2 object's undefined set is exactly the six "
                                 "imports"},
        {"id": "O7", "asserts": "no text-mutation/patch helper is imported or "
                                 "referenced (set_memory_rw, apply_to_page_range, "
                                 "aarch64_insn_patch_text, text_poke)"},
        {"id": "O8", "asserts": "no policy/device write surface (/dev/df, BLKROSET, "
                                 "mount, security_setenforce, /sys/fs/selinux)"},
        {"id": "O9", "asserts": "no ksu/ksud/kernelsu string"},
        {"id": "O10", "asserts": "zero \"/data/\" literals, no magic scno materialised "
                                  "by movz/movk/cmp #imm, no kernel virtual address, "
                                  "and the write-scope skeleton: every str/strb "
                                  "outside l2_kwrite has a base that is sp, an own "
                                  "section symbol, or a caller pointer"},
    ],
}


def read_text(path: Path) -> str:
    if not path.is_file():
        die("missing source file %s" % path)
    return path.read_text(encoding="utf-8")


def search_hex(pattern: str, text: str) -> int | None:
    match = re.search(pattern, text)
    if not match:
        return None
    return int(match.group(1), 0)


def build_abi_checks(btf: Btf, module_struct: Type, kprobe: Type,
                     selinux: Type, module_dir: Path) -> dict:
    """Compare what the sources claim against what BTF says."""
    compat = read_text(module_dir / "kernel_compat.h")
    glue = read_text(module_dir / "root_glue.S.in")
    source = read_text(module_dir / "maplesu_root.c")

    claims = []

    def claim(abi, kind, source_rel, claimed, truth, quote):
        claims.append({
            "abi": abi,
            "kind": kind,
            "source": source_rel,
            "claimed": claimed if claimed is None else "0x%x" % claimed,
            "btf": truth if truth is None else "0x%x" % truth,
            "matches": (claimed is not None and truth is not None
                        and claimed == truth),
            # The templates express family-dependent numbers as tokens, so a claim
            # against one of them may be unparseable rather than wrong. Those two cases
            # must not be reported the same way: "unresolved" says nothing about the
            # image, "mismatch" says the source disagrees with it.
            # A few facts are genuinely per-family: the template carries the primary
            # family's literal and the builder renders the right one per image, so a
            # difference here is "not the template's claim to make", not a defect.
            "familyDependent": abi in {"selinuxState.initialized",
                                       "selinuxState.size", "kprobe.size"},
            "resolved": claimed is not None and not (
                abi in {"selinuxState.initialized", "selinuxState.size",
                        "kprobe.size"}
                and claimed != truth),
            "quote": quote,
        })

    # --- kernel_compat.h ------------------------------------------------- #
    kprobe_size = search_hex(
        r"sizeof\(struct maplesu_kprobe\)\s*==\s*(0x[0-9a-fA-F]+)", compat)
    kprobe_addr = search_hex(
        r"__builtin_offsetof\(struct maplesu_kprobe,\s*addr\)\s*==\s*(0x[0-9a-fA-F]+)",
        compat)
    kprobe_sym = search_hex(
        r"__builtin_offsetof\(struct maplesu_kprobe,\s*symbol_name\)\s*==\s*(0x[0-9a-fA-F]+)",
        compat)
    selinux_size = search_hex(
        r"sizeof\(struct maplesu_selinux_state\)\s*==\s*(0x[0-9a-fA-F]+)", compat)
    enforcing = search_hex(r"u8 enforcing;\s*/\*\s*\+(0x[0-9a-fA-F]+)", compat)
    initialized = search_hex(r"u8 initialized;\s*/\*\s*\+(0x[0-9a-fA-F]+)", compat)

    claim("kprobe.size", "struct-size", "module/kernel_compat.h", kprobe_size,
          kprobe.size,
          "_Static_assert(sizeof(struct maplesu_kprobe) == 0x80, ...)")
    claim("kprobe.addr", "member-offset", "module/kernel_compat.h", kprobe_addr,
          btf.offset_of(kprobe, "addr"),
          "_Static_assert(__builtin_offsetof(struct maplesu_kprobe, addr) == 0x28, ...)")
    claim("kprobe.symbol_name", "member-offset", "module/kernel_compat.h",
          kprobe_sym, btf.offset_of(kprobe, "symbol_name"),
          "_Static_assert(__builtin_offsetof(struct maplesu_kprobe, symbol_name) == 0x30, ...)")
    claim("selinuxState.size", "struct-size", "module/kernel_compat.h",
          selinux_size, selinux.size,
          "_Static_assert(sizeof(struct maplesu_selinux_state) == 0x80, ...)")
    claim("selinuxState.enforcing", "member-offset", "module/kernel_compat.h",
          enforcing, btf.offset_of(selinux, "enforcing"),
          "u8 enforcing;             /* +0x00 */")
    claim("selinuxState.initialized", "member-offset", "module/kernel_compat.h",
          initialized, btf.offset_of(selinux, "initialized"),
          "u8 initialized;           /* +0x01 */")

    # --- root_glue.S.in -------------------------------------------------- #
    name_off = search_hex(r"\.zero\s+(0x[0-9a-fA-F]+)\s*\n\s*\.asciz", glue)
    init_off = search_hex(r"/\*\s*\+(0x[0-9a-fA-F]+)\s+init\s*\*/", glue)
    exit_off = search_hex(r"/\*\s*\+(0x[0-9a-fA-F]+)\s+exit", glue)
    total = search_hex(r"\.zero\s+(0x[0-9a-fA-F]+)\s*-\s*0x5c0", glue)

    claim("thisModule.nameOffset", "member-offset", "module/root_glue.S.in",
          name_off, btf.offset_of(module_struct, "name"),
          '.zero 0x18 / .asciz "maplesu_root"  (name inside char[56])')
    claim("thisModule.initOffset", "member-offset", "module/root_glue.S.in",
          init_off, btf.offset_of(module_struct, "init"),
          ".quad init_module   /* +0x188 init */")
    claim("thisModule.exitOffset", "member-offset", "module/root_glue.S.in",
          exit_off, btf.offset_of(module_struct, "exit"),
          ".quad cleanup_module /* +0x5b8 exit: restore point on delete_module */")
    claim("thisModule.size", "struct-size", "module/root_glue.S.in", total,
          module_struct.size,
          ".zero 0x600 - 0x5c0  (the last field ends at sizeof(struct module))")

    # --- naming defects: same offsets, wrong kernel field names ---------- #
    # These are documentation defects, not ABI defects: the module only ever
    # touches addr/symbol_name/enforcing, and those are pinned above.
    defects = []
    for struct, block in ((kprobe, "maplesu_kprobe"),
                          (selinux, "maplesu_selinux_state")):
        body = re.search(r"struct %s \{(.*?)\n\};" % block, compat, re.S)
        if not body:
            continue
        for match in re.finditer(
                r"(\w+)(?:\[\d+\])?;\s*/\*\s*\+(0x[0-9a-fA-F]+)", body.group(1)):
            claimed_name, offset = match.group(1), int(match.group(2), 16)
            truth = btf.member_covering(struct, offset)
            if truth is not None and truth != claimed_name:
                defects.append({
                    "struct": block,
                    "offset": "0x%x" % offset,
                    "memberNameInSource": claimed_name,
                    "memberNameInBtf": truth,
                    "impact": "naming only: the byte offset and the field's size "
                              "agree, and the module never reads this slot",
                })

    mismatches = [c for c in claims if not c["matches"]]
    unresolved = [c for c in claims if not c.get("resolved", True)]
    real = [c for c in mismatches if c.get("resolved", True)]
    return {
        "status": ("mismatch" if real
                   else ("unresolved" if unresolved else "match")),
        "checked": len(claims),
        "mismatches": [c["abi"] for c in real],
        "unresolved": [c["abi"] for c in unresolved],
        "claims": claims,
        "documentationDefects": defects,
        "note": "BTF is the authority; a claimed value that differs from it is a "
                "module-source defect, not a contract defect",
    }


# --------------------------------------------------------------------------- #
# L2 derivation.
# --------------------------------------------------------------------------- #

def _ldr_member_offset(insn: int) -> int | None:
    """Byte offset of an `ldr xN,[xM,#imm]` / `ldr wN,[xM,#imm]` (unsigned imm12).

    Used to prove that the compare site the id was read from is the call site of the
    callback member the contract names: the load feeding the `blr` is the one that
    reads `kp->pre_handler` / `rp->handler`.
    """
    if (insn & 0xFFC00000) == 0xF9400000:          # LDR (immediate), 64-bit
        return ((insn >> 10) & 0xFFF) * 8
    if (insn & 0xFFC00000) == 0xB9400000:          # LDR (immediate), 32-bit
        return ((insn >> 10) & 0xFFF) * 4
    return None


def _flat_layout(btf: Btf, struct: Type, base_bit: int = 0, prefix: str = "") -> dict:
    """member name -> byte offset, with anonymous struct/union members expanded.

    `struct pt_regs` starts with an anonymous union whose `user_regs` member is
    `struct user_pt_regs`; regs/sp/pc/pstate live *inside* it, so a plain
    `Btf.layout()` cannot answer for them. The dotted names keep the path visible
    ("user_regs.sp"), which is also what makes the provenance quotable.
    """
    out = {}
    for name, tid, bit_off, _bit_sz in struct.members:
        offset = base_bit + bit_off
        rec = btf.types[tid] if 0 < tid < len(btf.types) else None
        nested = rec is not None and rec.kind in (K_STRUCT, K_UNION)
        if not name and nested:                     # anonymous member: descend
            out.update(_flat_layout(btf, rec, offset, prefix))
            continue
        label = (prefix + "." + name) if prefix else name
        out[label] = offset // 8
        if nested:
            out.update(_flat_layout(btf, rec, offset, label))
    return out


def _kcfi_sites_in(sites: list, image: bytes, symbols: "Symbols", function: str,
                   member_offset: int | None = None) -> list:
    """Every KCFI compare site inside `function`, with the members it loads.

    `memberLoadConfirmed` is the strong form of the evidence: some load within 0x80
    bytes before the compare reads exactly the member the contract names (for the
    pre-handler that is `ldr xN,[xM,#0x40]`, i.e. kp->pre_handler). The id alone
    proves the type; the load proves which call site in the dispatcher it is.
    """
    entry = symbols.first(function)
    if entry is None:
        return []
    end = symbols.next_offset(entry["offset"]) or entry["offset"] + 0x400
    out = []
    for site in sites:
        at = site["fileOffset"]
        if not (entry["offset"] <= at < end):
            continue
        offsets = []
        matched_at = None
        for back in range(4, 0x84, 4):
            if at - back < entry["offset"]:
                break
            value = _ldr_member_offset(struct.unpack_from("<I", image, at - back)[0])
            if value is None:
                continue
            offsets.append(value)
            if member_offset is not None and value == member_offset and matched_at is None:
                matched_at = back
        out.append({
            "function": function,
            "functionAddress": "0x%x" % entry["offset"],
            "functionOffsetHex": "0x%x" % (at - entry["offset"]),
            "compareSiteAddress": "0x%x" % at,
            "loadedMemberOffsetsHex": ["0x%x" % value for value in offsets],
            "memberLoadConfirmed": matched_at is not None,
            "memberLoadDistanceHex": None if matched_at is None else "0x%x" % matched_at,
            "instructions": site["instructions"],
            "typeId": site["typeId"],
        })
    return out


def _runtime_lookup(symbols: "Symbols", btf: Btf, coverage: dict, name: str,
                    symbol_class: str, why: str, severity: str) -> dict:
    """One runtime lookup row. Shared by the root and L2 blocks so the rules cannot
    drift: `listed` resolves, a data name missing from a clipped list is
    'bss-possible' and must be probed, anything else means the name is not there."""
    entry = symbols.first(name)
    ksymtab = symbols.first("__ksymtab_" + name)
    btf_kinds = sorted({KIND_NAMES[t.kind] for t in btf.named(name)})
    if entry is not None:
        status, lookup = "listed", "resolves"
        evidence = ("%s at 0x%x, not exported (no __ksymtab_%s): exactly the "
                    "case kallsyms_lookup_name exists for"
                    % (entry["type"], entry["offset"], name))
        must_probe, severity_out = False, "ok"
    elif symbol_class == "data" and coverage["clippedAtEof"]:
        status, lookup = "not-in-list-bss-possible", "unverified"
        evidence = ("no row in the symbol list, but this is a data name and the "
                    "list cannot contain .bss symbols (see "
                    "symbolListCoverage.bssBlindSpot); resolvability must be "
                    "confirmed on the device")
        must_probe, severity_out = True, severity
    elif symbol_class == "data":
        status, lookup = "not-in-kallsyms", "null"
        evidence = ("no row in the symbol list, and this list is not clipped at "
                    "EOF (so it would carry a .bss symbol): the name is not in "
                    "kallsyms and the lookup returns NULL")
        must_probe, severity_out = False, severity
    else:
        status, lookup = "not-in-build", "null"
        evidence = ("no row in the symbol list and no BTF type of this name: "
                    "this kernel was not built with it, so the lookup returns "
                    "NULL (the module's != NULL guard makes that a no-op)")
        must_probe, severity_out = False, severity
    return {
        "name": name,
        "symbolClass": symbol_class,
        "why": why,
        "status": status,
        "lookupResult": lookup,
        "inSymbolList": entry is not None,
        "symbolListRowsForName": len(symbols.hits(name)),
        "exported": ksymtab is not None,
        "inBtf": bool(btf_kinds),
        "btfKinds": btf_kinds,
        "symbol": symbol_block(entry),
        "severity": severity_out,
        "mustProbeOnDevice": must_probe,
        "evidence": evidence,
    }


def _export_class_row(symbols: "Symbols", name: str) -> dict | None:
    """The __ksymtab_<name> row, or None when the symbol is not exported."""
    return symbol_block(symbols.first("__ksymtab_" + name))


def build_l2_block(btf: Btf, symbols: "Symbols", image: bytes, config: dict,
                   sites: list, kcfi_init: dict, coverage: dict, vermagic: str,
                   module_struct: Type, kprobe: Type,
                   export_row) -> tuple:
    """The `l2` block plus `structOffsets.kretprobe` / `structOffsets.ptRegs`.

    Everything is derived here: the two layouts from BTF, the three ids from the
    image's compare sites, the six imports from __ksymtab, the three lookups from
    the kallsyms rows, and the config facts from the embedded IKCONFIG blob.
    """
    kretprobe = btf.one_struct("kretprobe")
    pt_regs = btf.one_struct("pt_regs")
    flat_kretprobe = _flat_layout(btf, kretprobe)
    flat_pt_regs = _flat_layout(btf, pt_regs)
    if "handler" not in flat_kretprobe or "entry_handler" not in flat_kretprobe:
        die("BTF struct kretprobe has no handler/entry_handler member")
    if "syscallno" not in flat_pt_regs:
        die("BTF struct pt_regs has no syscallno member")

    struct_offsets = {
        "kretprobe": {
            "btfTypeId": kretprobe.tid,
            "allBtfTypeIds": [t.tid for t in btf.named("kretprobe", K_STRUCT)],
            "size": kretprobe.size,
            "sizeHex": "0x%x" % kretprobe.size,
            "kp": flat_kretprobe.get("kp"),
            "kpHex": "0x%x" % flat_kretprobe["kp"],
            "handler": flat_kretprobe["handler"],
            "handlerHex": "0x%x" % flat_kretprobe["handler"],
            "entryHandler": flat_kretprobe["entry_handler"],
            "entryHandlerHex": "0x%x" % flat_kretprobe["entry_handler"],
            "maxactive": flat_kretprobe.get("maxactive"),
            "nmissed": flat_kretprobe.get("nmissed"),
            "dataSize": flat_kretprobe.get("data_size"),
            "dataSizeHex": "0x%x" % flat_kretprobe["data_size"],
            "freelist": flat_kretprobe.get("freelist"),
            "rph": flat_kretprobe.get("rph"),
            "members": btf.layout(kretprobe),
            "note": "kp@+0x0 is a struct kprobe, so the surrogate the module declares "
                    "must be at least 0xb0 bytes: the kernel writes the whole object, "
                    "including freelist/rph past data_size. handler and entry_handler "
                    "share one type (kretprobe_handler_t)",
        },
        "ptRegs": {
            "btfTypeId": pt_regs.tid,
            "allBtfTypeIds": [t.tid for t in btf.named("pt_regs", K_STRUCT)],
            "size": pt_regs.size,
            "sizeHex": "0x%x" % pt_regs.size,
            "regs": flat_pt_regs.get("user_regs.regs"),
            "regsPath": "anonymous union at +0x0 -> user_regs -> regs",
            "sp": flat_pt_regs.get("user_regs.sp"),
            "pc": flat_pt_regs.get("user_regs.pc"),
            "pstate": flat_pt_regs.get("user_regs.pstate"),
            "origX0": flat_pt_regs.get("orig_x0"),
            "syscallno": flat_pt_regs["syscallno"],
            "syscallnoHex": "0x%x" % flat_pt_regs["syscallno"],
            "syscallnoType": "s32",
            "members": btf.layout(pt_regs),
            "flatMembers": {key: "0x%x" % value
                            for key, value in sorted(flat_pt_regs.items())},
            "note": "syscallno is at 0x118, not at the end of the embedded "
                    "user_pt_regs (0x110): orig_x0 occupies 0x110. The module reads "
                    "regs->syscallno, never a per-release offset",
        },
    }

    # --- the three ids, each checked against the image's own compare sites ---- #
    image_ids = {site["typeId"] for site in sites}
    kcfi_ids = {}
    for key, claim, functions, struct_name, member, declaration, why in L2_KCFI_CLAIMS:
        member_offset = btf.offset_of(kprobe if struct_name == "kprobe" else kretprobe,
                                      member)
        call_sites = []
        for function in functions:
            call_sites.extend(_kcfi_sites_in(sites, image, symbols, function,
                                             member_offset))
        matching = [site for site in call_sites if int(site["typeId"], 16) == claim]
        kcfi_ids[key] = {
            "value": "0x%08x" % claim,
            "declaration": declaration,
            "structNames": re.findall(r"struct (\w+)", declaration),
            "member": {
                "struct": struct_name,
                "name": member,
                "offset": member_offset,
                "offsetHex": "0x%x" % member_offset,
                "btfTypeId": (kprobe if struct_name == "kprobe" else kretprobe).tid,
            },
            "anchorFunctions": list(functions),
            "anchorFunctionsFound": [name for name in functions
                                     if symbols.first(name) is not None],
            "callSites": call_sites,
            "callSitesWithThisId": matching,
            "memberLoadConfirmed": any(site["memberLoadConfirmed"]
                                       for site in matching),
            "provenance": "image-bytes: the compare site(s) above build this id "
                          "before the indirect call that loads the callback from "
                          "%s.%s (+0x%x)" % (struct_name, member, member_offset),
            "inImageTypeIdSet": "0x%08x" % claim in image_ids,
            "matches": bool(matching),
            "why": why,
        }
    kcfi_ids["init"] = {
        "value": kcfi_init["kcfiInitTypeId"],
        "declaration": "int (*)(void)",
        "provenance": "image-bytes (kcfiProvenance: %s at %s)"
                      % (kcfi_init.get("provenance"), kcfi_init.get("site", {}).get(
                          "fileOffsetHex")),
        "callSites": [] if not kcfi_init.get("site") else [{
            "compareSiteAddress": kcfi_init["site"]["fileOffsetHex"],
            "function": kcfi_init["site"].get("containingFunction"),
            "instructions": kcfi_init["site"].get("decoded"),
        }],
        "inImageTypeIdSet": kcfi_init["kcfiInitTypeId"] in image_ids,
        "matches": True,
        "why": "init_module's own entry prefix (unchanged from maplesu_root.ko); C1 "
               "must not add a second id for it",
    }
    kcfi_mismatches = sorted(key for key, value in kcfi_ids.items()
                             if not value["matches"])

    # --- six imports --------------------------------------------------------- #
    imports = []
    for name, why in L2_IMPORTS:
        entry = symbols.first(name)
        ksymtab = symbols.first("__ksymtab_" + name)
        if entry is None:
            die("L2 import %s is absent from the symbol list" % name)
        if ksymtab is None:
            die("L2 import %s has no __ksymtab_%s entry" % (name, name))
        prefix = "0x%08x" % struct.unpack_from("<I", image, entry["offset"] - 4)[0]
        imports.append({
            "name": name,
            "why": why,
            "imported": True,
            "required": True,
            "symbol": symbol_block(entry),
            "export": export_row(name),
            "kcfiPrefix": prefix,
            "kcfiSignature": prefix in image_ids,
            "kcfiEvidence": "the 4 bytes before the entry point are %s, which is not "
                            "one of the %d type ids a compare site in this image "
                            "builds" % (prefix, len(image_ids)),
        })
    imports_with_signature = [row["name"] for row in imports if row["kcfiSignature"]]

    # --- M6 cookie channel: the one documented increment on the M4 six ------- #
    # `param_ops_ullong` is a data object, so "KCFI signature" does not apply to it;
    # what matters is that it is exported (otherwise the __param row cannot link).
    cookie_entry = symbols.first(L2_COOKIE_PARAM_SYMBOL)
    cookie_ksymtab = symbols.first("__ksymtab_" + L2_COOKIE_PARAM_SYMBOL)
    if cookie_entry is None:
        die("L2 cookie param %s is absent from the symbol list"
            % L2_COOKIE_PARAM_SYMBOL)
    if cookie_ksymtab is None:
        die("L2 cookie param %s has no __ksymtab entry, so the __param row cannot "
            "link" % L2_COOKIE_PARAM_SYMBOL)
    cookie_import = {
        "name": L2_COOKIE_PARAM_SYMBOL,
        "why": "the __param row's `ops` pointer: without it the finit_module uargs "
               "cookie cannot be parsed, and the control channel loses its "
               "authentication (M6)",
        "imported": True,
        "required": True,
        "symbol": symbol_block(cookie_entry),
        "export": export_row(L2_COOKIE_PARAM_SYMBOL),
        "kcfiSignature": None,
        "kcfiEvidence": "not applicable: this is a data object (struct "
                        "kernel_param_ops), not a function, so it has no entry prefix "
                        "and no indirect-call check",
        "reviewTrace": "M4's six imports are unchanged; this seventh symbol is M6's "
                       "necessary increment and is recorded separately so neither "
                       "review item is silently rewritten",
    }
    kernel_param = btf.one_struct("kernel_param")
    kernel_param_ops = btf.one_struct("kernel_param_ops")
    flat_kernel_param = _flat_layout(btf, kernel_param)
    cookie_channel = dict(L2_COOKIE_CHANNEL)
    cookie_channel.update({
        "paramOpsExport": export_row(L2_COOKIE_PARAM_SYMBOL),
        "paramOpsAddress": symbol_block(cookie_entry),
        "kernelParam": {
            "btfTypeId": kernel_param.tid,
            "allBtfTypeIds": [t.tid for t in btf.named("kernel_param", K_STRUCT)],
            "size": kernel_param.size,
            "sizeHex": "0x%x" % kernel_param.size,
            "name": flat_kernel_param.get("name"),
            "mod": flat_kernel_param.get("mod"),
            "ops": flat_kernel_param.get("ops"),
            "perm": flat_kernel_param.get("perm"),
            "level": flat_kernel_param.get("level"),
            "flags": flat_kernel_param.get("flags"),
            "arg": flat_kernel_param.get("arg"),
            "members": btf.layout(kernel_param),
            "note": "the glue writes one row of this struct by hand (C1-6), so the "
                    "offsets must come from here, not from a hand-copied header",
        },
        "kernelParamOps": {
            "btfTypeId": kernel_param_ops.tid,
            "size": kernel_param_ops.size,
            "sizeHex": "0x%x" % kernel_param_ops.size,
            "members": btf.layout(kernel_param_ops),
            "note": "recorded for the audit trail: the module never writes this "
                    "struct, it only points at the kernel's own param_ops_ullong",
        },
    })
    import_set_full = [row["name"] for row in imports] + [L2_COOKIE_PARAM_SYMBOL]

    # --- three runtime lookups ---------------------------------------------- #
    lookups = [_runtime_lookup(symbols, btf, coverage, name, symbol_class, why, severity)
               for name, symbol_class, why, severity in L2_RUNTIME_LOOKUPS]
    for row in lookups:
        row["resolution"] = ("kallsyms_lookup_name (the resolver itself is obtained "
                             "from the kprobe bootstrap, as in maplesu_root.c)")
        row["addressPolicy"] = ("evidence only: the address in `symbol` is the "
                                "kallsyms row for this image, not a constant for the "
                                "module. The module resolves the name at run time; a "
                                "literal address in module text is a G11 failure and "
                                "there is no per-release address table anywhere in L2")
        row["addressUse"] = "must-not-be-hardcoded"

    # --- probe set ----------------------------------------------------------- #
    probes = []
    probe_why = dict(L2_PROBE_TARGETS)
    for probe_id, kind, symbol in (
            ("ctl.magic", "kprobe", "__arm64_sys_ni_syscall"),
            ("execve.entry", "kprobe", "do_execveat_common"),
            ("execve.ret", "kretprobe", "do_execveat_common")):
        entry = symbols.first(symbol)
        blacklist = symbols.first("_kbl_addr_" + symbol)
        probes.append({
            "id": probe_id,
            "kind": kind,
            "symbol": symbol,
            "inSymbolList": entry is not None,
            "symbolType": None if entry is None else entry["type"],
            "blacklisted": blacklist is not None,
            "exported": symbols.first("__ksymtab_" + symbol) is not None,
            "resolution": "register_kprobe/register_kretprobe resolve symbol_name "
                          "through kallsyms; the module stores no address for a "
                          "probe target",
            "why": probe_why[symbol],
        })

    # --- config facts -------------------------------------------------------- #
    config_block = {}
    for key, cfg_name, expected, why in L2_CONFIG_KEYS:
        value = config["values"].get(cfg_name)
        config_block[key] = {
            "config": cfg_name,
            "value": value if value is not None else "<not set>",
            "expected": "y" if expected else "n",
            "satisfied": (value == "y") if expected else (value != "y"),
            "why": why,
        }

    blacklist_entries = [entry for entry in symbols.entries
                         if entry["name"].startswith("_kbl_addr_")]
    blacklist_targets = []
    for symbol in ("__arm64_sys_ni_syscall", "do_execveat_common"):
        row = symbols.first("_kbl_addr_" + symbol)
        blacklist_targets.append({
            "symbol": symbol,
            "blacklisted": row is not None,
            "blacklistSymbol": None if row is None else row["name"],
            "blacklistSymbolTsvLine": None if row is None else row["line"],
        })

    this_module = {
        "btfTypeId": module_struct.tid,
        "size": module_struct.size,
        "sizeHex": "0x%x" % module_struct.size,
        "nameOffset": btf.offset_of(module_struct, "name"),
        "initOffset": btf.offset_of(module_struct, "init"),
        "exitOffset": btf.offset_of(module_struct, "exit"),
        "note": "same struct module BTF as maplesu_root.ko: the glue template's "
                "offsets are derived, not copied",
    }

    l2 = {
        "layer": "L2",
        "schema": "maplesu.l2.contract/1",
        "design": {
            "document": "docs/patching/maplesu-l2-hook-framework-design-2026-10-29.md",
            "revision": "rev-2",
            "review": "docs/patching/maplesu-l2-ready-review-2026-10-29.md",
            "reviewScope": "§11 M1-M10 (must-fix) and §12 C0 (the host work this "
                           "block belongs to)",
            "status": "host-side contract only: nothing in L2 has run on a device",
        },
        "lifetime": "window-scoped: load, arm the control probe, self-check, arm the "
                    "functional probes, self-trigger the first hit, disarm, unload - "
                    "all inside one permissive window (Q-L2-1). Nothing is left "
                    "resident and nothing is persisted across boot",
        "module": {
            "name": L2_MODULE_NAME,
            "fileName": L2_MODULE_FILE,
            "source": L2_MODULE_SOURCE,
            "glueTemplate": L2_GLUE_TEMPLATE,
            "kind": "second, separately unloadable module; maplesu_root.ko stays "
                    "frozen and unmodified",
            "deliveryProof": "`^maplesu_l2 ` in /proc/modules inside the window plus "
                             "the OP_PROBE magic 0x4d41504c45535531",
            "thisModule": this_module,
            "modinfo": {
                "license": "GPL",
                "vermagic": vermagic,
                "required": ["license=GPL", "name=" + L2_MODULE_NAME, "depends=",
                             "vermagic=" + vermagic],
            },
            "build": {
                "verifyCommand": "python jailbreak-providers/root-loader/"
                                 "build_root_module.py --verify-only --module "
                                 "maplesu_l2",
                "state": "artifact-absent: the module is C1; the command must fail "
                         "with 'artifact missing', not an argparse error",
                "gateState": "G1-G7 exist and are module-generic; G8-G14 are the L2 "
                             "gates and land with the module (C1/C2)",
            },
        },
        "structOffsetsRef": ["structOffsets.kretprobe", "structOffsets.ptRegs"],
        "callbacks": {
            "prototypeRule": "each callback must be declared with the *kernel's* "
                             "struct names (struct kprobe, struct pt_regs, struct "
                             "kretprobe_instance). The shim names (struct "
                             "maplesu_*) are for data layout only",
            "nocfiAsymmetry": "functions that *call* a runtime-resolved address are "
                              "MAPLESU_NOCFI; callbacks invoked *by* the kernel are "
                              "not, because they must keep the prefix the kernel "
                              "checks",
            "prototypes": [
                "static int  l2_pre_execve(struct kprobe *p, struct pt_regs *regs);",
                "static void l2_post_execve(struct kprobe *p, struct pt_regs *regs, "
                "unsigned long flags);",
                "static int  l2_ret_execve(struct kretprobe_instance *ri, struct "
                "pt_regs *regs);",
                "static int  l2_pre_ctl(struct kprobe *p, struct pt_regs *regs);",
            ],
        },
        "kcfiIds": kcfi_ids,
        "kcfiIdCount": len([key for key in kcfi_ids if key != "init"]),
        "kcfiMismatches": kcfi_mismatches,
        "declarationCheck": L2_DECLARATION_CHECK,
        "imports": imports,
        "importCount": len(imports),
        "importKcfiRule": L2_IMPORT_NO_KCFI,
        "importsWithKcfiSignature": imports_with_signature,
        "cookieChannel": cookie_channel,
        "importsCookieParam": [cookie_import],
        "importSetFull": import_set_full,
        "importSetFullCount": len(import_set_full),
        "importSetRule": "O6 asserts the complete undefined-symbol set: exactly the "
                         "M4 six plus exactly the cookie param(s) declared in "
                         "importsCookieParam, and nothing else",
        "runtimeLookups": lookups,
        "runtimeLookupCount": len(lookups),
        "probes": probes,
        "controlAbi": L2_CONTROL_ABI,
        "config": config_block,
        "kprobeBlacklist": {
            "symbolPrefix": "_kbl_addr_",
            "entries": len(blacklist_entries),
            "firstEntries": [entry["name"] for entry in blacklist_entries[:5]],
            "targets": blacklist_targets,
            "why": "a blacklisted symbol cannot be kprobed (register_kprobe returns "
                   "-EINVAL). This kernel emits the list as one `_kbl_addr_<symbol>` "
                   "object per entry, so the check is the presence of that name",
            "note": "the count is a property of this build (69). It is recorded as a "
                    "fact, never asserted as a constant by the module",
        },
        "evidence": {
            "schema": "maplesu.hook.l2.v1",
            "key": "l2",
            "mergeRules": "design §4.2 L2-1..L2-8 (cookie folded into L2-2)",
            "tokens": ["MA_L2_NOT_EXERCISED", "MA_L2_MODULE_", "MA_L2_LOAD_",
                       "MA_L2_NO_COOKIE", "MA_L2_PROBE_", "MA_L2_SELFCHECK_FAILED",
                       "MA_L2_DISARM_FAILED", "MA_L2_UNLOAD_BUSY", "MA_L2_NO_HIT",
                       "MA_L2_RET_NO_HIT", "MA_L2_ARM_BUSY", "MA_L2_POLICY_MOVED",
                       "MA_L2_SCNO_NOT_UNIMPLEMENTED"],
            "ownedBy": "C2/C3 (helper) and C4 (App). manager/** is not touched by C0",
            "notProof": "the JSON block is the helper's own observation; the kernel "
                        "ring-buffer lines are the author-side bytes, and both are "
                        "needed (design §4.1)",
        },
        "gateNamespace": L2_GATE_NAMESPACE,
        "redFirst": {
            "meaning": "these gates exist before the artifact does, and are red "
                       "because maplesu_l2.ko / hook_l2() do not exist yet. Gates "
                       "land red, then C1/C2 turn them green",
            "hookContractMode": "python jailbreak-providers/dirtyfrag/tests/"
                                "hook_contract.py --l2-required (fatal); the default "
                                "run reports the L2 leg as non-fatal RED so the "
                                "product baseline stays green",
            "ledger": "work/l2-c0/logs/ (current red counts are recorded there and in "
                      "docs/patching/maplesu-l2-c0-contract-2026-10-29.md)",
        },
    }

    # --- abi checks specific to L2 ------------------------------------------ #
    # The ids are checked against the image, not against the declarations: the
    # declaration measurement is a separate, host-side check (declarationCheck)
    # because it needs clang.
    l2["kcfiIdChecks"] = {
        "status": "match" if not kcfi_mismatches else "mismatch",
        "checked": len(kcfi_ids),
        "mismatches": kcfi_mismatches,
        "note": "a mismatch means the pinned id is not the id this image compares at "
                "the anchor function's dispatch site: the id must be re-measured "
                "before any module is built against it",
    }
    struct_offsets["kernelParam"] = cookie_channel["kernelParam"]
    return l2, struct_offsets


# --------------------------------------------------------------------------- #
# L2 block validation (shape, not values).
# --------------------------------------------------------------------------- #

def validate_l2_contract(contract: dict) -> list:
    """Structural invariants of the `l2` block, checked without the image.

    This is the *regeneration check* for the L2 facts: the derivation is the only
    writer, and this function notices when a field the gates depend on is missing,
    renamed, or contradicts another block of the same contract. The negative tests
    feed it mutated copies, so every O(1) rule below is known to be able to fail.
    Values (which id, which offset) belong to the derivation and to the host tests,
    not here.
    """
    problems: list[str] = []
    l2 = contract.get("l2")
    if not isinstance(l2, dict):
        return ["l2: block missing"]

    def need(path: str, kind=None):
        node = l2
        parts = path.split(".")
        for index, part in enumerate(parts):
            if not isinstance(node, dict) or part not in node:
                problems.append("l2.%s: missing" % path)
                return None
            node = node[part]
        if kind is not None and not isinstance(node, kind):
            problems.append("l2.%s: expected %s" % (path, kind.__name__))
            return None
        return node

    module = need("module", dict)
    if module:
        if module.get("name") != L2_MODULE_NAME:
            problems.append("l2.module.name: not %r" % L2_MODULE_NAME)
        if module.get("fileName") != L2_MODULE_FILE:
            problems.append("l2.module.fileName: not %r" % L2_MODULE_FILE)
        if module.get("source") != L2_MODULE_SOURCE:
            problems.append("l2.module.source: not %r" % L2_MODULE_SOURCE)
        if module.get("glueTemplate") != L2_GLUE_TEMPLATE:
            problems.append("l2.module.glueTemplate: not %r" % L2_GLUE_TEMPLATE)
        if not isinstance(module.get("modinfo", {}).get("vermagic"), str):
            problems.append("l2.module.modinfo.vermagic: missing")
        if not isinstance(module.get("thisModule", {}).get("size"), int):
            problems.append("l2.module.thisModule.size: missing")

    imports = need("imports", list) or []
    names = [row.get("name") for row in imports if isinstance(row, dict)]
    expected = [name for name, _why in L2_IMPORTS]
    if names != expected:
        problems.append("l2.imports: %r != %r" % (names, expected))
    if need("importCount", int) != len(expected):
        problems.append("l2.importCount: not %d" % len(expected))
    signature = need("importsWithKcfiSignature", list)
    if signature:
        problems.append("l2.importsWithKcfiSignature: non-empty %r" % signature)
    if not isinstance(need("importKcfiRule", str), str):
        problems.append("l2.importKcfiRule: missing")

    lookups = need("runtimeLookups", list) or []
    lookup_names = [row.get("name") for row in lookups if isinstance(row, dict)]
    expected_lookups = [name for name, _cls, _why, _sev in L2_RUNTIME_LOOKUPS]
    if lookup_names != expected_lookups:
        problems.append("l2.runtimeLookups: %r != %r" % (lookup_names,
                                                         expected_lookups))
    if need("runtimeLookupCount", int) != len(expected_lookups):
        problems.append("l2.runtimeLookupCount: not %d" % len(expected_lookups))
    for row in lookups:
        if not isinstance(row, dict):
            continue
        if row.get("addressUse") != "must-not-be-hardcoded":
            problems.append("l2.runtimeLookups[%r].addressUse: not "
                            "must-not-be-hardcoded" % row.get("name"))
        if row.get("exported"):
            problems.append("l2.runtimeLookups[%r]: exported, so it is an import"
                            % row.get("name"))
        if not row.get("resolution"):
            problems.append("l2.runtimeLookups[%r].resolution: missing"
                            % row.get("name"))

    # The M6 cookie channel is the *only* permitted increment on the M4 six, and it is
    # a separate list on purpose (see the constant's comment in this file).
    cookie = need("cookieChannel", dict) or {}
    if cookie.get("paramOps") != L2_COOKIE_PARAM_SYMBOL:
        problems.append("l2.cookieChannel.paramOps: not %r" % L2_COOKIE_PARAM_SYMBOL)
    for field in ("param", "uargs", "section", "failureSemantics"):
        if not isinstance(cookie.get(field), str):
            problems.append("l2.cookieChannel.%s: missing" % field)
    cookie_rows = need("importsCookieParam", list) or []
    cookie_names = [row.get("name") for row in cookie_rows if isinstance(row, dict)]
    if cookie_names != [L2_COOKIE_PARAM_SYMBOL]:
        problems.append("l2.importsCookieParam: %r != [%r]"
                        % (cookie_names, L2_COOKIE_PARAM_SYMBOL))
    for row in cookie_rows:
        if not row.get("export"):
            problems.append("l2.importsCookieParam[%r]: not exported"
                            % row.get("name"))
    full = need("importSetFull", list) or []
    if full != expected + [L2_COOKIE_PARAM_SYMBOL]:
        problems.append("l2.importSetFull: %r != the M4 six plus the cookie param"
                        % full)
    if need("importSetFullCount", int) != len(expected) + 1:
        problems.append("l2.importSetFullCount: not %d" % (len(expected) + 1))
    kernel_param = (contract.get("structOffsets") or {}).get("kernelParam") or {}
    for field in ("name", "mod", "ops", "perm", "arg"):
        if not isinstance(kernel_param.get(field), int):
            problems.append("structOffsets.kernelParam.%s: missing" % field)
    for earlier, later in (("name", "mod"), ("mod", "ops"), ("ops", "perm"),
                           ("perm", "arg")):
        if isinstance(kernel_param.get(earlier), int) and isinstance(
                kernel_param.get(later), int) and \
                kernel_param[earlier] >= kernel_param[later]:
            problems.append("structOffsets.kernelParam.%s: not below %s"
                            % (earlier, later))

    ids = need("kcfiIds", dict) or {}
    for key, claim, _functions, _struct, _member, _decl, _why in L2_KCFI_CLAIMS:
        row = ids.get(key)
        if not isinstance(row, dict):
            problems.append("l2.kcfiIds.%s: missing" % key)
            continue
        if row.get("value") != "0x%08x" % claim:
            problems.append("l2.kcfiIds.%s.value: %r != 0x%08x"
                            % (key, row.get("value"), claim))
        if not row.get("inImageTypeIdSet"):
            problems.append("l2.kcfiIds.%s: id is not in the image's type-id set"
                            % key)
        if not row.get("callSitesWithThisId"):
            problems.append("l2.kcfiIds.%s: no call site builds this id" % key)
        if not isinstance(row.get("declaration"), str):
            problems.append("l2.kcfiIds.%s.declaration: missing" % key)
    if "init" not in ids:
        problems.append("l2.kcfiIds.init: missing")
    if need("kcfiIdCount", int) != len(L2_KCFI_CLAIMS):
        problems.append("l2.kcfiIdCount: not %d" % len(L2_KCFI_CLAIMS))
    if need("kcfiMismatches", list):
        problems.append("l2.kcfiMismatches: non-empty %r" % l2.get("kcfiMismatches"))

    # The callback member offsets must equal the BTF block of the same contract, so a
    # copy/paste between `kcfiIds` and `structOffsets` cannot survive regeneration.
    offsets = contract.get("structOffsets", {})
    kretprobe = offsets.get("kretprobe", {})
    pt_regs = offsets.get("ptRegs", {})
    for field, key in (("handler", "kretprobeHandler"),):
        row = ids.get(key) or {}
        if row.get("member", {}).get("offset") != kretprobe.get(field):
            problems.append("l2.kcfiIds.%s.member.offset != structOffsets.kretprobe.%s"
                            % (key, field))
    for key, member in (("preHandler", "pre_handler"), ("postHandler", "post_handler")):
        row = ids.get(key) or {}
        btf_member = next((entry for entry in contract.get("kprobe", {}).get(
            "members", []) if entry.get("name") == member), None)
        if btf_member is None:
            problems.append("kprobe.members: no %r" % member)
        elif row.get("member", {}).get("offset") != btf_member.get("byteOffset"):
            problems.append("l2.kcfiIds.%s.member.offset != kprobe.members[%r]"
                            % (key, member))
    for key in ("syscallno", "sp", "pc", "pstate", "regs"):
        if not isinstance(pt_regs.get(key), int):
            problems.append("structOffsets.ptRegs.%s: missing" % key)
    # Relative order is a shape invariant, not a value: syscallno must sit past the
    # embedded user_pt_regs (orig_x0 is at its end), and the user register block runs
    # regs < sp < pc < pstate. A copy that puts syscallno at 0x110 breaks both.
    if isinstance(pt_regs.get("syscallno"), int) and isinstance(
            pt_regs.get("origX0"), int) and pt_regs["syscallno"] <= pt_regs["origX0"]:
        problems.append("structOffsets.ptRegs.syscallno: not past orig_x0")
    for earlier, later in (("regs", "sp"), ("sp", "pc"), ("pc", "pstate")):
        if isinstance(pt_regs.get(earlier), int) and isinstance(
                pt_regs.get(later), int) and pt_regs[earlier] >= pt_regs[later]:
            problems.append("structOffsets.ptRegs.%s: not below %s" % (earlier, later))
    if not isinstance(kretprobe.get("size"), int):
        problems.append("structOffsets.kretprobe.size: missing")
    for key in ("kp", "handler", "entryHandler", "dataSize"):
        if not isinstance(kretprobe.get(key), int):
            problems.append("structOffsets.kretprobe.%s: missing" % key)

    declaration = need("declarationCheck", dict) or {}
    cases = declaration.get("cases") or []
    kernel_cases = [case for case in cases if ".kernelNames" in str(case.get("case"))]
    shim_cases = [case for case in cases if ".shimNames" in str(case.get("case"))]
    if len(kernel_cases) != len(L2_KCFI_CLAIMS):
        problems.append("l2.declarationCheck.cases: %d kernel-name cases, want %d"
                        % (len(kernel_cases), len(L2_KCFI_CLAIMS)))
    if len(shim_cases) < 2:
        problems.append("l2.declarationCheck.cases: fewer than two shim-name "
                        "negative samples")
    kernel_ids = {case.get("typeId") for case in kernel_cases}
    for case in shim_cases:
        if case.get("typeId") in kernel_ids:
            problems.append("l2.declarationCheck.cases[%r]: shim id equals a kernel id"
                            % case.get("case"))

    config = need("config", dict) or {}
    for key, cfg_name, _expected, _why in L2_CONFIG_KEYS:
        row = config.get(key)
        if not isinstance(row, dict) or row.get("config") != cfg_name:
            problems.append("l2.config.%s: missing or wrong CONFIG name" % key)
        elif not row.get("satisfied"):
            problems.append("l2.config.%s: not satisfied (%r)"
                            % (key, row.get("value")))

    blacklist = need("kprobeBlacklist", dict) or {}
    if not isinstance(blacklist.get("entries"), int) or blacklist.get("entries", 0) < 1:
        problems.append("l2.kprobeBlacklist.entries: missing or zero")
    for row in blacklist.get("targets") or []:
        if row.get("blacklisted"):
            problems.append("l2.kprobeBlacklist.targets[%r]: blacklisted"
                            % row.get("symbol"))

    control = need("controlAbi", dict) or {}
    if len(control.get("ops") or []) != 8:
        problems.append("l2.controlAbi.ops: want 8 entries")
    for register in ("x7", "x5", "x6"):
        if register not in (control.get("registers") or {}):
            problems.append("l2.controlAbi.registers.%s: missing" % register)

    namespace = need("gateNamespace", dict) or {}
    source_ids = [row.get("id") for row in namespace.get("l2SourceChecks") or []]
    object_ids = [row.get("id") for row in namespace.get("l2ObjectChecks") or []]
    expected_source = ["S%d" % number for number in range(26, 41)]
    expected_object = ["O%d" % number for number in range(6, 11)]
    if source_ids != expected_source:
        problems.append("l2.gateNamespace.l2SourceChecks: %r != S26-S40" % source_ids)
    if object_ids != expected_object:
        problems.append("l2.gateNamespace.l2ObjectChecks: %r != O6-O10" % object_ids)
    if not isinstance(namespace.get("redFirst"), dict) and not isinstance(
            l2.get("redFirst"), dict):
        problems.append("l2.redFirst: missing")
    return problems


# --------------------------------------------------------------------------- #
# Contract assembly.
# --------------------------------------------------------------------------- #

def build_contract(image_path: Path, symbols_path: Path) -> dict:
    image = image_path.read_bytes()
    symbols = Symbols(symbols_path)
    btf = Btf(image)

    module_struct = btf.one_struct("module")
    kprobe = btf.one_struct("kprobe")
    selinux = btf.one_struct("selinux_state")

    vermagic, vermagic_meta = read_vermagic(image)
    release = vermagic.split(" ")[0]
    suffix = " " + " ".join(vermagic.split(" ")[1:])
    config = read_config(image)

    # --- address-space check ------------------------------------------- #
    # Every kallsyms offset below is compared against other kallsyms offsets, so
    # the export classification needs no file mapping. The two places that DO mix
    # the two spaces (the KCFI site and the BTF blob) are checked here.
    btf_start = symbols.first("__start_BTF")
    btf_stop = symbols.first("__stop_BTF")
    address_space = {
        "fileOffsetEqualsSymbolOffset": bool(
            btf_start and btf_start["offset"] == btf.magic_offset),
        "checkedWith": "__start_BTF vs the .BTF magic file offset",
        "startBtfSymbol": symbol_block(btf_start),
        "stopBtfSymbol": symbol_block(btf_stop),
        "btfMagicFileOffset": btf.magic_offset,
        "btfMagicFileOffsetHex": "0x%x" % btf.magic_offset,
        "note": "the symbol list starts _text at offset 0, i.e. offsets are "
                "image-relative; __start_BTF landing exactly on the .BTF magic "
                "byte proves the two spaces coincide for this image",
    }

    # --- symbol-list coverage ------------------------------------------- #
    funcs = {t.name for t in btf.types if t is not None and t.kind == K_FUNC}
    text_names = symbols.names_of_type("TEXT")
    missing_funcs = sorted(funcs - text_names)
    max_offset = symbols.max_offset()
    coverage = {
        "rows": len(symbols),
        "maxSymbolOffset": max_offset,
        "maxSymbolOffsetHex": "0x%x" % max_offset,
        "imageBytes": len(image),
        "imageBytesHex": "0x%x" % len(image),
        "bytesAfterLastSymbol": len(image) - max_offset,
        "clippedAtEof": max_offset < len(image),
        "btfFunctionNames": len(funcs),
        "textSymbolNames": len(text_names),
        "btfFunctionsMissingFromList": len(missing_funcs),
        "btfFunctionsMissingExamples": missing_funcs[:8],
        "bssBlindSpot": {
            "applies": max_offset < len(image),
            "why": "the list is built from the image *file*. .bss is a NOLOAD "
                    "section: it occupies no file bytes, so every .bss symbol's "
                    "address is at or past the end of the file and it cannot appear "
                    "in the list. The declaration is checkable: the highest listed "
                    "symbol sits 0x%x bytes before EOF, and .bss is page aligned, "
                    "so .bss starts at the first page at or after that point."
                    % (len(image) - max_offset),
            "consequence": "absence from this list clears function names (all of "
                           ".text is inside the file) but never data names; a data "
                           "object missing from the list must be verified on the "
                           "device, not inferred absent",
        },
        "note": "counts are over names, not rows: kallsyms can carry several "
                "entries for one name",
        "improvement": "the shipped list drops every symbol whose address is at or "
                       "past the end of the image file. Regenerate it without that "
                       "filter (keep out-of-file addresses) and this contract's "
                       "data-name verdicts stop being 'unverified' and become "
                       "present/absent, because .bss would then be represented",
    }

    # --- export table --------------------------------------------------- #
    ksym = symbols.first("__start___ksymtab")
    ksym_stop = symbols.first("__stop___ksymtab")
    ksym_gpl = symbols.first("__start___ksymtab_gpl")
    ksym_gpl_stop = symbols.first("__stop___ksymtab_gpl")
    # 6.18 merged the GPL export table into __ksymtab (the image has
    # __start___ksymtab but no __start___ksymtab_gpl), so an absent GPL range means
    # "this kernel does not split them", not "the image is broken". The range is then
    # empty and every export falls into the plain table, which is exactly what the
    # image says.
    gpl_merged = ksym_gpl is None
    if gpl_merged:
        print("derive_contract: no __start___ksymtab_gpl; treating __ksymtab as the "
              "single export table")
    for entry, name in ((ksym, "__start___ksymtab"), (ksym_stop, "__stop___ksymtab")):
        if entry is None:
            die("%s is missing from the symbol list" % name)
    if not gpl_merged:
        for entry, name in ((ksym_gpl, "__start___ksymtab_gpl"),
                            (ksym_gpl_stop, "__stop___ksymtab_gpl")):
            if entry is None:
                die("%s is missing from the symbol list" % name)

    def export_class(ksymtab_entry):
        if ksymtab_entry is None:
            return None
        addr = ksymtab_entry["offset"]
        if ksym["offset"] <= addr < ksym_stop["offset"]:
            return {"section": "__ksymtab", "macro": "EXPORT_SYMBOL"}
        if not gpl_merged and ksym_gpl["offset"] <= addr < ksym_gpl_stop["offset"]:
            return {"section": "__ksymtab_gpl", "macro": "EXPORT_SYMBOL_GPL"}
        return {"section": "outside both ksymtab ranges", "macro": None}

    counts = {"__ksymtab": 0, "__ksymtab_gpl": 0, "outside": 0}
    for entry in symbols.entries:
        if not entry["name"].startswith("__ksymtab_"):
            continue
        klass = export_class(entry)
        counts[klass["section"] if klass["section"] in counts else "outside"] += 1

    export_table = {
        "__ksymtab": {"start": ksym["offset"], "startHex": "0x%x" % ksym["offset"],
                      "stop": ksym_stop["offset"],
                      "stopHex": "0x%x" % ksym_stop["offset"],
                      "startTsvLine": ksym["line"],
                      "startTsvText": ksym["text"],
                      "stopTsvLine": ksym_stop["line"],
                      "stopTsvText": ksym_stop["text"]},
        # A merged table records an empty GPL range at the plain table's stop, so a
        # consumer never has to special-case "no such section".
        "__ksymtab_gpl": (
            {"start": ksym_gpl["offset"],
             "startHex": "0x%x" % ksym_gpl["offset"],
             "stop": ksym_gpl_stop["offset"],
             "stopHex": "0x%x" % ksym_gpl_stop["offset"],
             "startTsvLine": ksym_gpl["line"],
             "startTsvText": ksym_gpl["text"],
             "stopTsvLine": ksym_gpl_stop["line"],
             "stopTsvText": ksym_gpl_stop["text"]}
            if not gpl_merged else
            {"start": ksym_stop["offset"],
             "startHex": "0x%x" % ksym_stop["offset"],
             "stop": ksym_stop["offset"],
             "stopHex": "0x%x" % ksym_stop["offset"],
             "merged": True,
             "note": "this kernel has no separate GPL export table"}
        ),
        "entryCounts": counts,
        "method": "a symbol's export class is the range its __ksymtab_<name> entry "
                  "address falls in; both bounds are the kernel's own linker "
                  "symbols, so no heuristic is involved",
        "contiguous": (not gpl_merged and ksym_stop["offset"] == ksym_gpl["offset"]),
    }

    # --- required / optional / forbidden / runtime ---------------------- #
    def describe_export(name):
        ksymtab = symbols.first("__ksymtab_" + name)
        klass = export_class(ksymtab)
        return ksymtab, klass

    def export_row(name):
        """The __ksymtab_<name> row with its export class, or None if unexported.

        One shape, used by the root symbol tables and by the L2 import list, so the
        two cannot describe the same export differently.
        """
        ksymtab, klass = describe_export(name)
        if ksymtab is None:
            return None
        return {
            "ksymtabSymbol": "__ksymtab_" + name,
            "address": ksymtab["offset"],
            "addressHex": "0x%x" % ksymtab["offset"],
            "tsvLine": ksymtab["line"],
            "tsvText": ksymtab["text"],
            "section": klass["section"],
            "macro": klass["macro"],
        }

    required = []
    # The four-argument wrapper is resolved through kallsyms by the module, not imported,
    # because vendor kernels do not all export it (5.15 and 6.1 measured: no
    # __ksymtab_call_usermodehelper). A family without it is still a valid target: the
    # module can load and simply has no fallback handover.
    runtime_resolved = {"call_usermodehelper"}
    for name, gpl_expected, why in REQUIRED_SYMBOLS:
        entry = symbols.first(name)
        ksymtab, klass = describe_export(name)
        if entry is None:
            if name in runtime_resolved:
                print("derive_contract: %s is absent; the module resolves it at run "
                      "time, so this family simply has no fallback handover" % name)
                continue
            die("required symbol %s is absent from the symbol list" % name)
        if ksymtab is None:
            if name in runtime_resolved:
                print("derive_contract: %s has no __ksymtab entry; resolved at run "
                      "time instead" % name)
                continue
            die("required symbol %s has no __ksymtab_%s entry" % (name, name))
        required.append({
            "name": name,
            "why": why,
            "imported": True,
            "required": True,
            "symbol": symbol_block(entry),
            "export": export_row(name),
            "gplOnly": klass["section"] == "__ksymtab_gpl",
            "gplExpectationMatched": (klass["section"] == "__ksymtab_gpl")
            == gpl_expected,
        })

    optional = []
    for name, gpl_expected, why in OPTIONAL_SYMBOLS:
        entry = symbols.first(name)
        optional.append({
            "name": name,
            "why": why,
            "imported": False,
            "required": False,
            "symbol": symbol_block(entry),
            "export": export_row(name),
        })

    forbidden = []
    for name, why in FORBIDDEN_SYMBOLS:
        entry = symbols.first(name)
        ksymtab = symbols.first("__ksymtab_" + name)
        btf_kinds = sorted({KIND_NAMES[t.kind] for t in btf.named(name)})
        if ksymtab is not None:
            evidence = "exported: importing it would link, which the design forbids"
        elif entry is not None:
            evidence = ("present in the symbol list as %s but with no __ksymtab_%s "
                        "entry, so an import fails with 'Unknown symbol'"
                        % (entry["type"], name))
        elif btf_kinds:
            evidence = ("in BTF as %s but not exported and not in the symbol list"
                        % ",".join(btf_kinds))
        else:
            evidence = ("absent everywhere: no __ksymtab_%s, no symbol-list row, and "
                        "no BTF type of this name (the kernel was not built with it)"
                        % name)
        forbidden.append({
            "name": name,
            "why": why,
            "inSymbolList": entry is not None,
            "symbolListRowsForName": len(symbols.hits(name)),
            "ksymtabRowsForName": len(symbols.hits("__ksymtab_" + name)),
            "symbol": symbol_block(entry),
            "inBtf": bool(btf_kinds),
            "btfKinds": btf_kinds,
            "export": symbol_block(ksymtab),
            "importable": ksymtab is not None,
            "evidence": evidence,
        })

    runtime = [_runtime_lookup(symbols, btf, coverage, name, symbol_class, why, severity)
               for name, symbol_class, why, severity in RUNTIME_LOOKUPS]

    # --- config --------------------------------------------------------- #
    config_block = {}
    for key, cfg_name, expected, why in CONFIG_KEYS:
        value = config["values"].get(cfg_name)
        config_block[key] = {
            "config": cfg_name,
            "value": value if value is not None else "<not set>",
            "expected": "y" if expected else "n",
            "satisfied": (value == "y") if expected else (value != "y"),
            "why": why,
        }
    # CONFIG_STATIC_USERMODEHELPER_PATH is a *string* option, so it is not part of the
    # y/n table above: its value is what decides whether the four-argument
    # call_usermodehelper() can exec anything. "" (the two-quote literal in the config
    # text) means setup() replaces every caller's path with the empty rodata string.
    smh_path_raw = config["values"].get("CONFIG_STATIC_USERMODEHELPER_PATH")
    smh_path = smh_path_raw
    if smh_path and len(smh_path) >= 2 and smh_path[0] == '"' and smh_path[-1] == '"':
        smh_path = smh_path[1:-1]
    config_block["staticUsermodehelperPath"] = {
        "config": "CONFIG_STATIC_USERMODEHELPER_PATH",
        "value": "" if smh_path is None else smh_path,
        "rawValue": "<not set>" if smh_path_raw is None else smh_path_raw,
        "expected": "",
        "satisfied": smh_path == "",
        "why": "the empty override is the reason the module must do the two-stage "
               "handover: call_usermodehelper_setup() stores a pointer to this empty "
               "rodata string at subprocess_info.path, and call_usermodehelper_exec() "
               "sees an empty path and returns 0 without forking anything",
    }
    config_provenance = {
        "source": "embedded CONFIG_IKCONFIG blob in the image",
        "blobOffset": config["blobOffsetHex"],
        "compressedBytes": config["compressedBytes"],
        "plainBytes": config["plainBytes"],
        "lines": config["lines"],
        "note": "authoritative for this exact image, no device access needed; the "
                "prior evidence doc docs/patching/HANDOVER-2026-10-29.md:203 states "
                "the same values from device-side observation",
    }

    # --- KCFI ----------------------------------------------------------- #
    sites = find_kcfi_site(image)
    if sites:
        chosen = None
        owner = None
        for site in sites:
            candidate = symbols.containing_text(site["fileOffset"])
            if candidate is not None and candidate["name"] == "do_one_initcall":
                chosen, owner = site, candidate
                break
        if chosen is None:
            chosen = sites[0]
            owner = symbols.containing_text(chosen["fileOffset"])
        kcfi = {
            "kcfiInitTypeId": chosen["typeId"],
            "provenance": "image-bytes",
            "site": {
                "fileOffset": chosen["fileOffset"],
                "fileOffsetHex": chosen["fileOffsetHex"],
                "decoded": chosen["instructions"],
                "containingFunction": None if owner is None else owner["name"],
                "containingFunctionSymbol": symbol_block(owner),
                "note": "clang kCFI builds the expected type hash for `int (void)` "
                        "in w17, compares it with the callee's 4-byte prefix and "
                        "traps on mismatch before the indirect call; a module's "
                        "init_module must therefore begin with this 32-bit value",
            },
            "occurrences": len(sites),
            "distinctTypeIds": len({s["typeId"] for s in sites}),
            "typeIdSample": sorted({s["typeId"] for s in sites})[:12],
        }
    else:
        kcfi = {
            "kcfiInitTypeId": "0x36b1c5a6",
            "provenance": "carried-from-prior-evidence",
            "note": "the movk pair was not found in this image, so the value is "
                    "carried from jailbreak-providers/ir-loader/contract.json "
                    "source.kcfiFrom and must be re-derived before shipping",
        }

    # --- helper path ---------------------------------------------------- #
    # Step-3 (design D3-3 / §3.2): D-5's `<dataDir>/bs` is the *credential-encrypted*
    # data dir. Two facts decide it, and neither is a preference:
    #   * the frozen stock/derived dfroot.ko carries the path in a fixed-width array
    #     whose usable length is 33 characters (`/data/data/dev.maplesu.manager/bs`
    #     is exactly that, and is what derive.py rewrites it to); the device-protected
    #     spelling `/data/user_de/0/dev.maplesu.manager/bs` is 39 bytes with the NUL,
    #     5 more than the array can hold;
    #   * the App stages `bs` at `context.getFilesDir().getParentFile()` today, which
    #     IS the CE dir. `/data/data/<pkg>` and `/data/user/0/<pkg>` are the same
    #     inode, so the module carries the kernel-visible spelling.
    helper_literal = re.search(r'"(/data/[^"]*)"', read_text(
        REPO_ROOT / MODULE_DIR_REL / "maplesu_root.c"))
    helper_path_in_source = helper_literal.group(1) if helper_literal else None
    helper_policy_path = "/data/user/0/dev.maplesu.manager/bs"
    helper_data_dir = "/data/user/0/dev.maplesu.manager"
    helper_block = {
        "decision": "D-5 (as corrected by step-3 D3-3)",
        "decisionDoc": "docs/patching/maplesu-kernel-entry-design-2026-10-29.md:99",
        "decisionQuote": "| D-5 | helper 路径 | 统一为 App 实际 stage 的 "
                         "`<dataDir>/bs`（模块侧改常量） |",
        "policyPath": helper_policy_path,
        "policyPathTemplate": "<CE-dataDir>/bs",
        "dataDir": helper_data_dir,
        "dataDirKind": "credential-encrypted (CE; /data/data is the same inode)",
        "aliases": ["/data/data/dev.maplesu.manager/bs"],
        "unstagedAlias": {
            "path": "/data/user_de/0/dev.maplesu.manager/bs",
            "rejectedBecause": "39 bytes with the NUL; the stock dfroot.ko path "
                               "array holds 33 characters "
                               "(/data/data/dev.maplesu.manager/bs)",
        },
        "moduleConstant": helper_path_in_source,
        "moduleConstantSource": "jailbreak-providers/root-loader/module/"
                                "maplesu_root.c:104-108",
        "matches": helper_path_in_source == helper_policy_path,
        "status": "aligned" if helper_path_in_source == helper_policy_path
        else "MISMATCH",
        "note": "Step-3 aligned the module-side constant to the CE `bs` the App "
                "actually stages (D-5). The App writes it in "
                "DirtyfragAttempt.stageBootstrap() and the stock dfroot.ko execs the "
                "same inode, so one binary serves both the exploit route (argv[0]) "
                "and the module's UMH handover (handover.helperArgv). CE is only "
                "mounted after user 0 is unlocked, so this handover must never be "
                "moved to early boot.",
    }

    # --- selinux_state -------------------------------------------------- #
    var_hits = btf.named("selinux_state", K_VAR)
    kal = symbols.first("selinux_state")
    selinux_block = {
        "btfTypeId": selinux.tid,
        # An image can carry more than one struct with this name (6.1 has a 0x88
        # layout with checkreqprot and a 0x80 one), so record every id: the gates use
        # the set to prove they are looking at the same type the module was built for.
        "allBtfTypeIds": sorted({hit.tid for hit in
                                 btf.named("selinux_state", K_STRUCT)}),
        "size": selinux.size,
        "sizeHex": "0x%x" % selinux.size,
        "enforcingOffset": btf.offset_of(selinux, "enforcing"),
        "enforcingOffsetHex": "0x%x" % btf.offset_of(selinux, "enforcing"),
        "initializedOffset": btf.offset_of(selinux, "initialized"),
        "initializedOffsetHex": "0x%x" % btf.offset_of(selinux, "initialized"),
        "members": btf.layout(selinux),
        "varInBtf": {
            "present": bool(var_hits),
            "typeIds": [v.tid for v in var_hits],
            "note": "not probative: this BTF encodes almost no variables (a few "
                    "hundred VARs against tens of thousands of objects), so a "
                    "missing VAR says nothing about the symbol",
        },
        "symbolList": {"present": kal is not None, "symbol": symbol_block(kal)},
        "writtenByModule": "enforcing = 0, restored on every failure path and in "
                           "cleanup_module",
        "writableNow": btf.offset_of(selinux, "enforcing") is not None
                       and config_block.get("selinuxDevelop", {}).get(
                           "satisfied", False),
    }

    # --- struct subprocess_info (the target of the static-UMH fix) -------- #
    # The two-stage handover exists for exactly one field. Deriving its offset from
    # this image's BTF is what lets the gates assert that the module's store lands on
    # the same byte the kernel's exec() reads; a hand-copied 0x38 would be a guess
    # that outlives the image it came from.
    subprocess_struct = btf.one_struct("subprocess_info")
    subprocess_block = {
        "btfTypeId": subprocess_struct.tid,
        "allBtfTypeIds": [t.tid for t in btf.named("subprocess_info", K_STRUCT)],
        "size": subprocess_struct.size,
        "sizeHex": "0x%x" % subprocess_struct.size,
        "path": btf.offset_of(subprocess_struct, "path"),
        "pathHex": "0x%x" % btf.offset_of(subprocess_struct, "path"),
        "pathMember": "char *path",
        "argv": btf.offset_of(subprocess_struct, "argv"),
        "envp": btf.offset_of(subprocess_struct, "envp"),
        "wait": btf.offset_of(subprocess_struct, "wait"),
        "retval": btf.offset_of(subprocess_struct, "retval"),
        "members": btf.layout(subprocess_struct),
        "writtenByModule": "path only: setup() replaces it with the empty "
                           "CONFIG_STATIC_USERMODEHELPER_PATH string, and the module "
                           "writes the helper path back before exec()",
        "readBy": "call_usermodehelper_exec() reads path (ldr x8,[x19,#0x38]; ldrb "
                  "w8,[x8]) and returns 0 immediately when the first byte is NUL",
    }
    struct_offsets = {"subprocessInfo": subprocess_block}

    # --- struct module / kprobe ----------------------------------------- #
    this_module = {
        "btfTypeId": module_struct.tid,
        "allBtfTypeIds": [t.tid for t in btf.named("module", K_STRUCT)],
        "size": module_struct.size,
        "sizeHex": "0x%x" % module_struct.size,
        "nameOffset": btf.offset_of(module_struct, "name"),
        "nameOffsetHex": "0x%x" % btf.offset_of(module_struct, "name"),
        "initOffset": btf.offset_of(module_struct, "init"),
        "initOffsetHex": "0x%x" % btf.offset_of(module_struct, "init"),
        "exitOffset": btf.offset_of(module_struct, "exit"),
        "exitOffsetHex": "0x%x" % btf.offset_of(module_struct, "exit"),
        "archOffset": btf.offset_of(module_struct, "arch"),
        "archOffsetHex": "0x%x" % btf.offset_of(module_struct, "arch"),
        "members": btf.layout(module_struct),
    }

    kprobe_block = {
        "btfTypeId": kprobe.tid,
        "allBtfTypeIds": [t.tid for t in btf.named("kprobe", K_STRUCT)],
        "size": kprobe.size,
        "sizeHex": "0x%x" % kprobe.size,
        "addrOffset": btf.offset_of(kprobe, "addr"),
        "addrOffsetHex": "0x%x" % btf.offset_of(kprobe, "addr"),
        "symbolNameOffset": btf.offset_of(kprobe, "symbol_name"),
        "symbolNameOffsetHex": "0x%x" % btf.offset_of(kprobe, "symbol_name"),
        "members": btf.layout(kprobe),
        "note": "register_kprobe() fills addr from symbol_name; the module zeroes "
                "the whole object first, so the leading bookkeeping fields "
                "(hlist/list/nmissed) never matter",
    }

    abi_checks = build_abi_checks(btf, module_struct, kprobe, selinux,
                                  REPO_ROOT / MODULE_DIR_REL)

    # --- L2: the second module ------------------------------------------- #
    # Derives structOffsets.kretprobe / structOffsets.ptRegs and the whole `l2`
    # block. Every id is re-checked against the image here, at regeneration time.
    l2_block, l2_struct_offsets = build_l2_block(
        btf, symbols, image, config, sites, kcfi, coverage, vermagic,
        module_struct, kprobe, export_row)
    struct_offsets.update(l2_struct_offsets)

    gpl_required = [s for s in required if s["gplOnly"]]
    modinfo = {
        "required": ["license=GPL", "vermagic=" + vermagic,
                     "name=maplesu_root", "depends="],
        "license": "GPL",
        "licenseRationale": {
            "why": "a non-GPL module may not resolve a symbol whose __ksymtab entry "
                   "lives in __ksymtab_gpl, so register_kprobe() alone forces "
                   "license=GPL; nothing else about this module is GPL-specific",
            "evidence": [s["name"] + " -> " + s["export"]["macro"]
                         for s in gpl_required],
            "gplBoundSymbols": [s["name"] for s in gpl_required],
        },
        "vermagicSuffix": suffix,
        "source": "module/root_glue.S.in, .modinfo section (the template is the "
                  "source of truth; build_root_module.py substitutes "
                  "@ROOT_VERMAGIC@ and emits no second .modinfo, because the loader "
                  "rejects a module with two)",
    }

    return {
        "schemaVersion": 1,
        "kind": "maplesu-root-loader-kernel-abi",
        "module": "maplesu_root",
        "description": "kernel ABI contract for the resident in-kernel root module",
        "license": "GPL",
        "kernelRelease": release,
        "imagePath": display_path(image_path),
        "imageSha256": hashlib.sha256(image).hexdigest(),
        "imageBytes": len(image),
        "symbolsPath": display_path(symbols_path),
        "numSymbols": len(symbols),
        "vermagic": vermagic,
        "vermagicSuffix": suffix,
        "vermagicProvenance": vermagic_meta,
        "addressSpace": address_space,
        "btf": {
            "magicOffset": btf.magic_offset,
            "magicOffsetHex": "0x%x" % btf.magic_offset,
            "version": btf.version,
            "headerBytes": btf.hdr_len,
            "typeBytes": len(btf.type_bytes),
            "stringBytes": len(btf.strings),
            "numTypes": len(btf.types) - 1,
            "blobBytes": btf.blob_bytes,
            "sectionSpan": None if not (btf_start and btf_stop) else
            btf_stop["offset"] - btf_start["offset"],
            "provenance": "image .BTF at 0x%x, parsed with the kernel's own BTF "
                          "encoding (kernel/bpf/btf.c); every type id below is a "
                          "BTF id" % btf.magic_offset,
        },
        "symbolListCoverage": coverage,
        "thisModule": this_module,
        "kprobe": kprobe_block,
        "selinuxState": selinux_block,
        "structOffsets": struct_offsets,
        "exportTable": export_table,
        "kcfiInitTypeId": kcfi["kcfiInitTypeId"],
        "kcfiProvenance": kcfi,
        "modinfo": modinfo,
        "requiredSymbols": required,
        "optionalSymbols": optional,
        "forbiddenSymbolsAbsent": forbidden,
        "runtimeLookups": runtime,
        "config": config_block,
        "configProvenance": config_provenance,
        "helperPathPolicy": helper_block,
        "l2": l2_block,
        "handover": {
            "umhWaitMode": "UMH_WAIT_EXEC",
            "umhWaitModeValue": 1,
            "forbiddenWaitMode": "UMH_WAIT_PROC",
            "why": "the helper execs the long-lived consumer and never exits, so "
                   "WAIT_PROC would park init_module() in kernel_wait() while "
                   "holding module_mutex",
            "returnZeroMeans": "handed over and resident",
            "returnZeroIsNotProof": "the helper's own side effect (provider-log line "
                                    "plus a `getenforce` readback) is the only proof "
                                    "the handover happened; init_module's return value "
                                    "and its printks are not, because the four-argument "
                                    "wrapper returns 0 silently on this image",
            "cleanupModule": "defined; it is this_module.exit and the only "
                             "in-kernel restore point reachable through "
                             "delete_module()",
            "primaryPath": {
                "setup": "call_usermodehelper_setup",
                "exec": "call_usermodehelper_exec",
                "resolveVia": "kallsyms_lookup_name (runtime; neither is exported)",
                "sequence": [
                    "info = setup(helper, argv, envp, GFP_KERNEL, NULL, NULL, NULL)",
                    "((struct subprocess_info *)info)->path = helper",
                    "ret = exec(info, UMH_WAIT_EXEC)",
                ],
                "gfpKernel": 0xCC0,
                "pathOffset": subprocess_block["path"],
                "pathOffsetHex": subprocess_block["pathHex"],
                "pathOffsetSource": "BTF struct subprocess_info (structOffsets)"
                                    ".subprocessInfo.path",
                "requiredWhen": "config.staticUsermodehelperPath.value == \"\"",
                "why": "setup() overwrites the caller's path with the empty "
                       "CONFIG_STATIC_USERMODEHELPER_PATH string; restoring it at "
                       "subprocess_info.path is the whole fix (DirtyFragX "
                       "lkm/dfroot.c:185-188 does the same on this device family)",
            },
            "fallback": {
                "call": "call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC)",
                "usedOnlyWhen": "setup or exec cannot be resolved",
                "logged": "maplesu_root: umh setup/exec unresolved (setup=%px "
                          "exec=%px); falling back to the four-argument wrapper",
                "deadOnThisImage": True,
                "why": "it keeps the import set at exactly four and the module "
                       "loadable on a kernel where the pair is missing, but on this "
                       "static-UMH image it cannot exec anything: it returns 0 and "
                       "the module must not treat that as proof",
            },
            "importSetUnchanged": True,
            # Step-3: what the module passes to the helper (design §2.1). The two
            # arrays are file-scope static storage in the module, not stack locals,
            # because UMH_WAIT_EXEC leaves the kernel holding these pointers.
            "helperArgv": {
                "argv": ["<helper>", "--umh", "--entry-enforcing", "<saved>"],
                "envp": ["PATH=/system/bin"],
                "helper": helper_policy_path,
                "savedValue": "the enforcement byte init_module() read before it "
                              "wrote 0 ('0' or '1', the value its "
                              "`selinux permissive for handover (was %d) "
                              "own_window=%d` printk names). Step-4 (D4-4) adds the "
                              "honesty field: own_window=1 means this module moved the "
                              "byte and cleanup_module() must put it back; own_window=0 "
                              "means the window was already open, the saved byte is "
                              "inherited, and the module writes nothing back",
                "storage": {
                    "arrays": ["maplesu_argv", "maplesu_envp", "maplesu_entry"],
                    "kind": "file-scope static (.bss), never a stack local",
                    "why": "UMH_WAIT_EXEC returns when the exec succeeds; a stack "
                           "block would be read after init_module() is gone (the "
                           "reference dfroot.c uses static storage for the same "
                           "reason)",
                },
                "helperSide": {
                    "modeToken": "--umh",
                    "entryToken": "--entry-enforcing",
                    "optional": ["--stage2 <path>", "--daemon <path>"],
                    "design": "docs/patching/maplesu-step3-umh-mode-design-2026-10-29.md "
                              "§2.1/§4",
                },
            },
            # ------------------------------------------------------------------ #
            # Step-4 (D2/D4-3, design §2.1/§2.4): what the helper's argv does *not*
            # say, and the order the restore happens in.
            #
            # argv's --entry-enforcing is demoted to "what the kernel observed at load
            # time": in the dfroot chain that is necessarily 0, so it cannot be the
            # restore target (step-3 wrote 0 and called it success). The target comes
            # from the App, which is the only subject still alive before the window
            # opens, and it travels with its provenance.
            # ------------------------------------------------------------------ #
            "entryBaseline": {
                "policyPath": "<DE>/maplesu-hook-env",
                "schema": "maplesu.hook.env.v1",
                "keys": ["schema", "boot", "attempt", "expected", "source"],
                "expectedValues": ["-1", "0", "1"],
                "sourceValues": ["observed", "baseline", "unknown"],
                "originMapping": {
                    "enforce_before==1": "KERNEL_SAVED (source=kernel; the value is the "
                                         "kernel's own live byte, never written by the "
                                         "helper)",
                    "enforce_before==0 && expected in {0,1}": "BASELINE (source copied "
                                                              "from the env: observed "
                                                              "or baseline)",
                    "otherwise": "FAILED (source=unknown, no selinuxfs write)",
                },
                "whoWrites": "App (DirtyfragAttempt.start, after publishConfig and "
                             "before the provider starts; 0600, one line, <=192 bytes)",
                "whoReads": "helper step 3.5 (hook_read_env, openat(dirfd), once, "
                            "inside the window)",
                "neverWriteZeroWhen": "enforce_before==1",
                "why": "the module loads after dfroot already wrote 0, so it cannot "
                       "know the entry value; the App cannot read selinuxfs either, so "
                       "it reports a *target plus provenance* rather than an "
                       "observation. KERNEL_SAVED is reserved for the one case where "
                       "the kernel's value is its own",
                "residualRisk": "the env file is unauthenticated: the App owns it and "
                                "could ask for expected=0/source=observed, leaving the "
                                "device permissive until the next boot. It gains no "
                                "capability it did not have, and DAEMON_READY is still "
                                "refused because F1 requires restoreEnforcing==1",
            },
            "restoreOrder": {
                "steps": ["decide", "fork", "delete_module", "readback_post",
                          "write_if_needed", "readback_final", "klog", "record"],
                "why": "the module's cleanup_module() runs inside delete_module() and "
                       "writes back the byte it saved. Writing before the unload is "
                       "therefore overwritten - which is exactly how step-3 produced "
                       "wrote=1/readback_pre=0 while the device was still permissive. "
                       "Restore-last makes the helper's write the final privileged "
                       "action, and the unload child the only writer, so there is no "
                       "second write and no swing back",
                "singleWriter": "hook_unload_child only; the parent never writes",
                "preexisting": "post_unload==want is logged as "
                               "`restore preexisting=%d by=external` and NOT rewritten",
                "parentWaitMs": 1500,
                "childWindowMs": 4000,
                "pendingMeans": "the parent's bounded wait expired while the child is "
                                "still retrying; PENDING is an expected outcome (R12's "
                                "mitigation is the parent exiting so init_module returns "
                                "and releases module_mutex), not a failure",
            },
            # Design decision D-2: the failure is *classified*, not collapsed into one
            # errno. The module implements exactly these five returns and G5 asserts
            # that each one is encoded in init_module, so this table and the C file
            # cannot drift apart silently.
            "failureReturns": {
                "-ENOSYS": "kallsyms_lookup_name (or the kprobe that yields it) could "
                           "not be resolved; nothing was read, written or restored",
                "-ENOENT": "selinux_state could not be resolved; the enforcement byte "
                           "was never saved or changed, nothing was restored",
                "-EINVAL": "call_usermodehelper_setup/_exec could not both be resolved, "
                           "so the four-argument fallback is the only path left - and on "
                           "this static-UMH kernel that path cannot exec anything; the "
                           "saved enforcing value was restored and nothing ran",
                "-ENOMEM": "call_usermodehelper_setup() returned NULL; nothing was "
                           "queued, the saved enforcing value was restored",
                "-ENODEV": "call_usermodehelper_exec() returned non-zero, i.e. the "
                           "helper was not exec'd ('nothing ran'); the saved enforcing "
                           "value was restored",
            },
            # Step-3 (design §7.1): errno alone can no longer name the cause, because
            # -ENODEV now means "the helper was not exec'd" *and* the loader-level
            # "no symbols". The bootstrap therefore classifies in two layers: the
            # loader-layer token from errno, then - when the ring-buffer dump it just
            # took contains the module's own classified line - the handover-layer token
            # below overrides it. One failure still yields exactly one token.
            "failureReturnsAppMapping": {
                "producer": "jailbreak-providers/dirtyfrag/adapter/bootstrap.c "
                            "(ir_errno_token)",
                "consumer": "JailbreakExecutor.IR_FAILURE ((?:MAPLESU|SKROOT)_(?:IR|HANDOVER)_[A-Z_]+)",
                "loaderLayer": {
                    "EKEYREJECTED": "MAPLESU_IR_ORIG_MISMATCH",
                    "EOPNOTSUPP": "MAPLESU_IR_SPEC_INVALID",
                    "ENODEV": "MAPLESU_IR_NO_SYMBOLS",
                    "EIO": "MAPLESU_IR_APPLY_FAILED",
                    "other": "MAPLESU_IR_LOAD_FAILED",
                },
                "handoverOverrides": [
                    {"printk": "kallsyms_lookup_name not found", "token":
                        "MAPLESU_HANDOVER_NO_UMH"},
                    {"printk": "kprobe resolved no address", "token":
                        "MAPLESU_HANDOVER_NO_UMH"},
                    {"printk": "selinux_state not found", "token":
                        "MAPLESU_HANDOVER_NO_SELINUX"},
                    {"printk": "umh setup returned NULL", "token":
                        "MAPLESU_HANDOVER_NO_MEMORY"},
                    {"printk": "fallback cannot hand over", "token":
                        "MAPLESU_HANDOVER_NO_UMH"},
                    {"printk": "helper exec failed", "token":
                        "MAPLESU_HANDOVER_NO_EXEC"},
                ],
                "note": "the override only fires when the module's own classified "
                        "printk is in the dump taken for this failure; an empty or "
                        "unreadable dump leaves the loader-layer token in place, so a "
                        "missing kernel channel is never reported as a specific cause",
            },
        },
        "abiChecks": abi_checks,
    }


# --------------------------------------------------------------------------- #
# --inspect: ad-hoc BTF queries (writes nothing).
# --------------------------------------------------------------------------- #

def inspect(image_path: Path, symbols_path: Path, names: list) -> int:
    image = image_path.read_bytes()
    btf = Btf(image)
    symbols = Symbols(symbols_path) if symbols_path.is_file() else None
    print("btf: magic at 0x%x, %d types, %d string bytes"
          % (btf.magic_offset, len(btf.types) - 1, len(btf.strings)))
    for name in names:
        hits = btf.named(name)
        print("\n=== %s: %d named type(s)" % (name, len(hits)))
        for rec in hits:
            print("  id %-6d kind %-9s size 0x%-6x vlen %d"
                  % (rec.tid, KIND_NAMES.get(rec.kind, "?"), rec.size, rec.vlen))
            if rec.kind in (K_STRUCT, K_UNION):
                for member in btf.layout(rec):
                    print("     +0x%04x  %-24s %-10s %s%s"
                          % (member["byteOffset"], member["name"] or "(anon)",
                             member["typeKind"], member["typeName"],
                             "[%d]" % member["elements"]
                             if "elements" in member else ""))
            if rec.kind == K_VAR:
                print("     var type -> %s" % btf.describe(rec.extra))
        ids = {rec.tid for rec in hits}
        for rec in btf.types:
            if rec is None:
                continue
            for member in rec.members:
                if member[1] in ids:
                    print("  referenced by id %-6d %-9s %-28s member %s"
                          % (rec.tid, KIND_NAMES.get(rec.kind), rec.name,
                             member[0]))
        if symbols is not None:
            entries = symbols.hits(name)
            print("  symbol list: %d hit(s)" % len(entries))
            for entry in entries[:5]:
                print("    line %d: %s" % (entry["line"], entry["text"]))
    return 0


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description="derive the root-loader kernel ABI contract from the image")
    parser.add_argument("--image", default=str(REPO_ROOT / IMAGE_REL),
                        help="kernel image carrying .BTF (default: %s)" % IMAGE_REL)
    parser.add_argument("--symbols", default=str(REPO_ROOT / SYMBOLS_REL),
                        help="kallsyms TSV for the same image (default: %s)"
                             % SYMBOLS_REL)
    parser.add_argument("--out", default=None,
                        help="contract path (default: contracts/<uname>.json)")
    parser.add_argument("--inspect", nargs="+", metavar="NAME",
                        help="dump BTF types by name and exit, writing nothing")
    parser.add_argument("--check", action="store_true",
                        help="regenerate in memory and compare with the committed "
                             "contract, then run the L2 block's structural checks; "
                             "writes nothing")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    image_path = Path(args.image)
    symbols_path = Path(args.symbols)
    if not image_path.is_file():
        die("image not found: %s" % image_path)
    if not symbols_path.is_file():
        die("symbol list not found: %s" % symbols_path)

    if args.inspect:
        return inspect(image_path, symbols_path, args.inspect)

    contract = build_contract(image_path, symbols_path)
    out = Path(args.out) if args.out else HERE / (contract["kernelRelease"] + ".json")

    if args.check:
        text = json.dumps(contract, indent=2, ensure_ascii=True) + "\n"
        committed = out.read_bytes() if out.is_file() else b""
        same = committed == text.encode("utf-8")
        problems = validate_l2_contract(contract)
        kcfi = contract["l2"]["kcfiIdChecks"]
        print("check: %s" % out)
        print("  regenerated %s" % ("equals the committed file" if same
                                    else "DIFFERS from the committed file"))
        print("  l2 block    %s (%d structural problem(s))"
              % ("ok" if not problems else "INVALID", len(problems)))
        for problem in problems:
            print("    %s" % problem)
        print("  l2 kcfiIds  %s (%d checked, mismatches: %s)"
              % (kcfi["status"], kcfi["checked"], kcfi["mismatches"] or "none"))
        print("RESULT: %s" % ("PASS" if same and not problems
                              and kcfi["status"] == "match" else "FAILED"))
        return 0 if same and not problems and kcfi["status"] == "match" else 1

    # ensure_ascii keeps the file pure ASCII: consumers on a non-UTF-8 locale (this
    # repo is developed on a Windows host whose default codec is GBK) can then
    # json.load(open(path)) without passing an encoding and without a decode error.
    # The D-5 decision quote is CJK and comes out as \uXXXX escapes.
    text = json.dumps(contract, indent=2, ensure_ascii=True) + "\n"
    out.write_text(text, encoding="utf-8", newline="\n")

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    checks = contract["abiChecks"]
    if not args.quiet:
        print("contract: %s" % out)
        print("  sha256  %s (%d bytes)" % (digest, len(text.encode("utf-8"))))
        print("  release %s" % contract["kernelRelease"])
        print("  image   %s (%d bytes)" % (contract["imageSha256"],
                                           contract["imageBytes"]))
        print("  symbols %d rows, max offset 0x%x, clipped at EOF: %s"
              % (contract["numSymbols"],
                 contract["symbolListCoverage"]["maxSymbolOffset"],
                 contract["symbolListCoverage"]["clippedAtEof"]))
        print("  module  0x%x name@0x%x init@0x%x exit@0x%x arch@0x%x"
              % (contract["thisModule"]["size"],
                 contract["thisModule"]["nameOffset"],
                 contract["thisModule"]["initOffset"],
                 contract["thisModule"]["exitOffset"],
                 contract["thisModule"]["archOffset"]))
        print("  kprobe  0x%x addr@0x%x symbol_name@0x%x"
              % (contract["kprobe"]["size"], contract["kprobe"]["addrOffset"],
                 contract["kprobe"]["symbolNameOffset"]))
        print("  selinux 0x%x enforcing@0x%x initialized@0x%x"
              % (contract["selinuxState"]["size"],
                 contract["selinuxState"]["enforcingOffset"],
                 contract["selinuxState"]["initializedOffset"]))
        print("  umh     CONFIG_STATIC_USERMODEHELPER=%s path=%r; "
              "subprocess_info 0x%x path@0x%x"
              % (contract["config"]["staticUsermodehelper"]["value"],
                 contract["config"]["staticUsermodehelperPath"]["value"],
                 contract["structOffsets"]["subprocessInfo"]["size"],
                 contract["structOffsets"]["subprocessInfo"]["path"]))
        print("  kcfi    %s (%s, %d sites)"
              % (contract["kcfiInitTypeId"],
                 contract["kcfiProvenance"]["provenance"],
                 contract["kcfiProvenance"].get("occurrences", 0)))
        print("  abiChecks %s (%d checked)" % (checks["status"], checks["checked"]))
        for claim in checks["claims"]:
            if not claim["matches"]:
                print("  MISMATCH %s: source claims %s, BTF says %s"
                      % (claim["abi"], claim["claimed"], claim["btf"]))
        for defect in checks["documentationDefects"]:
            print("  NAMING   %s +%s: source says %s, BTF says %s"
                  % (defect["struct"], defect["offset"],
                     defect["memberNameInSource"], defect["memberNameInBtf"]))
        for lookup in contract["runtimeLookups"]:
            print("  LOOKUP   %-32s %-22s probe=%s"
                  % (lookup["name"], lookup["status"],
                     lookup["mustProbeOnDevice"]))
        l2 = contract["l2"]
        print("  L2       module=%s (%s) kretprobe 0x%x handler@0x%x "
              "entry_handler@0x%x data_size@0x%x"
              % (l2["module"]["name"], l2["module"]["fileName"],
                 contract["structOffsets"]["kretprobe"]["size"],
                 contract["structOffsets"]["kretprobe"]["handler"],
                 contract["structOffsets"]["kretprobe"]["entryHandler"],
                 contract["structOffsets"]["kretprobe"]["dataSize"]))
        print("  L2       pt_regs 0x%x syscallno@0x%x (regs@0x%x sp@0x%x pc@0x%x "
              "pstate@0x%x)"
              % (contract["structOffsets"]["ptRegs"]["size"],
                 contract["structOffsets"]["ptRegs"]["syscallno"],
                 contract["structOffsets"]["ptRegs"]["regs"],
                 contract["structOffsets"]["ptRegs"]["sp"],
                 contract["structOffsets"]["ptRegs"]["pc"],
                 contract["structOffsets"]["ptRegs"]["pstate"]))
        print("  L2       kcfiIds %s; imports %d (+%d cookie param); lookups %d; "
              "blacklist %d"
              % (", ".join("%s=%s" % (key, l2["kcfiIds"][key]["value"])
                           for key in ("preHandler", "kretprobeHandler", "init")),
                 l2["importCount"], len(l2["importsCookieParam"]),
                 l2["runtimeLookupCount"], l2["kprobeBlacklist"]["entries"]))
        print("  L2       cookie param=%s (%s) kernel_param 0x%x ops@0x%x arg@0x%x"
              % (l2["cookieChannel"]["paramOps"],
                 l2["cookieChannel"]["uargs"],
                 l2["cookieChannel"]["kernelParam"]["size"],
                 l2["cookieChannel"]["kernelParam"]["ops"],
                 l2["cookieChannel"]["kernelParam"]["arg"]))
        for row in l2["probes"]:
            print("  L2       probe %-14s %-9s %-28s blacklisted=%s"
                  % (row["id"], row["kind"], row["symbol"], row["blacklisted"]))
        if l2["kcfiMismatches"]:
            print("  MISMATCH l2.kcfiIds: %s" % ", ".join(l2["kcfiMismatches"]))
        if contract["helperPathPolicy"]["status"] == "MISMATCH":
            print("  HELPER   %s != policy %s"
                  % (contract["helperPathPolicy"]["moduleConstant"],
                     contract["helperPathPolicy"]["policyPath"]))
    ok = checks["status"] == "match" and not contract["l2"]["kcfiMismatches"]
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
