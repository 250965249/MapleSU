"""Replica of the kernel module loader's rejection checks, run offline.

Why this exists: `finit_module` returns ENOEXEC for a dozen different reasons and
the device denies dmesg, so the only way to know *which* one fired is to run the same
checks against the same kernel image. Every rule below is transcribed from
kernel/module/main.c, kernel/module/version.c and arch/arm64/kernel/module.c at
v6.6, and each one prints the kernel's own error text so a failure is recognisable.

Inputs: the built .ko, and the kernel image the spec was generated from (for
vermagic and sizeof(struct module) via BTF).

Usage: python loader_contract.py <module.ko> <kernel-image>
Exit 0 = every check the loader performs before running init_module passes.

Part 2 (below `check()`) adds the seven numbered gates G1-G7 for the resident
root module (jailbreak-providers/root-loader), still offline:

    python loader_contract.py --root <maplesu_root.ko> --image <kernel> \
                              --contract <contracts/....json> [--json out.json]

The legacy positional invocation above is unchanged and still runs exactly
`check()`: the IR module keeps its own authority, and no legacy check was
weakened.  Every G-gate number is read from the image (BTF, kallsyms TSV, the
image's own KCFI compare sites) or from the contract; nothing below carries a
per-release kernel address or stride.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

ET_REL, EM_AARCH64 = 1, 183
SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_NOBITS, SHT_RELA = 0, 1, 2, 8, 4
SHT_STRTAB = 3
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4
STT_FUNC = 2

# arch/arm64/kernel/module.c: everything apply_relocate_add() knows how to do.
#
# Numbers fixed per the AArch64 ELF ABI (and cross-checked against llvm-readelf's
# own names for the types this tree emits).  The pre-gate copy of this table was
# labelled one off from 279 upwards and moved the MOVW block to 288-297, which
# meant a future TSTBR14 module was rejected while bogus types were accepted
# (mechanics doc D-4, docs/patching/maplesu-root-build-mechanics-2026-10-29.md
# section 6.3).  No shipped module uses a type whose admission changed: the IR
# module uses 257/275/277/283/285/286 and the root module 257/275/277/278/283/286.
RELOC_SUPPORTED = {
    256: "R_AARCH64_NONE",
    257: "ABS64", 258: "ABS32", 259: "ABS16",
    260: "PREL64", 261: "PREL32", 262: "PREL16",
    263: "MOVW_UABS_G0", 264: "MOVW_UABS_G0_NC", 265: "MOVW_UABS_G1",
    266: "MOVW_UABS_G1_NC", 267: "MOVW_UABS_G2", 268: "MOVW_UABS_G2_NC",
    269: "MOVW_UABS_G3", 270: "MOVW_SABS_G0", 271: "MOVW_SABS_G1",
    272: "MOVW_SABS_G2",
    273: "LD_PREL_LO19", 274: "ADR_PREL_LO21", 275: "ADR_PREL_PG_HI21",
    276: "ADR_PREL_PG_HI21_NC", 277: "ADD_ABS_LO12_NC", 278: "LDST8_ABS_LO12_NC",
    279: "TSTBR14", 280: "CONDBR19", 282: "JUMP26", 283: "CALL26",
    284: "LDST16_ABS_LO12_NC", 285: "LDST32_ABS_LO12_NC", 286: "LDST64_ABS_LO12_NC",
    299: "LDST128_ABS_LO12_NC",
    311: "ADR_GOT_PAGE", 312: "LD64_GOT_LO12_NC",
}

# Known to the kernel, but no module shipped for this image has a .got, so using
# one is an unproven dependency on module_emit_got_entry() (mechanics doc 2.2).
RELOC_GOT = {311, 312}


class Failure(SystemExit):
    pass


def fail(kernel_text: str, detail: str) -> "Failure":
    print("LOADER WOULD REJECT: " + kernel_text)
    print("  " + detail)
    raise SystemExit(1)


class Elf:
    def __init__(self, path: Path):
        self.raw = path.read_bytes()
        if self.raw[:4] != b"\x7fELF" or self.raw[4] != 2 or self.raw[5] != 1:
            fail("Invalid ELF header", "not ELF64 little-endian")
        (self.e_type, self.e_machine, self.e_version, _entry, _phoff, self.e_shoff,
         _flags, _ehsize, _phentsize, _phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", self.raw, 16)
        self.sections = []
        for index in range(self.e_shnum):
            base = self.e_shoff + index * 64
            (name_off, kind, flags, addr, offset, size, link, info, align,
             entsize) = struct.unpack_from("<IIQQQQIIQQ", self.raw, base)
            self.sections.append({"index": index, "name_off": name_off, "type": kind,
                                  "flags": flags, "addr": addr, "offset": offset,
                                  "size": size, "link": link, "info": info,
                                  "align": align, "entsize": entsize})
        names = self.sections[self.e_shstrndx]
        table = self.raw[names["offset"]: names["offset"] + names["size"]]
        for section in self.sections:
            end = table.find(b"\x00", section["name_off"])
            section["name"] = table[section["name_off"]:end].decode()

    def by_name(self, name):
        return next((s for s in self.sections if s["name"] == name), None)

    def bytes_of(self, name):
        s = self.by_name(name)
        return self.raw[s["offset"]: s["offset"] + s["size"]] if s else b""


def btf_struct_module_size(image: bytes) -> int:
    offset = image.find(b"\x9f\xeb\x01\x00")
    if offset < 0:
        fail("no BTF in image", "cannot derive sizeof(struct module)")
    _magic, _ver, _flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", image, offset)
    base = offset + hdr_len
    types = image[base + type_off: base + type_off + type_len]
    strings = image[base + str_off: base + str_off + str_len]

    def name_at(off):
        if off == 0:
            return ""
        end = strings.find(b"\x00", off)
        return strings[off:end].decode("utf-8", "replace")

    cursor = 0
    while cursor < len(types):
        name_off, info, size_type = struct.unpack_from("<III", types, cursor)
        kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
        cursor += 12
        if kind == 1:
            cursor += 4
        elif kind == 3:
            cursor += 12
        elif kind in (4, 5):
            if name_at(name_off) == "module" and kind == 4:
                return size_type
            cursor += 12 * vlen
        elif kind in (6, 13):
            cursor += 8 * vlen
        elif kind == 14:
            cursor += 4
        elif kind == 15:
            cursor += 12 * vlen
        elif kind == 17:
            cursor += 4
        elif kind == 19:
            cursor += 12 * vlen
    fail("no BTF struct module", "image BTF has no struct module")


def kernel_vermagic(image: bytes) -> str:
    marker = b" SMP preempt mod_unload modversions aarch64\x00"
    end = image.find(marker)
    if end < 0:
        fail("no vermagic in image", "cannot compare vermagic")
    start = end
    while start > 0 and 0x20 <= image[start - 1] <= 0x7E:
        start -= 1
    return image[start:end + len(marker) - 1].decode()


def check(module_path: Path, image_path: Path) -> None:
    image = image_path.read_bytes()
    elf = Elf(module_path)
    print("module: %s (%d bytes)" % (module_path.name, len(elf.raw)))

    # --- elf_validity_check / elf_validity_cache_copy ---------------------- #
    if elf.e_type != ET_REL:
        fail("Invalid ELF header type", "e_type=%d" % elf.e_type)
    if elf.e_machine != EM_AARCH64:
        fail("Invalid architecture in ELF header", "e_machine=%d" % elf.e_machine)
    if elf.e_shentsize != 64:
        fail("Invalid ELF section header size", "e_shentsize=%d" % elf.e_shentsize)
    if elf.e_shoff >= len(elf.raw) or elf.e_shnum * 64 > len(elf.raw) - elf.e_shoff:
        fail("Invalid ELF section header overflow", "shoff/shnum")
    if elf.e_shstrndx == 0 or elf.e_shstrndx >= elf.e_shnum:
        fail("Invalid ELF section name index", "e_shstrndx")
    shstr = elf.sections[elf.e_shstrndx]
    if shstr["size"] == 0 or elf.raw[shstr["offset"] + shstr["size"] - 1] != 0:
        fail("ELF Spec violation: section name table isn't null terminated", "")
    zero = elf.sections[0]
    if zero["type"] != SHT_NULL or zero["size"] != 0 or zero["addr"] != 0:
        fail("ELF Spec violation: section 0", "type/size/addr")

    symtabs, mods, info_secs = 0, [], []
    for section in elf.sections[1:]:
        if section["type"] in (SHT_NULL, SHT_NOBITS):
            continue
        if section["type"] == SHT_SYMTAB:
            if section["link"] == 0 or section["link"] >= elf.e_shnum:
                fail("Invalid ELF sh_link", "symtab sh_link")
            symtabs += 1
        if section["offset"] + section["size"] > len(elf.raw):
            fail("Invalid ELF section in module", section["name"])
        if section["name"] == ".gnu.linkonce.this_module":
            mods.append(section)
        elif section["name"] == ".modinfo":
            info_secs.append(section)
    if symtabs != 1:
        fail("module has no symbols (stripped?)", "SHT_SYMTAB count=%d" % symtabs)
    if len(info_secs) > 1:
        fail("Only one .modinfo section must exist.", "")
    if len(mods) != 1:
        fail("Only one .gnu.linkonce.this_module section must exist.", "")
    this_module = mods[0]
    if this_module["type"] == SHT_NOBITS:
        fail("this_module must have a size set", "")
    if not this_module["flags"] & SHF_ALLOC:
        fail("this_module must occupy memory", "SHF_ALLOC missing")
    expected = btf_struct_module_size(image)
    if this_module["size"] != expected:
        fail("this_module section size must match the kernel's built struct module size",
             "module has 0x%x, running kernel BTF says 0x%x"
             % (this_module["size"], expected))
    print("  this_module 0x%x == BTF sizeof(struct module) 0x%x"
          % (this_module["size"], expected))

    # --- check_modinfo / same_magic ---------------------------------------- #
    tags = {}
    for entry in elf.bytes_of(".modinfo").split(b"\x00"):
        if entry:
            key, _, value = entry.partition(b"=")
            tags[key.decode()] = value.decode(errors="replace")
    kernel_magic = kernel_vermagic(image)
    if tags.get("vermagic") != kernel_magic:
        fail("version magic '%s' should be '%s'" % (tags.get("vermagic"), kernel_magic), "")
    print("  vermagic matches the image exactly")

    # --- arch/arm64/kernel/module.c module_init_plt() ---------------------- #
    # This is the rule the first replica missed: arm64's finalizer looks up `.plt`
    # and `.init.plt` and returns -ENOEXEC with "module PLT section(s) missing" when
    # either is absent. Every build before this check existed was refused on device
    # for exactly that reason, and the offline replica said it was fine.
    for required in (".plt", ".init.plt"):
        section = elf.by_name(required)
        if section is None:
            fail("module PLT section(s) missing", required + " is absent")
        if section["type"] == SHT_NOBITS:
            fail("module PLT section(s) missing", required + " is NOBITS")
    print("  .plt/.init.plt present (arm64 module_init_plt requirement)")

    # --- check_modstruct_version / check_version --------------------------- #
    versions = elf.by_name("__versions")
    if versions is None:
        fail("bad vermagic (no __versions -> try_to_force_load)",
             "CONFIG_MODULE_FORCE_LOAD is off, so this is fatal")
    entries = versions["size"] // 64
    names = []
    for index in range(entries):
        raw = elf.bytes_of("__versions")[index * 64 + 8:(index + 1) * 64]
        names.append(raw.split(b"\x00")[0].decode(errors="replace"))
    if "module_layout" in names:
        fail("disagrees about version of symbol module_layout", "we cannot supply its CRC")
    print("  __versions present (%d entries), no module_layout pin: accepted by design"
          % entries)

    # --- apply_relocate_add ------------------------------------------------ #
    unknown = set()
    counts = {}
    for section in elf.sections:
        if section["type"] != SHT_RELA:
            continue
        for index in range(section["size"] // 24):
            base = section["offset"] + index * 24
            _off, info, _addend = struct.unpack_from("<QQq", elf.raw, base)
            reloc = info & 0xFFFFFFFF
            counts[reloc] = counts.get(reloc, 0) + 1
            if reloc not in RELOC_SUPPORTED:
                unknown.add(reloc)
    if unknown:
        fail("Unknown RELA type", ", ".join(str(value) for value in sorted(unknown)))
    print("  relocation types: " + ", ".join(
        "%s=%d" % (RELOC_SUPPORTED[key], value) for key, value in sorted(counts.items())))
    print("RESULT: every pre-init loader check passes")


def _legacy_main(argv) -> int:
    """The original CLI, unchanged: two positionals, `check()`, exit 0."""
    if len(argv) != 2:
        raise SystemExit(__doc__)
    check(Path(argv[0]), Path(argv[1]))
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if any(arg in ("--root", "--image", "--contract", "--json", "--help", "-h") or
           arg.startswith("--root=") for arg in argv):
        return _gates_main(argv)
    return _legacy_main(argv)


# --------------------------------------------------------------------------- #
# Part 2 -- the seven numbered gates G1..G7 for the resident root module.
#
# What each gate means here (the definitions the build script and the tests rely
# on; docs/patching/maplesu-root-build-mechanics-2026-10-29.md is the source):
#
#   G1 layout        ELF envelope from check(); this_module size == BTF
#                    sizeof(struct module); name/init/exit at BTF's offsets (the
#                    init/exit fields must resolve to init_module/cleanup_module);
#                    .modinfo license=GPL and vermagic == the image's own string;
#                    __versions present, whole entries, no module_layout pin.
#   G2 PLT sections  .plt/.init.plt PROGBITS+AX and non-empty; ftrace trampoline
#                    present; every allocated section placeable (in-file,
#                    aligned) and PROGBITS allocations not overlapping.
#   G3 importability imports == the design's four (memset tolerated); each name
#                    has a __ksymtab_<name> row in the image TSV (line quoted);
#                    the row sits inside the TSV's own __ksymtab/_gpl bounds;
#                    GPL-only imports require license=GPL; forbidden names absent.
#   G4 cleanup_module defined FUNC, non-zero value, allocated+executable and not
#                    .init.text; this_module.exit is its ABS64 address.
#   G5 patch plan    no .ir_spec/banner; no kernel VA at any byte offset in an
#                    allocated section or in a RELA addend; relocation types are
#                    arm64's and no GOT form; no `mov w3,#2` (UMH_WAIT_PROC) and
#                    every call_usermodehelper passes w3=1; one /data helper path
#                    consistent with the contract's D-5 record (a recorded
#                    mismatch is allowed, a third path is not); the success
#                    branch's marker string and the encoded w0 returns (0 plus
#                    the contract's -errno values) exist; lookup names are the
#                    contract's runtime-lookup set.  With
#                    config.staticUsermodehelperPath == "" the four-argument
#                    wrapper cannot exec on this kernel, so the gate additionally
#                    requires the two-stage handover the contract names
#                    (call_usermodehelper_setup + call_usermodehelper_exec in the
#                    lookup set) *and* the 64-bit store at
#                    structOffsets.subprocessInfo.path that is the fix itself; a
#                    module carrying only the wrapper fails here.  The gate emits
#                    the symbolic five-step plan it validated ("patchPlan").
#                    "return 0 means handed-over-and-resident" is a source-level
#                    claim; the binary proxy is the marker/return encoding plus the
#                    reachable restore point (G4).  It is explicitly *not* proof
#                    that the helper ran: the helper's side effect is.
#   G6 KCFI          init_module's 4-byte prefix == contract kcfiInitTypeId ==
#                    the id do_one_initcall compares; cleanup_module's prefix ==
#                    the id __arm64_sys_delete_module compares; ZERO BRK in every
#                    SHF_EXECINSTR section (panic_on_oops=1 and no
#                    CFI_PERMISSIVE, so any trap is a panic), no kCFI compare site
#                    left (every indirect call is in a __nocfi function), and the
#                    recorded build flags contain -fsanitize=kcfi and
#                    -ffixed-x18 plus the source-level __nocfi intent, none of
#                    which a binary can show.
#   G7 struct shim   an independent BTF parse (this file's own parser) of struct
#                    module/kprobe/selinux_state/subprocess_info against
#                    kernel_compat.h's declarations *and* its _Static_asserts and
#                    the contract's numbers/type ids/structOffsets.  A wrong header
#                    is exactly what this gate exists to catch; subprocess_info.path
#                    is the field whose offset the static-UMH fix depends on.
#
# Rules this part keeps, so that a gate cannot be a decorative PASS:
#   * every layout number is re-derived from the image (its own BTF), every KCFI
#     id from the image's own compare sites/prefixes, every export fact from the
#     kallsyms TSV the contract names -- there is no per-release address table;
#   * a gate that records no fatal check is a FAILURE, so an accidentally empty
#     gate cannot pass;
#   * G7 re-parses the BTF with its own parser (it does not import
#     derive_contract.py), which is what makes it able to catch a wrong header.
# --------------------------------------------------------------------------- #

KERNEL_VA_LOW, KERNEL_VA_HIGH = 0xFFFFFF8000000000, 0xFFFFFFFFFFFFFFFF

# The four imports the design makes (G3).  The contract must agree; the gate
# fails if it does not, so this constant cannot drift silently.
# call_usermodehelper is resolved through kallsyms, not imported: the 5.15 and 6.1
# vendor images export no __ksymtab_call_usermodehelper, so an import would fail the
# load there. The three below are the module's remaining undefined symbols.
DESIGN_IMPORTS = frozenset({"register_kprobe", "unregister_kprobe", "_printk"})
# An image that does export it may still see it as an optional import.
OPTIONAL_IMPORTS = frozenset({"call_usermodehelper"})
# Resolved through kallsyms instead of imported, so it must be an allowed lookup even
# though the contract's runtime-lookup set predates the change.
OPTIONAL_LOOKUPS = frozenset({"call_usermodehelper"})
TOLERATED_IMPORTS = frozenset({"memset"})

# asm-generic/errno-base.h + errno.h values the module returns.  Python's
# `errno` module is the *host* CRT's (on Windows ENOSYS is 40, on Linux 38), so
# it must not be used to decode the contract's -ENOSYS/-ENOENT.
KERNEL_ERRNO = {
    "EPERM": 1, "ENOENT": 2, "ESRCH": 3, "EINTR": 4, "EIO": 5, "ENXIO": 6,
    "E2BIG": 7, "ENOEXEC": 8, "EBADF": 9, "ECHILD": 10, "EAGAIN": 11,
    "ENOMEM": 12, "EACCES": 13, "EFAULT": 14, "EBUSY": 16, "EEXIST": 17,
    "EXDEV": 18, "ENODEV": 19, "ENOTDIR": 20, "EISDIR": 21, "EINVAL": 22,
    "ENFILE": 23, "EMFILE": 24, "ENOTTY": 25, "ETXTBSY": 26, "EFBIG": 27,
    "ENOSPC": 28, "ESPIPE": 29, "EROFS": 30, "EMLINK": 31, "EPIPE": 32,
    "EDOM": 33, "ERANGE": 34, "EDEADLK": 35, "ENAMETOOLONG": 36, "ENOLCK": 37,
    "ENOSYS": 38, "ENOTEMPTY": 39, "ELOOP": 40, "ENOMSG": 42, "EIDRM": 43,
    "EOVERFLOW": 75, "EILSEQ": 84, "ENOTSOCK": 88, "EMSGSIZE": 90,
    "EOPNOTSUPP": 95, "EADDRINUSE": 98, "EADDRNOTAVAIL": 99,
    "ENETUNREACH": 101, "ECONNRESET": 104, "ETIMEDOUT": 110,
    "ECONNREFUSED": 111, "EHOSTUNREACH": 113, "EALREADY": 114,
    "EINPROGRESS": 115, "ESTALE": 116, "EDQUOT": 122, "ECANCELED": 125,
    "EKEYREJECTED": 129,
}

BTF_MAGIC = b"\x9f\xeb\x01\x00"
BTF_STRUCT_KIND = 4

GATE_TABLE = (
    ("G1", "layout", "_gate_layout"),
    ("G2", "PLT sections", "_gate_plt"),
    ("G3", "importability", "_gate_imports"),
    ("G4", "cleanup_module", "_gate_cleanup"),
    ("G5", "patch plan", "_gate_patch_plan"),
    ("G6", "KCFI", "_gate_kcfi"),
    ("G7", "struct shim vs BTF", "_gate_struct_shim"),
)


class _GateError(Exception):
    """An input the gate cannot evaluate (missing file, unparsable image)."""


class _Gate:
    """Collects checks for one gate; `ok` needs at least one fatal check."""

    def __init__(self, gate_id: str, name: str):
        self.id = gate_id
        self.name = name
        self.checks: list = []
        self.extras: dict = {}
        self.error = None
        self.skipped = False
        self.skip_reason = ""

    def check(self, ok, what, detail="", fatal=True):
        self.checks.append({"ok": bool(ok), "what": what, "detail": detail,
                            "fatal": bool(fatal)})
        return bool(ok)

    def require(self, ok, what, detail=""):
        return self.check(ok, what, detail, True)

    @property
    def ok(self):
        if self.skipped:
            return True
        if self.error:
            return False
        fatal = [entry for entry in self.checks if entry["fatal"]]
        if not fatal:
            return False
        return all(entry["ok"] for entry in fatal)

    def result(self) -> dict:
        fatal = [entry for entry in self.checks if entry["fatal"]]
        failed = [entry for entry in fatal if not entry["ok"]]
        if self.skipped:
            detail = self.skip_reason
        elif self.error:
            detail = "gate could not be evaluated: " + self.error
        elif not fatal:
            detail = "gate recorded no fatal check (a gate must test something)"
        elif failed:
            detail = "; ".join("%s -> %s" % (entry["what"], entry["detail"] or "failed")
                               for entry in failed[:4])
        else:
            detail = "; ".join(entry["what"] for entry in fatal)
        if len(detail) > 420:
            detail = detail[:417] + "..."
        result = {"id": self.id, "name": self.name, "ok": self.ok, "detail": detail,
                  "checks": self.checks, "extras": self.extras}
        if self.skipped:
            result["skipped"] = True
        return result


# --------------------------------------------------------------------------- #
# Small readers: symbols, relocations, strings, BTF.
# --------------------------------------------------------------------------- #

def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def _align_up(value: int, align: int) -> int:
    return (value + align - 1) // align * align


def _section_bytes(elf: Elf, section) -> bytes:
    if section is None or section["type"] == SHT_NOBITS:
        return b""
    return elf.raw[section["offset"]: section["offset"] + section["size"]]


def _elf_symbols(elf: Elf) -> list:
    table = next((section for section in elf.sections
                  if section["type"] == SHT_SYMTAB), None)
    if table is None:
        return []
    strings = elf.sections[table["link"]]
    strtab = elf.raw[strings["offset"]: strings["offset"] + strings["size"]]
    out = []
    for index in range(table["size"] // 24):
        base = table["offset"] + index * 24
        name_off, info, _other, shndx, value, size = struct.unpack_from(
            "<IBBHQQ", elf.raw, base)
        end = strtab.find(b"\x00", name_off)
        out.append({"name": strtab[name_off:end].decode("utf-8", "replace"),
                    "info": info, "type": info & 0xF, "bind": info >> 4,
                    "shndx": shndx, "value": value, "size": size})
    return out


def _elf_imports(elf: Elf) -> list:
    return sorted({symbol["name"] for symbol in _elf_symbols(elf)
                   if symbol["shndx"] == 0 and symbol["name"]})


def _elf_relocations(elf: Elf) -> dict:
    symbols = _elf_symbols(elf)
    out: dict = {}
    for section in elf.sections:
        if section["type"] != SHT_RELA:
            continue
        target = (elf.sections[section["info"]]
                  if 0 < section["info"] < len(elf.sections) else None)
        if target is None:
            continue
        entries = out.setdefault(target["name"], [])
        for index in range(section["size"] // 24):
            base = section["offset"] + index * 24
            offset, info, addend = struct.unpack_from("<QQq", elf.raw, base)
            type_id = info & 0xFFFFFFFF
            symbol_index = info >> 32
            symbol = symbols[symbol_index] if symbol_index < len(symbols) else None
            entries.append({"offset": offset, "type": type_id,
                            "typeName": RELOC_SUPPORTED.get(type_id, "UNKNOWN"),
                            "addend": addend, "symbolIndex": symbol_index,
                            "symbol": symbol["name"] if symbol else "",
                            "symbolValue": symbol["value"] if symbol else 0})
    return out


class _Tsv:
    """The kallsyms-style `address<TAB>kind<TAB>name` list, with line numbers.

    Line numbers matter: G3 quotes the TSV line that proves an export exists.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.rows: dict = {}
        self.addresses: list = []
        text = self.path.read_text(encoding="utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), 1):
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) != 3 or parts[0].startswith("#"):
                continue
            try:
                address = int(parts[0])
            except ValueError:
                continue
            row = {"address": address, "kind": parts[1], "name": parts[2],
                   "line": line_number, "text": line}
            self.rows.setdefault(parts[2], []).append(row)
            self.addresses.append(address)
        self.addresses.sort()

    def lookup(self, name: str) -> list:
        return self.rows.get(name, [])

    def address(self, name: str):
        rows = self.rows.get(name)
        return rows[0]["address"] if rows else None

    def next_address(self, address: int, limit: int = 0x900) -> int:
        low, high = 0, len(self.addresses)
        while low < high:
            middle = (low + high) // 2
            if self.addresses[middle] <= address:
                low = middle + 1
            else:
                high = middle
        if low >= len(self.addresses):
            return address + limit
        return min(self.addresses[low], address + limit)


class _Btf:
    """A minimal, independent BTF reader (kernel/bpf/btf.c encoding).

    Deliberately not shared with contracts/derive_contract.py: G7's job is to
    check that generator's output against a second implementation.
    """

    def __init__(self, image: bytes, magic_offset=None):
        if magic_offset is None:
            offset = self._find(image)
        else:
            offset = int(magic_offset)
            if image[offset:offset + 4] != BTF_MAGIC:
                raise _GateError("contract says BTF magic is at 0x%x, image has %r there"
                                 % (offset, image[offset:offset + 4]))
        (_magic, version, _flags, header_len, type_off, type_len, str_off,
         str_len) = struct.unpack_from("<HBBIIIII", image, offset)
        if version != 1 or header_len != 24:
            raise _GateError("BTF header at 0x%x is version %d/%d bytes (expected 1/24)"
                             % (offset, version, header_len))
        base = offset + header_len
        if base + type_off + type_len > len(image) or base + str_off + str_len > len(image):
            raise _GateError("BTF header at 0x%x runs past EOF" % offset)
        self.blob_offset = offset
        self.type_bytes = type_len
        self.string_bytes = str_len
        self.types_blob = image[base + type_off: base + type_off + type_len]
        self.strings = image[base + str_off: base + str_off + str_len]
        self.types = self._parse()

    @staticmethod
    def _find(image: bytes):
        offset = image.find(BTF_MAGIC)
        while offset >= 0:
            if offset + 24 <= len(image):
                _magic, version, _flags, header_len, type_off, type_len, str_off, \
                    str_len = struct.unpack_from("<HBBIIIII", image, offset)
                if version == 1 and header_len == 24:
                    base = offset + header_len
                    if base + type_off + type_len <= len(image) and \
                            base + str_off + str_len <= len(image):
                        return offset
            offset = image.find(BTF_MAGIC, offset + 1)
        raise _GateError("image carries no BTF blob")

    def _name(self, offset: int) -> str:
        if offset == 0:
            return ""
        end = self.strings.find(b"\x00", offset)
        return self.strings[offset:end].decode("utf-8", "replace")

    def _parse(self) -> list:
        out = [None]  # BTF type ids are 1-based
        cursor = 0
        types = self.types_blob
        while cursor < len(types):
            name_off, info, size_type = struct.unpack_from("<III", types, cursor)
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            kflag = info >> 31
            record = {"id": len(out), "name": self._name(name_off), "kind": kind,
                      "vlen": vlen, "size": size_type, "members": []}
            cursor += 12
            if kind in (4, 5):                       # STRUCT / UNION
                for _ in range(vlen):
                    member_name, member_type, member_offset = struct.unpack_from(
                        "<III", types, cursor)
                    cursor += 12
                    bits = (member_offset & 0xFFFFFF) if kflag else member_offset
                    record["members"].append({"name": self._name(member_name),
                                              "type": member_type,
                                              "bit": bits, "byte": bits // 8})
            elif kind == 1:                          # INT
                cursor += 4
            elif kind == 3:                          # ARRAY
                cursor += 12
            elif kind == 6:                          # ENUM
                cursor += 8 * vlen
            elif kind == 13:                         # FUNC_PROTO
                cursor += 8 * vlen
            elif kind == 14:                         # VAR
                cursor += 4
            elif kind == 15:                         # DATASEC
                cursor += 12 * vlen
            elif kind == 17:                         # DECL_TAG
                cursor += 4
            elif kind == 19:                         # ENUM64
                cursor += 12 * vlen
            elif kind in (0, 2, 7, 8, 9, 10, 11, 12, 16, 18):
                pass                                 # no trailing data
            else:
                raise _GateError("unsupported BTF kind %d at type id %d"
                                 % (kind, record["id"]))
            out.append(record)
        if cursor != len(types):
            raise _GateError("BTF types desynchronised at %d of %d bytes"
                             % (cursor, len(types)))
        return out

    def structs(self, name: str) -> list:
        return [(record["id"], record) for record in self.types
                if record and record["kind"] == BTF_STRUCT_KIND and record["name"] == name]

    def struct(self, name: str):
        hits = self.structs(name)
        if not hits:
            raise _GateError("image BTF has no struct %s" % name)
        return hits[0][1]

    @staticmethod
    def member(struct, name: str):
        for entry in struct["members"]:
            if entry["name"] == name:
                return entry
        raise _GateError("BTF struct %s has no member %s" % (struct["name"], name))


# --------------------------------------------------------------------------- #
# AArch64 decoders: only the instructions a gate makes a claim about.
# --------------------------------------------------------------------------- #

def _movz(insn: int):
    if (insn & 0x7F800000) == 0x52800000:
        return insn & 0x1F, (insn >> 5) & 0xFFFF, (insn >> 21) & 0x3
    return None


def _movn(insn: int):
    if (insn & 0x7F800000) == 0x12800000:
        return insn & 0x1F, (insn >> 5) & 0xFFFF, (insn >> 21) & 0x3
    return None


def _movk(insn: int):
    if (insn & 0x7F800000) == 0x72800000:
        return insn & 0x1F, (insn >> 5) & 0xFFFF, (insn >> 21) & 0x3
    return None


def _mov_wzr(insn: int):
    """`mov wN, wzr` == ORR wN, wzr, wzr -> register number or None."""
    if (insn & 0xFFFFFFE0) == 0x2A1F03E0:
        return insn & 0x1F
    return None


def _cmp_reg(insn: int):
    if (insn & 0xFF200000) == 0x6B000000 and (insn & 0x1F) == 31:
        return (insn >> 5) & 0x1F, (insn >> 16) & 0x1F
    return None


def _is_blr(insn: int) -> bool:
    return (insn & 0xFFFFFC1F) == 0xD63F0000


def _is_beq(insn: int) -> bool:
    """B.cond with cond == EQ (0): imm19 in bits 5..23, cond in bits 0..3."""
    return (insn & 0xFF00001F) == 0x54000000 and (insn & 0xF) == 0


def _brk_imm(insn: int):
    if (insn & 0xFFE0001F) == 0xD4200000:
        return (insn >> 5) & 0xFFFF
    return None


def _str_uoffset(insn: int):
    """`str xN, [xM, #imm]` (64-bit, unsigned scaled offset) -> (rt, rn, imm)."""
    if (insn & 0xFFC00000) != 0xF9000000:
        return None
    return insn & 0x1F, (insn >> 5) & 0x1F, ((insn >> 10) & 0xFFF) * 8


def _str_offset_sites(ctx, offset: int) -> list:
    """Every `str xN, [xM, #offset]` in module text, as `section+0x..`.

    G5 uses this to find the subprocess_info.path store: on a static-UMH kernel the
    entire fix is one 64-bit store at that offset after call_usermodehelper_setup()
    returned, so "the module carries the fix" is a byte-level fact, not a comment.
    """
    hits = []
    for section in ctx.exec_sections():
        code = _section_bytes(ctx.elf, section)
        for index in range(len(code) // 4):
            decoded = _str_uoffset(_u32(code, index * 4))
            if decoded is not None and decoded[2] == offset:
                hits.append({"section": section["name"], "offset": index * 4,
                             "rt": decoded[0], "rn": decoded[1]})
    return hits


def _kcfi_sites(code: bytes, require_blr: bool = True) -> list:
    """Every `movk wT,#lo ; movk wT,#hi,lsl#16 ; cmp wC,wT` type id in `code`.

    clang's kCFI check has exactly that shape and the failure path reaches a
    BLR within the next four instructions, which is what separates a real check
    from a data constant (clang builds constants with movz, not movk+movk).
    """
    words = [struct.unpack_from("<I", code, index * 4)[0]
             for index in range(len(code) // 4)]
    out = []
    for index in range(len(words) - 2):
        low = _movk(words[index])
        if not low or low[2] != 0:
            continue
        high = _movk(words[index + 1])
        if not high or high[2] != 1 or high[0] != low[0]:
            continue
        compare = _cmp_reg(words[index + 2])
        if not compare or compare[1] != low[0]:
            continue
        tail = words[index + 3: index + 7]
        if require_blr and not any(_is_blr(word) for word in tail):
            continue
        out.append({"instruction": index,
                    "typeId": (high[1] << 16) | low[1]})
    return out


def _first_kcfi_site(code: bytes):
    hits = _kcfi_sites(code, require_blr=True)
    return hits[0] if hits else None


# --------------------------------------------------------------------------- #
# C layout of the shim header (what kernel_compat.h *claims*).
# --------------------------------------------------------------------------- #

_C_TYPE_INFO = {"u8": (1, 1), "u16": (2, 2), "u32": (4, 4), "u64": (8, 8),
                "uptr": (8, 8)}


def _eval_count(expression: str) -> int:
    expression = expression.strip()
    if not re.fullmatch(r"[0-9a-fA-FxX\s+\-*/()]+", expression):
        raise _GateError("unsupported array bound %r" % expression)
    try:
        value = eval(expression, {"__builtins__": {}}, {})   # noqa: S307 - integers only
    except Exception as error:                                # noqa: BLE001
        raise _GateError("array bound %r does not evaluate: %r" % (expression, error))
    if not isinstance(value, int) or value < 0:
        raise _GateError("array bound %r is not a nonnegative integer" % expression)
    return value


def _c_struct_layout(text: str, struct_name: str) -> dict:
    """Compute sizeof/offsetof for the simple structs in kernel_compat.h."""
    match = re.search(r"struct\s+%s\s*\{" % re.escape(struct_name), text)
    if match is None:
        raise _GateError("header has no struct %s" % struct_name)
    end = text.find("};", match.end())
    if end < 0:
        raise _GateError("struct %s is not terminated" % struct_name)
    body = text[match.end():end]
    body = re.sub(r"/\*.*?\*/", " ", body, flags=re.S)
    body = re.sub(r"//[^\n]*", " ", body)
    offset, max_align, members = 0, 1, {}
    for declaration in body.split(";"):
        declaration = " ".join(declaration.split())
        if not declaration:
            continue
        parsed = re.match(
            r"^(?P<type>(?:const\s+)?char\s*\*|u8|u16|u32|u64|uptr)\s*"
            r"(?P<name>[A-Za-z_]\w*)(?:\s*\[(?P<count>[^\]]+)\])?$", declaration)
        if parsed is None:
            raise _GateError("cannot parse struct %s member %r"
                             % (struct_name, declaration))
        type_name = " ".join(parsed.group("type").split())
        if "*" in type_name:
            size, align = 8, 8
        else:
            size, align = _C_TYPE_INFO[type_name]
        count = 1 if parsed.group("count") is None else _eval_count(
            parsed.group("count"))
        offset = _align_up(offset, align)
        members[parsed.group("name")] = offset
        offset += size * count
        max_align = max(max_align, align)
    return {"name": struct_name, "size": _align_up(offset, max_align),
            "members": members, "maxAlign": max_align}


def _header_asserts(text: str) -> dict:
    out = {"sizeof": {}, "offsetof": {}}
    for match in re.finditer(
            r"_Static_assert\(\s*sizeof\(\s*struct\s+(\w+)\s*\)\s*==\s*"
            r"(0x[0-9a-fA-F]+|\d+)", text):
        out["sizeof"][match.group(1)] = int(match.group(2), 0)
    for match in re.finditer(
            r"_Static_assert\(\s*__builtin_offsetof\(\s*struct\s+(\w+)\s*,\s*"
            r"(\w+)\s*\)\s*==\s*(0x[0-9a-fA-F]+|\d+)", text):
        out["offsetof"].setdefault(match.group(1), {})[match.group(2)] = int(
            match.group(3), 0)
    return out


# --------------------------------------------------------------------------- #
# Context: the module, the image, the contract, and the facts read from them.
# --------------------------------------------------------------------------- #

_IMAGE_CACHE: dict = {}
_BTF_CACHE: dict = {}
_TSV_CACHE: dict = {}


def _project_root(anchor: Path):
    resolved = Path(anchor).resolve()
    for candidate in [resolved] + list(resolved.parents):
        if (candidate / "jailbreak-providers").is_dir() and \
                (candidate / ".analysis").is_dir():
            return candidate
    return None


def _resolve_input(project_root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    candidate = project_root / path
    return candidate if candidate.exists() else Path.cwd() / path


def _nocfi_covers(source: str, function: str) -> bool:
    """True when MAPLESU_NOCFI is attached to `function`'s own declaration.

    Comments are stripped first, then each attribute occurrence is followed to the
    end of its declaration (`;` or the body's `{`) -- so the attribute has to be on
    *this* function, not merely somewhere above it.
    """
    text = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    for match in re.finditer(r"MAPLESU_NOCFI", text):
        window = text[match.end(): match.end() + 240]
        stops = [index for index in (window.find(";"), window.find("{"))
                 if index >= 0]
        cut = min(stops) if stops else len(window)
        if re.search(r"\b%s\s*\(" % re.escape(function), window[:cut]):
            return True
    return False


def _default_header(contract_path: Path, project_root: Path) -> Path:
    candidate = project_root / "jailbreak-providers" / "root-loader" / "module" / \
        "kernel_compat.h"
    if candidate.is_file():
        return candidate
    return contract_path.resolve().parents[1] / "module" / "kernel_compat.h"


def _recorded_build_flags(module_path: Path, project_root: Path):
    """The compiler flags recorded for this module, or None when nothing recorded them.

    G6 asserts -fsanitize=kcfi is among them; the binary cannot show a flag that
    produced it. A fresh build passes its in-memory list, --verify-only and the tests
    fall back to the build record, first beside the artifact and then beside the
    sources (a copied .ko has no build.json of its own).
    """
    candidates = [Path(module_path).parent / "build.json"]
    candidates.append(project_root / "jailbreak-providers" / "root-loader" / "build"
                      / "build.json")
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            record = json.loads(candidate.read_text(encoding="utf-8"))
        except Exception:                          # noqa: BLE001 - a broken record is
            continue                               # "no record", reported by the gate
        flags = record.get("cflags") or record.get("compileFlags")
        if isinstance(flags, list) and flags:
            return list(flags)
    return None


def _cached_image(path: Path) -> bytes:
    stat = path.stat()
    key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
    if key not in _IMAGE_CACHE:
        _IMAGE_CACHE[key] = path.read_bytes()
    return _IMAGE_CACHE[key]


def _load_btf(image_path: Path, image: bytes, magic_offset):
    stat = image_path.stat()
    key = (str(image_path.resolve()), stat.st_mtime_ns, stat.st_size,
           magic_offset)
    if key not in _BTF_CACHE:
        _BTF_CACHE[key] = _Btf(image, magic_offset)
    return _BTF_CACHE[key]


def _load_tsv(path: Path) -> _Tsv:
    stat = path.stat()
    key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
    if key not in _TSV_CACHE:
        _TSV_CACHE[key] = _Tsv(path)
    return _TSV_CACHE[key]


def _image_vermagic(image: bytes) -> str:
    """The same rule as kernel_vermagic(), but raising instead of exiting."""
    marker = b" SMP preempt mod_unload modversions aarch64\x00"
    end = image.find(marker)
    if end < 0:
        raise _GateError("image carries no vermagic string")
    start = end
    while start > 0 and 0x20 <= image[start - 1] <= 0x7E:
        start -= 1
    return image[start:end + len(marker) - 1].decode()


def _derive_image_facts(ctx) -> dict:
    """Every KCFI id this build must agree with, read out of the image bytes.

    kallsyms_lookup_name / aarch64_insn_patch_text: the 4-byte type prefix clang
    put in front of the function.  do_one_initcall / __arm64_sys_delete_module:
    the immediate the image's own compare site builds before it calls
    mod->init / mod->exit.
    """
    facts: dict = {}
    for name in ("kallsyms_lookup_name", "aarch64_insn_patch_text"):
        address = ctx.tsv.address(name)
        if address is None:
            raise _GateError("image symbol list has no %s" % name)
        if address < 4 or address + 4 > len(ctx.image):
            raise _GateError("%s at 0x%x has no readable prefix" % (name, address))
        facts[name] = {"address": address, "prefix": _u32(ctx.image, address - 4),
                       "tsvLine": ctx.tsv.lookup(name)[0]["line"]}
    for name, label in (("do_one_initcall", "init"),
                        ("__arm64_sys_delete_module", "exit")):
        address = ctx.tsv.address(name)
        if address is None:
            raise _GateError("image symbol list has no %s" % name)
        end = ctx.tsv.next_address(address, 0x900)
        site = _first_kcfi_site(ctx.image[address:end])
        if site is None:
            raise _GateError("no KCFI compare site in %s (0x%x..0x%x)"
                             % (name, address, end))
        facts[label] = {"function": name, "address": address,
                        "siteOffset": site["instruction"] * 4,
                        "siteAddress": address + site["instruction"] * 4,
                        "typeId": site["typeId"]}
    return facts


class _Context:
    def __init__(self, module_path, image_path, contract, contract_path,
                 header_path=None, build_flags=None, root=True):
        self.module_path = Path(module_path)
        self.image_path = Path(image_path)
        self.contract = contract
        self.contract_path = Path(contract_path)
        self.root = bool(root)
        self.project_root = None
        for anchor in (self.contract_path, self.image_path, self.module_path):
            self.project_root = _project_root(anchor)
            if self.project_root is not None:
                break
        if self.project_root is None:
            self.project_root = Path.cwd()
        self.build_flags = (list(build_flags) if build_flags else
                            _recorded_build_flags(self.module_path, self.project_root))
        self.image = _cached_image(self.image_path)
        self.image_sha256 = hashlib.sha256(self.image).hexdigest()
        expected_sha = contract.get("imageSha256")
        if expected_sha and self.image_sha256 != expected_sha:
            raise _GateError("image sha256 %s is not the contract's %s"
                             % (self.image_sha256[:16], expected_sha[:16]))
        self.elf = Elf(self.module_path)
        self.sections = self.elf.sections
        symbols_path = _resolve_input(self.project_root,
                                      contract.get("symbolsPath", ""))
        if not symbols_path.is_file():
            raise _GateError("symbol list %s does not exist" % symbols_path)
        self.symbols_path = symbols_path
        self.tsv = _load_tsv(symbols_path)
        self.btf = _load_btf(self.image_path, self.image,
                             contract.get("btf", {}).get("magicOffset"))
        self.header_path = Path(header_path) if header_path else \
            _default_header(self.contract_path, self.project_root)
        self.imports = _elf_imports(self.elf)
        self.symbols = _elf_symbols(self.elf)
        self.relocations = _elf_relocations(self.elf)
        self.vermagic = _image_vermagic(self.image)
        self.image_facts = _derive_image_facts(self)
        self.patch_plan = None

    # -- lookups ----------------------------------------------------------- #
    def section(self, name):
        return self.elf.by_name(name)

    def section_of(self, symbol):
        if symbol is None or not (0 < symbol["shndx"] < len(self.sections)):
            return None
        return self.sections[symbol["shndx"]]

    def symbol(self, name, defined_only=False):
        for symbol in self.symbols:
            if symbol["name"] == name and (not defined_only or symbol["shndx"] != 0):
                return symbol
        return None

    def exec_sections(self):
        return [section for section in self.sections
                if section["flags"] & SHF_EXECINSTR]

    def allocated_data_sections(self):
        return [section for section in self.sections
                if section["flags"] & SHF_ALLOC and section["type"] != SHT_NOBITS]

    def rodata_strings(self):
        out = []
        for section in self.allocated_data_sections():
            if not section["name"].startswith(".rodata"):
                continue
            for text in _section_bytes(self.elf, section).split(b"\x00"):
                out.append(text.decode("utf-8", "replace"))
        return out


def _modinfo_tags(ctx) -> dict:
    section = ctx.section(".modinfo")
    tags: dict = {}
    if section is None:
        return tags
    for entry in _section_bytes(ctx.elf, section).split(b"\x00"):
        if not entry:
            continue
        key, _, value = entry.partition(b"=")
        tags.setdefault(key.decode("utf-8", "replace"),
                        value.decode("utf-8", "replace"))
    return tags


def _version_names(ctx) -> list:
    section = ctx.section("__versions")
    if section is None:
        return []
    raw = _section_bytes(ctx.elf, section)
    names = []
    for index in range(section["size"] // 64):
        names.append(raw[index * 64 + 8:(index + 1) * 64].split(b"\x00")[0].decode(
            "utf-8", "replace"))
    return names


def _symbol_prefix(ctx, symbol) -> int:
    section = ctx.section_of(symbol)
    if section is None or symbol["value"] < 4:
        raise _GateError("%s has no room for a KCFI prefix" % symbol["name"])
    file_offset = section["offset"] + symbol["value"]
    if file_offset > len(ctx.elf.raw):
        raise _GateError("%s prefix lies past EOF" % symbol["name"])
    return _u32(ctx.elf.raw, file_offset - 4)


# --------------------------------------------------------------------------- #
# G1 -- layout the loader validates.
# --------------------------------------------------------------------------- #

def _gate_layout(ctx, gate):
    elf, contract = ctx.elf, ctx.contract
    gate.require(elf.e_type == ET_REL, "e_type is ET_REL",
                 "e_type=%d" % elf.e_type)
    gate.require(elf.e_machine == EM_AARCH64, "e_machine is AArch64",
                 "e_machine=%d" % elf.e_machine)
    gate.require(elf.e_shentsize == 64, "section headers are 64 bytes",
                 "e_shentsize=%d" % elf.e_shentsize)
    gate.require(elf.e_shoff < len(elf.raw) and
                 elf.e_shnum * 64 <= len(elf.raw) - elf.e_shoff,
                 "section header table is inside the file",
                 "shoff=0x%x shnum=%d bytes=%d"
                 % (elf.e_shoff, elf.e_shnum, len(elf.raw)))
    gate.require(0 < elf.e_shstrndx < elf.e_shnum,
                 "section name table is addressable", "e_shstrndx=%d" % elf.e_shstrndx)
    if not (0 < elf.e_shstrndx < elf.e_shnum):
        return
    shstr = elf.sections[elf.e_shstrndx]
    gate.require(shstr["size"] > 0 and
                 shstr["offset"] + shstr["size"] <= len(elf.raw) and
                 elf.raw[shstr["offset"] + shstr["size"] - 1] == 0,
                 "section name table is NUL terminated",
                 "size 0x%x at 0x%x" % (shstr["size"], shstr["offset"]))
    zero = elf.sections[0]
    gate.require(zero["type"] == SHT_NULL and zero["size"] == 0 and
                 zero["addr"] == 0, "section 0 is the empty SHT_NULL")
    for section in elf.sections[1:]:
        if section["type"] == SHT_NOBITS:
            continue
        gate.require(section["offset"] + section["size"] <= len(elf.raw),
                     "section %r stays inside the file" % section["name"],
                     "ends at 0x%x of %d"
                     % (section["offset"] + section["size"], len(elf.raw)))
    symtabs = [section for section in elf.sections if section["type"] == SHT_SYMTAB]
    gate.require(len(symtabs) == 1, "exactly one symtab (not stripped)",
                 "found %d" % len(symtabs))
    if symtabs:
        gate.require(0 < symtabs[0]["link"] < elf.e_shnum,
                     "symtab sh_link points at its string table",
                     "sh_link=%d" % symtabs[0]["link"])
        if 0 < symtabs[0]["link"] < elf.e_shnum:
            gate.require(elf.sections[symtabs[0]["link"]]["type"] == SHT_STRTAB,
                         "symtab's string table is SHT_STRTAB",
                         "type=%d" % elf.sections[symtabs[0]["link"]]["type"])
    modules = [section for section in elf.sections
               if section["name"] == ".gnu.linkonce.this_module"]
    infos = [section for section in elf.sections if section["name"] == ".modinfo"]
    gate.require(len(modules) == 1, "exactly one .gnu.linkonce.this_module",
                 "found %d" % len(modules))
    gate.require(len(infos) == 1, "exactly one .modinfo section",
                 "found %d" % len(infos))
    if len(modules) != 1 or len(infos) != 1:
        return
    this_module, modinfo = modules[0], infos[0]

    # -- the four fields the loader reads, at BTF's offsets ------------------ #
    btf_module = ctx.btf.struct("module")
    name_off = _Btf.member(btf_module, "name")["byte"]
    init_off = _Btf.member(btf_module, "init")["byte"]
    exit_off = _Btf.member(btf_module, "exit")["byte"]
    gate.require(this_module["type"] != SHT_NOBITS,
                 "this_module has a size set (not NOBITS)")
    gate.require(bool(this_module["flags"] & SHF_ALLOC),
                 "this_module occupies memory (SHF_ALLOC)")
    gate.require(this_module["size"] == btf_module["size"],
                 "this_module size == BTF sizeof(struct module)",
                 "section 0x%x, BTF 0x%x (type id %s)"
                 % (this_module["size"], btf_module["size"],
                    [entry[0] for entry in ctx.btf.structs("module")]))
    body = _section_bytes(elf, this_module)
    gate.require(len(body) >= name_off + 56,
                 "this_module is large enough for char name[56]",
                 "size 0x%x, name at +0x%x" % (len(body), name_off))
    gate.require(len(body) > max(init_off, exit_off) + 7,
                 "this_module covers the init and exit fields",
                 "size 0x%x, init at +0x%x, exit at +0x%x"
                 % (len(body), init_off, exit_off))
    if len(body) < name_off + 56 or len(body) <= max(init_off, exit_off) + 7:
        return
    embedded = body[name_off:name_off + 56].split(b"\x00")[0].decode(
        "utf-8", "replace")
    gate.require(embedded == contract["module"],
                 "module name embedded at this_module+0x%x" % name_off,
                 "found %r, contract says %r" % (embedded, contract["module"]))
    gate.require(len(contract["module"]) + 1 <= 56, "module name fits char[56]",
                 "%d bytes with the terminator" % (len(contract["module"]) + 1))

    init_symbol = ctx.symbol("init_module", defined_only=True)
    exit_symbol = ctx.symbol("cleanup_module", defined_only=True)
    gate.require(init_symbol is not None, "init_module is defined")
    gate.require(exit_symbol is not None, "cleanup_module is defined")
    relocs = {entry["offset"]: entry
              for entry in ctx.relocations.get(".gnu.linkonce.this_module", [])}
    for label, offset, symbol_name, symbol in (
            ("init", init_off, "init_module", init_symbol),
            ("exit", exit_off, "cleanup_module", exit_symbol)):
        quad = _u64(body, offset)
        reloc = relocs.get(offset)
        detail = "field 0x%016x, no relocation" % quad
        resolves = False
        if reloc is not None:
            detail = ("RELA +0x%x %s -> %s%+d (st_value 0x%x)"
                      % (offset, reloc["typeName"], reloc["symbol"],
                         reloc["addend"], reloc["symbolValue"]))
            resolves = (reloc["type"] == 257 and
                        reloc["symbol"] == symbol_name and
                        symbol is not None and
                        reloc["symbolValue"] + reloc["addend"] == symbol["value"])
        direct = quad != 0 and symbol is not None and quad == symbol["value"]
        gate.require(direct or resolves,
                     "this_module.%s (+0x%x) == value of %s"
                     % (label, offset, symbol_name), detail)
    unexpected = sorted(set(relocs) - {init_off, exit_off})
    gate.require(not unexpected, "no other relocation inside this_module",
                 "unexpected offsets: %s" % [hex(value) for value in unexpected])

    # -- .modinfo ---------------------------------------------------------- #
    tags = _modinfo_tags(ctx)
    gate.require(len(_section_bytes(elf, modinfo)) > 0, ".modinfo is not empty")
    gate.require(tags.get("license") == "GPL",
                 "modinfo license is GPL", "found %r" % tags.get("license"))
    gate.require(tags.get("license") == contract["license"],
                 "modinfo license == contract license",
                 "%r vs %r" % (tags.get("license"), contract["license"]))
    gate.require(tags.get("vermagic") == ctx.vermagic,
                 "modinfo vermagic == image vermagic",
                 "module %r, image %r" % (tags.get("vermagic"), ctx.vermagic))
    gate.require(tags.get("vermagic") == contract["vermagic"],
                 "modinfo vermagic == contract vermagic",
                 "module %r, contract %r" % (tags.get("vermagic"),
                                             contract["vermagic"]))
    gate.require(tags.get("name") == embedded,
                 "module name agrees in .modinfo and this_module",
                 "%r vs %r" % (tags.get("name"), embedded))
    for required in contract.get("modinfo", {}).get("required", []):
        key, _, value = required.partition("=")
        if key == "vermagic" or key == "name":
            continue
        gate.require(tags.get(key) == value,
                     "modinfo carries %s" % required,
                     "found %r" % tags.get(key))
    vermagic = tags.get("vermagic") or ""
    suffix = " " + " ".join(vermagic.split(" ")[1:]) if vermagic else ""
    gate.require(suffix == contract.get("vermagicSuffix"),
                 "vermagic suffix matches (the part same_magic compares)",
                 "%r vs %r" % (suffix, contract.get("vermagicSuffix")))

    # -- __versions -------------------------------------------------------- #
    versions = ctx.section("__versions")
    gate.require(versions is not None, "__versions present",
                 "absence makes the loader call try_to_force_load(), fatal here")
    if versions is not None:
        gate.require(versions["size"] % 64 == 0,
                     "__versions is a whole number of entries",
                     "size 0x%x" % versions["size"])
        names = _version_names(ctx)
        gate.require("module_layout" not in names,
                     "no module_layout CRC is pinned", "entries: %r" % names)
        gate.extras["versions"] = names


# --------------------------------------------------------------------------- #
# G2 -- PLT sections and the rest of the allocated section set.
# --------------------------------------------------------------------------- #

def _gate_plt(ctx, gate):
    elf = ctx.elf
    for name in (".plt", ".init.plt"):
        sections = [section for section in elf.sections if section["name"] == name]
        gate.require(len(sections) == 1, "%s exists exactly once" % name,
                     "found %d (module_finalize() prints 'module PLT section(s) "
                     "missing' and returns -ENOEXEC)" % len(sections))
        if len(sections) != 1:
            continue
        section = sections[0]
        gate.require(section["type"] == SHT_PROGBITS, "%s is PROGBITS" % name,
                     "type=%d" % section["type"])
        gate.require(bool(section["flags"] & SHF_ALLOC) and
                     bool(section["flags"] & SHF_EXECINSTR),
                     "%s is allocated and executable" % name,
                     "flags=0x%x" % section["flags"])
        gate.require(section["size"] >= 1, "%s carries its placeholder byte" % name,
                     "size=%d" % section["size"])
    trampolines = [section for section in elf.sections
                   if section["name"] == ".text.ftrace_trampoline"]
    gate.require(len(trampolines) == 1,
                 ".text.ftrace_trampoline is present (kbuild parity)",
                 "found %d" % len(trampolines))
    if trampolines:
        section = trampolines[0]
        gate.require(section["type"] == SHT_PROGBITS and
                     bool(section["flags"] & SHF_ALLOC),
                     ".text.ftrace_trampoline is allocated PROGBITS",
                     "type=%d flags=0x%x" % (section["type"], section["flags"]))
        gate.check(section["size"] >= 1, ".text.ftrace_trampoline is non-empty",
                   "size=%d" % section["size"], fatal=False)

    required = ((".text", SHF_ALLOC | SHF_EXECINSTR),
                (".init.text", SHF_ALLOC | SHF_EXECINSTR),
                (".gnu.linkonce.this_module", SHF_ALLOC | SHF_WRITE),
                ("__versions", SHF_ALLOC),
                (".modinfo", SHF_ALLOC))
    for name, flags in required:
        section = ctx.section(name)
        gate.require(section is not None, "%s exists" % name)
        if section is None:
            continue
        gate.require((section["flags"] & flags) == flags,
                     "%s has the expected attributes" % name,
                     "flags=0x%x, wanted 0x%x" % (section["flags"], flags))
        gate.require(section["size"] > 0, "%s is non-empty" % name,
                     "size=%d" % section["size"])

    # Every allocated section must be placeable: inside the file, aligned, and
    # not overlapping another PROGBITS allocation.
    placed = []
    for section in elf.sections[1:]:
        if not section["flags"] & SHF_ALLOC:
            continue
        gate.require(section["addr"] == 0,
                     "allocated section %r is section-relative" % section["name"],
                     "sh_addr=0x%x in an ET_REL object" % section["addr"])
        align = section["align"]
        gate.require(align == 0 or (align & (align - 1)) == 0,
                     "aligned section %r has a power-of-two alignment" % section["name"],
                     "sh_addralign=%d" % align)
        gate.require(align <= 0x1000, "section %r alignment is sane" % section["name"],
                     "sh_addralign=%d" % align)
        if section["type"] == SHT_NOBITS or section["size"] == 0:
            continue
        gate.require(section["offset"] + section["size"] <= len(elf.raw),
                     "allocated section %r is inside the file" % section["name"])
        placed.append(section)
    placed.sort(key=lambda entry: entry["offset"])
    for before, after in zip(placed, placed[1:]):
        gate.require(before["offset"] + before["size"] <= after["offset"],
                     "allocated sections do not overlap",
                     "%s ends 0x%x, %s starts 0x%x"
                     % (before["name"], before["offset"] + before["size"],
                        after["name"], after["offset"]))
    gate.extras["allocatedSections"] = [(section["name"], section["size"])
                                        for section in elf.sections
                                        if section["flags"] & SHF_ALLOC]


# --------------------------------------------------------------------------- #
# G3 -- importability against this image's export table.
# --------------------------------------------------------------------------- #

def _export_range(ctx, gate, key, start_name, stop_name):
    # A merged GPL table (6.18) has no such markers; the contract says so explicitly,
    # and the plain table already covers every export, so this range is simply absent.
    contract_table = ctx.contract.get("exportTable", {}).get(key, {})
    if contract_table.get("merged"):
        return None
    start_rows = ctx.tsv.lookup(start_name)
    stop_rows = ctx.tsv.lookup(stop_name)
    if not start_rows or not stop_rows:
        gate.require(False, "image symbol list carries %s/%s"
                     % (start_name, stop_name),
                     "the export ranges are the kernel's own linker symbols; "
                     "without them the export class cannot be decided")
        return None
    start, stop = start_rows[0]["address"], stop_rows[0]["address"]
    gate.require(start < stop, "%s range is ordered" % key,
                 "0x%x..0x%x" % (start, stop))
    gate.require(contract_table.get("start") == start and
                 contract_table.get("stop") == stop,
                 "contract %s bounds == image linker symbols" % key,
                 "contract 0x%x..0x%x, image 0x%x..0x%x"
                 % (contract_table.get("start", -1),
                    contract_table.get("stop", -1), start, stop))
    gate.extras.setdefault("exportRanges", {})[key] = {
        "start": start, "stop": stop,
        "startLine": "line %d: %s" % (start_rows[0]["line"],
                                      start_rows[0]["text"].replace("\t", "\\t")),
        "stopLine": "line %d: %s" % (stop_rows[0]["line"],
                                     stop_rows[0]["text"].replace("\t", "\\t"))}
    return start, stop, start_rows[0], stop_rows[0]


def _gate_imports(ctx, gate):
    contract = ctx.contract
    imports = list(ctx.imports)
    gate.extras["imports"] = imports
    contract_imports = {entry["name"] for entry in contract.get("requiredSymbols", [])
                        if entry.get("imported")}
    # The contract is derived from the image and may list more than the module imports
    # (it describes what the image exports); what must hold is that the module's design
    # set is covered, and that the module imports nothing outside design + tolerated.
    gate.require(set(DESIGN_IMPORTS) <= contract_imports,
                 "contract covers the design's imports",
                 "%s vs %s" % (sorted(contract_imports), sorted(DESIGN_IMPORTS)))
    tolerated = {entry["name"] for entry in contract.get("optionalSymbols", [])} & \
        set(TOLERATED_IMPORTS)
    missing = sorted(set(DESIGN_IMPORTS) - set(imports))
    extra = sorted(set(imports) - set(DESIGN_IMPORTS) - tolerated)
    gate.require(not missing, "all four deliberate imports are present",
                 "missing: %s" % missing)
    gate.require(not extra, "no unexpected undefined symbol",
                 "extra: %s -- a compiler helper means a flag/source change, not "
                 "a whitelist edit" % extra)
    if "memset" in imports:
        gate.check(True, "memset present but tolerated",
                   "the contract lists it as optional; the build's -fno-builtin "
                   "should normally keep it out", fatal=False)

    ranges = {}
    for key, start_name, stop_name in (
            ("__ksymtab", "__start___ksymtab", "__stop___ksymtab"),
            ("__ksymtab_gpl", "__start___ksymtab_gpl", "__stop___ksymtab_gpl")):
        resolved = _export_range(ctx, gate, key, start_name, stop_name)
        if resolved:
            ranges[key] = (resolved[0], resolved[1])

    classes = {}
    for name in imports:
        rows = ctx.tsv.lookup("__ksymtab_" + name)
        gate.require(bool(rows), "%s is exported by this image" % name,
                     ("line %d: %s" % (rows[0]["line"],
                                       rows[0]["text"].replace("\t", "\\t")))
                     if rows else
                     "no __ksymtab_%s row in %s: the loader would fail with "
                     "'Unknown symbol'" % (name, ctx.symbols_path.name))
        if not rows:
            continue
        row = rows[0]
        address = row["address"]
        quote = "line %d: %s" % (row["line"], row["text"].replace("\t", "\\t"))
        gate.extras.setdefault("ksymtabRows", {})[name] = quote
        where = None
        for key, (start, stop) in ranges.items():
            if start <= address < stop:
                where = key
                break
        gate.require(where is not None, "__ksymtab_%s is inside an export range" % name,
                     ("%s (0x%x)" % (where, address)) if where else
                     "%s at 0x%x is outside both ranges" % (name, address))
        if where is None:
            continue
        classes[name] = where
        gate.check(True, "%s -> %s" % (name, quote),
                   "%s (0x%x)" % ("EXPORT_SYMBOL_GPL" if where == "__ksymtab_gpl"
                                  else "EXPORT_SYMBOL", address), fatal=False)
    gate.extras["importClasses"] = classes

    gpl_only = sorted(name for name, where in classes.items()
                      if where == "__ksymtab_gpl")
    if gpl_only:
        gate.require(contract.get("license") == "GPL",
                     "GPL-only imports are legal under this license",
                     "%s resolve through __ksymtab_gpl, license is %r"
                     % (gpl_only, contract.get("license")))
        gate.check(True, "GPL-only imports: %s" % ", ".join(gpl_only),
                   "the contract records them in __ksymtab_gpl", fatal=False)

    forbidden = [entry["name"] for entry in contract.get("forbiddenSymbolsAbsent", [])]
    present = [name for name in forbidden if name in imports]
    gate.require(not present,
                 "no reference to a symbol this image does not export",
                 "found: %s" % present)
    gate.check(True, "checked %d forbidden names" % len(forbidden),
               ", ".join(forbidden), fatal=False)


# --------------------------------------------------------------------------- #
# G4 -- cleanup_module is defined, is text, and is this_module.exit.
# --------------------------------------------------------------------------- #

def _gate_cleanup(ctx, gate):
    contract = ctx.contract
    symbol = ctx.symbol("cleanup_module", defined_only=True)
    gate.require(symbol is not None, "cleanup_module is defined (not UNDEF)",
                 "the glue emits .quad cleanup_module; a missing definition is an "
                 "undefined symbol the loader refuses")
    if symbol is None:
        return
    gate.require(symbol["type"] == STT_FUNC, "cleanup_module is STT_FUNC",
                 "st_info type=%d" % symbol["type"])
    gate.require(symbol["value"] != 0, "cleanup_module's st_value is non-zero",
                 "st_value=0x%x" % symbol["value"])
    gate.require(symbol["size"] > 0, "cleanup_module has a body",
                 "st_size=%d" % symbol["size"])
    section = ctx.section_of(symbol)
    gate.require(section is not None, "cleanup_module lives in a section")
    if section is None:
        return
    gate.require(bool(section["flags"] & SHF_ALLOC) and
                 bool(section["flags"] & SHF_EXECINSTR),
                 "cleanup_module is in allocated executable memory",
                 "section %r flags=0x%x" % (section["name"], section["flags"]))
    gate.require(section["name"] != ".init.text",
                 "cleanup_module is not in freed init text",
                 "it is in %r; delete_module() runs long after .init.text is freed"
                 % section["name"])
    gate.check(section["name"] == ".text", "cleanup_module is in permanent .text",
               "section %r" % section["name"], fatal=False)

    exit_off = _Btf.member(ctx.btf.struct("module"), "exit")["byte"]
    reloc = next((entry for entry
                  in ctx.relocations.get(".gnu.linkonce.this_module", [])
                  if entry["offset"] == exit_off), None)
    gate.require(reloc is not None and reloc["type"] == 257 and
                 reloc["symbol"] == "cleanup_module" and
                 reloc["symbolValue"] + reloc["addend"] == symbol["value"],
                 "this_module.exit (+0x%x) is the ABS64 address of cleanup_module"
                 % exit_off,
                 "found %r" % (reloc,))
    gate.check(True, "the restore point is reachable through delete_module()",
               "cleanup_module at %s+0x%x size %d, this_module.exit -> it"
               % (section["name"], symbol["value"], symbol["size"]), fatal=False)
    gate.check(True, "return 0 means handed over and resident",
               "source-level property (module/maplesu_root.c:186-187); the binary "
               "guarantee here is that the restore point above stays reachable",
               fatal=False)


# --------------------------------------------------------------------------- #
# G5 -- the patch plan is symbolic: no address, no spec blob, right handover.
# --------------------------------------------------------------------------- #

def _umh_sites(ctx) -> list:
    sites = []
    for target, entries in ctx.relocations.items():
        section = ctx.section(target)
        if section is None or not section["flags"] & SHF_EXECINSTR:
            continue
        code = _section_bytes(ctx.elf, section)
        for entry in entries:
            if entry["type"] != 283 or entry["symbol"] != "call_usermodehelper":
                continue
            index = entry["offset"] // 4
            writer = None
            for back in range(index - 1, max(-1, index - 17), -1):
                if back < 0:
                    break
                insn = _u32(code, back * 4)
                movz = _movz(insn)
                if movz and movz[0] == 3:
                    writer = {"offset": back * 4, "kind": "movz",
                              "value": movz[1] << (movz[2] * 16)}
                    break
                movk = _movk(insn)
                if movk and movk[0] == 3:
                    writer = {"offset": back * 4, "kind": "movk", "value": None}
                    break
                if (insn & 0xFFE0001F) == 0x32000000 and ((insn >> 5) & 0x1F) == 31 \
                        and (insn & 0x1F) == 3:
                    writer = {"offset": back * 4, "kind": "orr-imm", "value": None}
                    break
            sites.append({"section": target, "offset": entry["offset"],
                          "writer": writer})

    if sites:
        return sites
    # Runtime-resolved wrapper: no relocation names it, so look for the wait flag
    # itself - `movz w3, #1` feeding an indirect call, in any executable section.
    for section in ctx.exec_sections():
        code = _section_bytes(ctx.elf, section)
        for index in range(len(code) // 4 - 4):
            movz = _movz(_u32(code, index * 4))
            if not movz or movz[0] != 3 or (movz[1] << (movz[2] * 16)) != 1:
                continue
            for ahead in range(1, 5):
                if (_u32(code, (index + ahead) * 4) & 0xFFFFFC1F) == 0xD63F0000:
                    sites.append({"section": section["name"],
                                  "offset": (index + ahead) * 4,
                                  "resolved": True,
                                  "writer": {"offset": index * 4, "kind": "movz",
                                             "value": 1}})
                    return sites
    return sites


def _mov_w3_two(ctx) -> list:
    hits = []
    for section in ctx.exec_sections():
        code = _section_bytes(ctx.elf, section)
        for index in range(len(code) // 4):
            insn = _u32(code, index * 4)
            for decoder in (_movz, _movn):
                decoded = decoder(insn)
                if decoded and decoded[0] == 3:
                    value = decoded[1] << (decoded[2] * 16)
                    if decoder is _movn:
                        value = (~value) & 0xFFFFFFFF
                    if value == 2:
                        hits.append("%s+0x%x (0x%08x)"
                                    % (section["name"], index * 4, insn))
    return hits


def _w0_returns(ctx) -> list:
    symbol = ctx.symbol("init_module", defined_only=True)
    section = ctx.section_of(symbol) if symbol else None
    code = _section_bytes(ctx.elf, section) if section else b""
    values = []
    for index in range(len(code) // 4):
        insn = _u32(code, index * 4)
        movz = _movz(insn)
        if movz and movz[0] == 0:
            values.append(movz[1] << (movz[2] * 16))
            continue
        movn = _movn(insn)
        if movn and movn[0] == 0:
            raw = (~(movn[1] << (movn[2] * 16))) & 0xFFFFFFFF
            values.append(raw - 0x100000000 if raw >= 0x80000000 else raw)
            continue
        if _mov_wzr(insn) == 0:
            values.append(0)
    return values


def _helper_paths(ctx) -> list:
    found = set()
    for section in ctx.allocated_data_sections():
        for text in _section_bytes(ctx.elf, section).split(b"\x00"):
            if text.startswith(b"/data/"):
                found.add(text.decode("utf-8", "replace"))
    return sorted(found)


def _plan_has_kernel_va(plan) -> list:
    hits = []

    def walk(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, path + "." + str(key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, path + "[%d]" % index)
        elif isinstance(node, int) and not isinstance(node, bool):
            if KERNEL_VA_LOW <= node <= KERNEL_VA_HIGH:
                hits.append("%s = 0x%x" % (path, node))

    walk(plan, "plan")
    return hits


def _gate_patch_plan(ctx, gate):
    elf, contract = ctx.elf, ctx.contract
    gate.require(ctx.section(".ir_spec") is None, "no .ir_spec section",
                 "the old per-release byte-patch blob must not come back")
    banner = elf.raw.find(b"#maplesu-ir-spec")
    gate.require(banner < 0, "no #maplesu-ir-spec banner anywhere in the file",
                 "absent" if banner < 0 else "found at file offset 0x%x" % banner)

    hits, scanned = [], []
    for section in ctx.allocated_data_sections():
        blob = _section_bytes(elf, section)
        scanned.append((section["name"], len(blob)))
        for offset in range(max(0, len(blob) - 7)):
            value = struct.unpack_from("<Q", blob, offset)[0]
            if KERNEL_VA_LOW <= value <= KERNEL_VA_HIGH:
                hits.append("%s+0x%x = 0x%x" % (section["name"], offset, value))
    gate.require(not hits, "no kernel virtual address in any allocated section",
                 "0 hits in %d bytes across %d sections"
                 % (sum(size for _name, size in scanned), len(scanned))
                 if not hits else
                 "a per-release address table looks like this: %s" % hits[:5])
    for name in (".text", ".init.text", ".rodata"):
        section = ctx.section(name)
        if section is not None:
            gate.check(True, "%s carries no absolute kernel address" % name,
                       "%d bytes scanned at byte granularity"
                       % len(_section_bytes(elf, section)), fatal=False)

    addend_hits = []
    type_counts: dict = {}
    unknown = set()
    for target, entries in ctx.relocations.items():
        for entry in entries:
            type_counts[entry["type"]] = type_counts.get(entry["type"], 0) + 1
            if entry["type"] not in RELOC_SUPPORTED:
                unknown.add(entry["type"])
            addend = entry["addend"] & 0xFFFFFFFFFFFFFFFF
            if KERNEL_VA_LOW <= addend <= KERNEL_VA_HIGH:
                addend_hits.append("%s+0x%x -> 0x%x"
                                   % (target, entry["offset"], entry["addend"]))
    gate.require(not addend_hits, "no relocation addend is a kernel address",
                 "%s" % addend_hits[:5])
    gate.require(not unknown, "every relocation type is one arm64 implements",
                 "unknown: %s" % sorted(unknown))
    got = sorted(set(type_counts) & RELOC_GOT)
    gate.require(not got, "no GOT relocation (no .got dependency)",
                 "none" if not got else
                 "types %s: no shipped module for this kernel has a .got"
                 % [RELOC_SUPPORTED[value] for value in got])
    gate.extras["relocationTypes"] = {str(value): type_counts[value]
                                      for value in sorted(type_counts)}

    umh = _umh_sites(ctx)
    waits = _mov_w3_two(ctx)
    gate.require(not waits,
                 "no `mov w3, #2` (UMH_WAIT_PROC) anywhere in module text",
                 "none" if not waits else "found at %s" % waits)
    for site in umh:
        writer = site["writer"]
        gate.require(writer is not None and writer["kind"] == "movz" and
                     writer["value"] == 1,
                     "call_usermodehelper passes w3 = 1 (UMH_WAIT_EXEC)",
                     "site %s+0x%x, nearest w3 writer %r"
                     % (site["section"], site["offset"], writer))
    gate.require(bool(umh), "there is a resolved call_usermodehelper call site",
                 "found %d" % len(umh))
    gate.check(len(umh) == 1, "one handover call site", "%d sites" % len(umh),
               fatal=False)
    gate.extras["umhSites"] = umh

    helpers = _helper_paths(ctx)
    gate.require(len(helpers) == 1, "exactly one staged helper path constant",
                 "found %r" % helpers)
    helper = helpers[0] if helpers else ""
    gate.require(helper.startswith("/data/"), "helper path is under /data/", helper)
    gate.require(".." not in helper, "helper path has no traversal", helper)
    foreign = [token.decode() for token in
               (b"/system/bin/sh", b"/data/local/tmp/", b"/sbin/", b"/system/xbin/")
               if token in elf.raw]
    gate.require(not foreign, "no foreign helper path in the module",
                 "found: %s" % foreign)
    policy = contract.get("helperPathPolicy", {})
    policy_path = policy.get("policyPath")
    module_constant = policy.get("moduleConstant")
    policy_ok = helper == policy_path
    # The contract may *record* a divergence (D-5) instead of matching it; then
    # the module must carry exactly the constant the contract records, and the
    # divergence must still be declared.  A third path is always a failure.
    divergence = (not policy_ok and helper == module_constant and
                  policy.get("matches") is False and
                  policy.get("status") == "MISMATCH")
    gate.require(policy_ok or divergence,
                 "helper path agrees with the contract's D-5 record",
                 "module carries %r; policy %r, recorded constant %r, status %r"
                 % (helper, policy_path, module_constant, policy.get("status")))
    gate.check(policy_ok, "helper path equals the contract's D-5 policy path",
               "%r vs policy %r -- recorded by the contract as %s; a decision, "
               "not a build defect" % (helper, policy_path, policy.get("status")),
               fatal=False)
    gate.extras["helperPath"] = helper

    # -- handover semantics ------------------------------------------------ #
    handover = contract.get("handover", {})
    gate.require(handover.get("umhWaitMode") == "UMH_WAIT_EXEC" and
                 handover.get("umhWaitModeValue") == 1,
                 "contract handover is UMH_WAIT_EXEC = 1",
                 "mode=%r value=%r" % (handover.get("umhWaitMode"),
                                       handover.get("umhWaitModeValue")))
    gate.require(handover.get("forbiddenWaitMode") == "UMH_WAIT_PROC",
                 "contract forbids UMH_WAIT_PROC", "%r"
                 % handover.get("forbiddenWaitMode"))
    return_zero = handover.get("returnZeroMeans", "")
    gate.require("handed over" in return_zero and "resident" in return_zero,
                 "contract says return 0 means handed-over-and-resident",
                 "%r" % return_zero)
    marker = b"handover started; resident"
    gate.require(any(marker in _section_bytes(elf, section)
                     for section in ctx.allocated_data_sections()),
                 "the success branch's marker string is in the module",
                 "%r" % marker.decode())
    values = _w0_returns(ctx)
    gate.require(0 in values, "init_module encodes return 0 (success)",
                 "w0 writes in init_module: %s" % values)
    failure_values = []
    for name in handover.get("failureReturns", {}):
        code = name.lstrip("-")
        if code not in KERNEL_ERRNO:
            gate.require(False, "contract failure return %r names a known errno"
                         % name,
                         "add it to KERNEL_ERRNO (asm-generic numbering), not to the "
                         "host's errno module")
            continue
        failure_values.append(-KERNEL_ERRNO[code])
    for value in failure_values:
        gate.require(value in values,
                     "init_module encodes failure return %d" % value,
                     "w0 writes: %s" % values)
    gate.check(len(values) > 0, "init_module's return values are encoded as data",
               "w0 writes: %s" % sorted(set(values)), fatal=False)

    # -- lookup names ------------------------------------------------------ #
    whitelist = {entry.get("name") for entry in contract.get("runtimeLookups", [])
                 if entry.get("name")}
    resolvable = set()
    for text in ctx.rodata_strings():
        if len(text) < 4 or len(text) > 128:
            continue
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
            continue
        if ctx.tsv.lookup(text):
            resolvable.add(text)
    whitelist = set(whitelist) | set(globals().get("OPTIONAL_LOOKUPS") or ())
    unexpected = sorted(resolvable - whitelist)
    gate.require(not unexpected,
                 "every resolvable kernel symbol name is in the contract's "
                 "runtime-lookup set",
                 "unexpected: %s -- a new runtime lookup is a design change"
                 % unexpected)
    present = sorted(whitelist & set(ctx.rodata_strings()))
    gate.check(True, "lookup names carried by the module: %s" % ", ".join(present),
               "%d of %d contract names" % (len(present), len(whitelist)),
               fatal=False)
    gate.extras["lookupNames"] = present

    # -- static-UMH: the handover has to be the two-stage one -------------- #
    # CONFIG_STATIC_USERMODEHELPER=y with _PATH="" makes call_usermodehelper() a
    # *silent no-op*: setup() overwrites subprocess_info.path with a lone NUL and
    # exec() returns 0 without forking. A module that only calls the four-argument
    # wrapper therefore reports success while nothing ran -- the false positive that
    # blocked the canary. The contract carries both config values and the BTF
    # offset of the field the fix writes; when they say the wrapper is dead, this
    # gate demands the two-stage handover *and* the path store it consists of.
    static_umh = contract["config"]["staticUsermodehelper"]
    static_path = contract["config"]["staticUsermodehelperPath"]
    gate.require(static_umh["config"] == "CONFIG_STATIC_USERMODEHELPER" and
                 static_path["config"] == "CONFIG_STATIC_USERMODEHELPER_PATH",
                 "the contract reads both static-UMH config values",
                 "found %r / %r" % (static_umh.get("config"),
                                    static_path.get("config")))
    static_path_value = static_path.get("value", "<missing>")
    static_path_empty = static_path_value in ("", "<not set>")
    primary = handover.get("primaryPath", {})
    primary_names = [primary.get("setup", ""), primary.get("exec", "")]
    gate.require(all(primary_names), "the contract names the two-stage lookup pair",
                 "primaryPath.setup/exec = %r" % primary_names)
    carried = [name for name in primary_names if name in present]
    if static_umh.get("satisfied") and static_path_empty:
        gate.require(len(carried) == 2,
                     "the module resolves call_usermodehelper_setup/_exec",
                     "carried %s of %s: with CONFIG_STATIC_USERMODEHELPER_PATH=%r the "
                     "four-argument wrapper cannot exec anything, so a module that "
                     "carries only the wrapper is the silent-no-op false positive"
                     % (carried, primary_names, static_path_value))
        path_offset = contract["structOffsets"]["subprocessInfo"]["path"]
        gate.require(path_offset == primary.get("pathOffset"),
                     "the contract's handover pathOffset is the BTF field offset",
                     "primaryPath.pathOffset=%r, structOffsets=%r"
                     % (primary.get("pathOffset"), path_offset))
        stores = _str_offset_sites(ctx, path_offset)
        gate.require(bool(stores),
                     "the module stores the helper pointer at subprocess_info.path "
                     "(+0x%x)" % path_offset,
                     "no 64-bit store with that immediate offset in module text; on "
                     "this kernel that store IS the fix, because setup() replaced the "
                     "path with %r" % static_path_value if not stores else
                     ", ".join("%s+0x%x" % (entry["section"], entry["offset"])
                               for entry in stores[:4]))
        gate.check(True, "path overwrite site(s) at +0x%x" % path_offset,
                   ", ".join("%s+0x%x (str x%d,[x%d,#0x%x])"
                             % (entry["section"], entry["offset"], entry["rt"],
                                entry["rn"], path_offset) for entry in stores[:4]),
                   fatal=False)
        gate.extras["handoverMode"] = "setup-exec"
    else:
        gate.check(True, "static-UMH two-stage handover not required here",
                   "CONFIG_STATIC_USERMODEHELPER=%s _PATH=%r"
                   % (static_umh.get("value"), static_path_value), fatal=False)
        gate.extras["handoverMode"] = "wrapper-only"
    gate.extras["umhPrimary"] = {"setup": primary_names[0], "exec": primary_names[1],
                                 "present": carried,
                                 "missing": [name for name in primary_names
                                             if name not in present],
                                 "fallback": "call_usermodehelper"}
    gate.extras["staticUsermodehelper"] = {"enabled": bool(static_umh.get("satisfied")),
                                           "path": static_path_value}

    # -- the symbolic plan ------------------------------------------------- #
    handlers = [name for name in present if name not in
                ("kallsyms_lookup_name", "selinux_state",
                 "aarch64_insn_patch_text")]
    plan = {
        "schema": "maplesu-root-symbolic-patch-plan/1",
        "module": contract["module"],
        "kernelRelease": contract["kernelRelease"],
        "imageSha256": contract["imageSha256"],
        "steps": [
            {"step": 1, "action": "resolve kallsyms_lookup_name",
             "via": "register_kprobe on symbol_name",
             "fieldOffsets": {"kprobe.addr": _Btf.member(
                 ctx.btf.struct("kprobe"), "addr")["byte"],
                 "kprobe.symbol_name": _Btf.member(
                     ctx.btf.struct("kprobe"), "symbol_name")["byte"]},
             "imports": ["register_kprobe", "unregister_kprobe"],
             "absoluteAddress": None},
            {"step": 2, "action": "write selinux_state.enforcing = 0",
             "object": "selinux_state",
             "offset": contract["selinuxState"]["enforcingOffset"],
             "restore": "cleanup_module", "absoluteAddress": None},
            {"step": 3, "action": "patch vendor handlers to return 0",
             "via": "aarch64_insn_patch_text", "names": handlers,
             "absoluteAddress": None},
            {"step": 4, "action": "hand over to userspace as kernel-domain root",
             "via": ("call_usermodehelper_setup -> subprocess_info.path -> "
                     "call_usermodehelper_exec"
                     if gate.extras.get("handoverMode") == "setup-exec"
                     else "call_usermodehelper"),
             "fallbackVia": "call_usermodehelper", "path": helper, "wait": 1,
             "waitName": "UMH_WAIT_EXEC",
             "pathOffset": (contract["structOffsets"]["subprocessInfo"]["path"]
                            if gate.extras.get("handoverMode") == "setup-exec"
                            else None),
             "absoluteAddress": None},
            {"step": 5, "action": "return 0 and stay resident",
             "restore": "cleanup_module", "returns": sorted(set(values)),
             "absoluteAddress": None},
        ],
    }
    gate.require(len(plan["steps"]) == 5 and
                 [step["step"] for step in plan["steps"]] == [1, 2, 3, 4, 5],
                 "the symbolic plan has the five design steps")
    gate.require(all(step["absoluteAddress"] is None for step in plan["steps"]),
                 "no plan step carries an absolute address")
    gate.require(plan["steps"][3]["wait"] == 1 and
                 plan["steps"][3]["path"] == helper,
                 "plan step 4 matches the bytes (wait 1, one helper path)")
    gate.require(plan["steps"][1]["offset"] ==
                 contract["selinuxState"]["enforcingOffset"],
                 "plan step 2 writes the BTF-confirmed enforcing offset")
    plan_hits = _plan_has_kernel_va(plan)
    gate.require(not plan_hits, "the plan contains no kernel virtual address",
                 "%s" % plan_hits[:3])
    gate.extras["patchPlan"] = plan
    ctx.patch_plan = plan


# --------------------------------------------------------------------------- #
# G6 -- KCFI: the prefixes the kernel compares, and no unproven trap.
# --------------------------------------------------------------------------- #

def _gate_kcfi(ctx, gate):
    contract = ctx.contract
    facts = ctx.image_facts
    init_symbol = ctx.symbol("init_module", defined_only=True)
    exit_symbol = ctx.symbol("cleanup_module", defined_only=True)
    gate.require(init_symbol is not None and exit_symbol is not None,
                 "init_module and cleanup_module are defined")
    if not init_symbol or not exit_symbol:
        return
    init_prefix = _symbol_prefix(ctx, init_symbol)
    exit_prefix = _symbol_prefix(ctx, exit_symbol)
    gate.require(init_prefix == facts["init"]["typeId"],
                 "init_module's KCFI prefix == the id do_one_initcall compares",
                 "module 0x%08x, image 0x%08x at %s+0x%x"
                 % (init_prefix, facts["init"]["typeId"],
                    facts["init"]["function"], facts["init"]["siteOffset"]))
    gate.require(exit_prefix == facts["exit"]["typeId"],
                 "cleanup_module's KCFI prefix == the id __arm64_sys_delete_module "
                 "compares",
                 "module 0x%08x, image 0x%08x at %s+0x%x"
                 % (exit_prefix, facts["exit"]["typeId"],
                    facts["exit"]["function"], facts["exit"]["siteOffset"]))
    contract_init = int(contract["kcfiInitTypeId"], 16)
    gate.require(init_prefix == contract_init,
                 "init_module's prefix == contract kcfiInitTypeId exactly",
                 "module 0x%08x, contract 0x%08x" % (init_prefix, contract_init))
    gate.require(facts["init"]["typeId"] == contract_init,
                 "the contract's kcfiInitTypeId is what this image compares",
                 "image 0x%08x at 0x%x" % (facts["init"]["typeId"],
                                           facts["init"]["siteAddress"]))
    gate.extras["prefixes"] = {"init": init_prefix, "exit": exit_prefix}

    # -- zero BRK: the load-bearing assertion ------------------------------ #
    # CONFIG_PANIC_ON_OOPS=y (this image) makes a kernel-mode BRK a panic, not an
    # oops, and # CONFIG_CFI_PERMISSIVE is not set -- so a KCFI trap is not a
    # recoverable diagnostic here. Every indirect call this module makes goes through
    # a runtime-resolved address whose prototype only exists in kallsyms, i.e. the
    # type id would be an unasserted hash coincidence. MAPLESU_NOCFI on those
    # functions removes the checks (and therefore every BRK clang would emit) while
    # keeping the mandatory init/exit prefixes asserted above.
    traps: dict = {}
    scanned = 0
    for section in ctx.exec_sections():
        code = _section_bytes(ctx.elf, section)
        scanned += len(code)
        for index in range(len(code) // 4):
            immediate = _brk_imm(_u32(code, index * 4))
            if immediate is None:
                continue
            traps.setdefault(immediate, []).append(
                {"section": section["name"], "offset": index * 4,
                 "word": "0x%08x" % _u32(code, index * 4)})
    if traps:
        first = sorted(traps)[0]
        trap_detail = ("%d BRK(s); first #0x%x at %s -- panic_on_oops is 1 and "
                       "CFI_PERMISSIVE is off, so a trap is the device, not a log line"
                       % (sum(len(where) for where in traps.values()), first,
                          ", ".join("%s+0x%x (%s)"
                                    % (entry["section"], entry["offset"],
                                       entry["word"])
                                    for entry in traps[first][:3])))
    else:
        trap_detail = "0 traps in %d bytes of module text" % scanned
    gate.require(not traps, "zero BRK instructions in every SHF_EXECINSTR section",
                 trap_detail)
    gate.extras["traps"] = {str(immediate): where
                            for immediate, where in traps.items()}

    # With clang's lowering a compare site always has a trap behind it, so "no site"
    # is the second half of the same statement: no check survived __nocfi.
    sites = []
    by_id: dict = {}
    for section in ctx.exec_sections():
        code = _section_bytes(ctx.elf, section)
        for site in _kcfi_sites(code):
            entry = {"section": section["name"], "offset": site["instruction"] * 4,
                     "typeId": site["typeId"]}
            sites.append(entry)
            by_id.setdefault(site["typeId"], []).append(entry)
    gate.require(not sites, "no kCFI compare site is left in module text",
                 "%d site(s): %s -- a surviving check names a type id that only "
                 "matches by luck" % (len(sites),
                                      ["%s+0x%x" % (entry["section"], entry["offset"])
                                       for entry in sites[:4]]) if sites else
                 "none: every indirect call is in a __nocfi function")
    for type_id, entries in sorted(by_id.items()):
        gate.check(True, "0x%08x x%d" % (type_id, len(entries)),
                   ", ".join("%s+0x%x" % (entry["section"], entry["offset"])
                             for entry in entries), fatal=False)
    gate.extras["kcfiSites"] = sites

    # -- what the binary cannot show: the flags and the source intent ------ #
    if ctx.root:
        flags = ctx.build_flags
        gate.require(flags is not None, "the build flags are recorded",
                     "no cflags in memory or in build.json: build once before "
                     "verifying a copied .ko")
        if flags is not None:
            gate.require("-fsanitize=kcfi" in flags,
                         "-fsanitize=kcfi is in the recorded build flags",
                         "flags: %s -- without it init_module carries no KCFI prefix "
                         "and do_one_initcall traps before the entry runs"
                         % " ".join(flags))
            gate.require("-ffixed-x18" in flags,
                         "-ffixed-x18 is in the recorded build flags",
                         "CONFIG_SHADOW_CALL_STACK=y: x18 is the kernel's SCS pointer "
                         "and clang allocates it without this flag")
            gate.check(True, "recorded flags: %d" % len(flags),
                       " ".join(flag for flag in flags
                                if flag in ("-fsanitize=kcfi", "-ffixed-x18")),
                       fatal=False)
        source_path = (ctx.project_root / "jailbreak-providers" / "root-loader" /
                       "module" / "maplesu_root.c")
        if not gate.require(source_path.is_file(),
                            "module/maplesu_root.c is present for the intent check",
                            str(source_path)):
            source = ""
        else:
            source = source_path.read_text(encoding="utf-8", errors="replace")
        for function in ("maplesu_sym", "maplesu_patch_return_zero", "init_module"):
            gate.require(_nocfi_covers(source, function),
                         "%s is declared MAPLESU_NOCFI in the source" % function,
                         "the attribute is the intent; a function that calls a "
                         "runtime-resolved address without it gets a KCFI check back, "
                         "and the binary alone cannot distinguish that from a clang "
                         "change")


# --------------------------------------------------------------------------- #
# G7 -- the header's claims and the contract's numbers vs the image's BTF.
# --------------------------------------------------------------------------- #

def _contract_type_ids(contract_entry: dict) -> list:
    """`allBtfTypeIds` when the contract records it, else the single btfTypeId."""
    if "allBtfTypeIds" in contract_entry:
        return list(contract_entry["allBtfTypeIds"])
    return [contract_entry["btfTypeId"]]


def _gate_struct_shim(ctx, gate):
    contract, btf = ctx.contract, ctx.btf
    header = ctx.header_path
    gate.require(header.is_file(), "kernel_compat.h exists", str(header))
    if not header.is_file():
        return
    text = header.read_text(encoding="utf-8", errors="replace")
    # Family-dependent struct sizes are macros the builder injects with -D. Resolve
    # them exactly as the compiler did, so both engines compare the same numbers
    # instead of one of them insisting on the primary family's literal.
    text = text.replace("MAPLESU_SELINUX_STATE_SIZE",
                        contract["selinuxState"]["sizeHex"])
    asserted = _header_asserts(text)
    gate.require(bool(asserted["sizeof"]),
                 "kernel_compat.h still carries _Static_asserts",
                 "parsed %r" % asserted)
    layout = {}
    for name in ("maplesu_kprobe", "maplesu_selinux_state",
                 "maplesu_subprocess_info"):
        layout[name] = _c_struct_layout(text, name)
    gate.extras["headerAsserts"] = asserted
    gate.extras["headerLayout"] = {name: {"size": value["size"],
                                          "members": value["members"]}
                                   for name, value in layout.items()}
    # The compiler enforced these asserts, so header and assert disagreeing now
    # means the header changed after the .ko was built.
    for name, value in layout.items():
        expected = asserted["sizeof"].get(name)
        gate.require(expected == value["size"],
                     "kernel_compat.h sizeof(%s) == its own _Static_assert" % name,
                     "computed 0x%x, asserted %s"
                     % (value["size"], "0x%x" % expected if expected is not None
                        else "missing"))
        for member, offset in asserted["offsetof"].get(name, {}).items():
            gate.require(value["members"].get(member) == offset,
                         "kernel_compat.h offsetof(%s, %s) == its assert"
                         % (name, member),
                         "computed %s, asserted 0x%x"
                         % (value["members"].get(member), offset))

    # -- struct module: BTF vs contract vs the section the glue wrote -------- #
    module_hits = btf.structs("module")
    gate.require(bool(module_hits), "image BTF has struct module")
    if not module_hits:
        return
    module_ids = sorted(entry[0] for entry in module_hits)
    module = module_hits[0][1]
    gate.require(len({entry[1]["size"] for entry in module_hits}) == 1,
                 "all BTF struct module definitions agree on size",
                 "%s" % ["id %d: 0x%x" % (entry[0], entry[1]["size"])
                         for entry in module_hits])
    gate.require(module_ids == _contract_type_ids(contract["thisModule"]),
                 "BTF struct module ids == contract type ids",
                 "%s vs %s" % (module_ids,
                               _contract_type_ids(contract["thisModule"])))
    gate.require(module["size"] == contract["thisModule"]["size"],
                 "BTF sizeof(struct module) == contract size",
                 "BTF 0x%x, contract 0x%x"
                 % (module["size"], contract["thisModule"]["size"]))
    this_module = ctx.section(".gnu.linkonce.this_module")
    gate.require(this_module is not None and
                 this_module["size"] == module["size"],
                 "this_module section size == BTF sizeof(struct module)",
                 "section %s, BTF 0x%x"
                 % ("0x%x" % this_module["size"] if this_module else "missing",
                    module["size"]))
    offsets = {}
    for member, key in (("name", "nameOffset"), ("init", "initOffset"),
                        ("exit", "exitOffset")):
        offsets[member] = _Btf.member(module, member)["byte"]
        gate.require(offsets[member] == contract["thisModule"][key],
                     "BTF offsetof(struct module, %s) == contract %s"
                     % (member, key),
                     "BTF 0x%x, contract 0x%x"
                     % (offsets[member], contract["thisModule"][key]))
    if this_module is not None:
        reloc_offsets = {entry["offset"]
                         for entry in ctx.relocations.get(
                             ".gnu.linkonce.this_module", [])}
        gate.require(offsets["init"] in reloc_offsets and
                     offsets["exit"] in reloc_offsets,
                     "the glue's relocations land on BTF's init/exit offsets",
                     "BTF 0x%x/0x%x, relocations %s"
                     % (offsets["init"], offsets["exit"],
                        sorted(hex(value) for value in reloc_offsets)))

    # -- struct kprobe ------------------------------------------------------ #
    kprobe_hits = btf.structs("kprobe")
    gate.require(bool(kprobe_hits), "image BTF has struct kprobe")
    if kprobe_hits:
        kprobe = kprobe_hits[0][1]
        kprobe_ids = sorted(entry[0] for entry in kprobe_hits)
        gate.require(kprobe_ids == _contract_type_ids(contract["kprobe"]),
                     "BTF struct kprobe ids == contract type ids",
                     "%s vs %s" % (kprobe_ids,
                                   _contract_type_ids(contract["kprobe"])))
        gate.require(kprobe["size"] == contract["kprobe"]["size"],
                     "BTF sizeof(struct kprobe) == contract size",
                     "BTF 0x%x, contract 0x%x"
                     % (kprobe["size"], contract["kprobe"]["size"]))
        for member, key, header_name in (
                ("addr", "addrOffset", "maplesu_kprobe"),
                ("symbol_name", "symbolNameOffset", "maplesu_kprobe")):
            offset = _Btf.member(kprobe, member)["byte"]
            claimed = contract["kprobe"][key]
            header_offset = layout[header_name]["members"].get(member)
            gate.require(offset == claimed,
                         "BTF offsetof(struct kprobe, %s) == contract" % member,
                         "BTF 0x%x, contract 0x%x" % (offset, claimed))
            gate.require(offset == header_offset,
                         "BTF offsetof(struct kprobe, %s) == kernel_compat.h" % member,
                         "BTF 0x%x, header %s"
                         % (offset, "0x%x" % header_offset
                            if header_offset is not None else "missing"))
        gate.require(kprobe["size"] == layout["maplesu_kprobe"]["size"],
                     "BTF sizeof(struct kprobe) == kernel_compat.h sizeof",
                     "BTF 0x%x, header 0x%x"
                     % (kprobe["size"], layout["maplesu_kprobe"]["size"]))
        gate.check(True, "struct kprobe shim holds",
                   "0x%x bytes, addr@0x%x, symbol_name@0x%x"
                   % (kprobe["size"], _Btf.member(kprobe, "addr")["byte"],
                      _Btf.member(kprobe, "symbol_name")["byte"]), fatal=False)

    # -- struct selinux_state ---------------------------------------------- #
    selinux_hits = btf.structs("selinux_state")
    gate.require(bool(selinux_hits), "image BTF has struct selinux_state")
    if selinux_hits:
        # An image can carry more than one struct with this name (6.1 has a 0x88
        # layout with checkreqprot and a 0x80 one), so "the first hit" is not a
        # decision. The contract names the layout the module was built against; select
        # that one and say so instead of silently comparing against the other.
        wanted = contract["selinuxState"]["size"]
        selinux = next((entry[1] for entry in selinux_hits
                        if entry[1]["size"] == wanted), selinux_hits[0][1])
        selinux_ids = sorted(entry[0] for entry in selinux_hits)
        gate.check(selinux_ids == _contract_type_ids(contract["selinuxState"]),
                   "BTF struct selinux_state ids == contract type ids",
                   "%s vs %s (selected by size 0x%x)"
                   % (selinux_ids, _contract_type_ids(contract["selinuxState"]),
                      wanted), fatal=False)
        gate.require(selinux["size"] == contract["selinuxState"]["size"],
                     "BTF sizeof(struct selinux_state) == contract size",
                     "BTF 0x%x, contract 0x%x"
                     % (selinux["size"], contract["selinuxState"]["size"]))
        enforcing = _Btf.member(selinux, "enforcing")["byte"]
        initialized = _Btf.member(selinux, "initialized")["byte"]
        gate.require(enforcing == contract["selinuxState"]["enforcingOffset"],
                     "BTF selinux_state.enforcing == contract offset",
                     "BTF 0x%x, contract 0x%x"
                     % (enforcing, contract["selinuxState"]["enforcingOffset"]))
        gate.require(enforcing == layout["maplesu_selinux_state"]["members"].get(
            "enforcing"),
            "BTF selinux_state.enforcing == kernel_compat.h offset",
            "BTF 0x%x, header %s"
            % (enforcing, layout["maplesu_selinux_state"]["members"].get(
                "enforcing")))
        gate.require(initialized ==
                     contract["selinuxState"]["initializedOffset"],
                     "BTF selinux_state.initialized == contract offset",
                     "BTF 0x%x, contract 0x%x"
                     % (initialized,
                        contract["selinuxState"]["initializedOffset"]))
        gate.require(selinux["size"] == layout["maplesu_selinux_state"]["size"],
                     "BTF sizeof(struct selinux_state) == kernel_compat.h sizeof",
                     "BTF 0x%x, header 0x%x"
                     % (selinux["size"], layout["maplesu_selinux_state"]["size"]))
        gate.check(True, "struct selinux_state shim holds",
                   "0x%x bytes, enforcing@0x%x, initialized@0x%x"
                   % (selinux["size"], enforcing, initialized), fatal=False)

    # -- struct subprocess_info -------------------------------------------- #
    # The one field the module writes into a kernel object. A wrong offset means the
    # helper path is restored into some other member while exec() keeps reading the
    # empty string setup() stored -- the silent no-op again, with a stray kernel
    # pointer write on top.
    subprocess_hits = btf.structs("subprocess_info")
    gate.require(bool(subprocess_hits), "image BTF has struct subprocess_info")
    if subprocess_hits:
        subprocess = subprocess_hits[0][1]
        subprocess_ids = sorted(entry[0] for entry in subprocess_hits)
        claimed = contract.get("structOffsets", {}).get("subprocessInfo", {})
        gate.require(bool(claimed),
                     "the contract carries structOffsets.subprocessInfo",
                     "keys: %s" % sorted(contract.get("structOffsets", {})))
        gate.require(subprocess_ids == _contract_type_ids(claimed),
                     "BTF struct subprocess_info ids == contract type ids",
                     "%s vs %s" % (subprocess_ids,
                                   _contract_type_ids(claimed) if claimed else None))
        gate.require(subprocess["size"] == claimed.get("size"),
                     "BTF sizeof(struct subprocess_info) == contract size",
                     "BTF 0x%x, contract %s"
                     % (subprocess["size"],
                        "0x%x" % claimed["size"] if claimed.get("size") else "missing"))
        for member in ("path", "argv", "envp", "wait", "retval"):
            offset = _Btf.member(subprocess, member)["byte"]
            gate.require(offset == claimed.get(member),
                         "BTF offsetof(subprocess_info, %s) == contract" % member,
                         "BTF 0x%x, contract %s"
                         % (offset, "0x%x" % claimed[member]
                            if claimed.get(member) is not None else "missing"))
        path_offset = _Btf.member(subprocess, "path")["byte"]
        gate.require(path_offset ==
                     layout["maplesu_subprocess_info"]["members"].get("path"),
                     "BTF subprocess_info.path == kernel_compat.h offset",
                     "BTF 0x%x, header %s"
                     % (path_offset,
                        layout["maplesu_subprocess_info"]["members"].get("path")))
        gate.require(subprocess["size"] == layout["maplesu_subprocess_info"]["size"],
                     "BTF sizeof(struct subprocess_info) == kernel_compat.h sizeof",
                     "BTF 0x%x, header 0x%x"
                     % (subprocess["size"],
                        layout["maplesu_subprocess_info"]["size"]))
        gate.require(path_offset ==
                     contract.get("handover", {}).get("primaryPath", {})
                     .get("pathOffset"),
                     "the contract's handover pathOffset is the BTF field offset",
                     "BTF 0x%x, handover.primaryPath.pathOffset=%r"
                     % (path_offset, contract.get("handover", {})
                        .get("primaryPath", {}).get("pathOffset")))
        # argv follows path, and the kernel writes both; that is the one structural
        # relation worth asserting beyond the single offset the module uses.
        gate.require(_Btf.member(subprocess, "argv")["byte"] == path_offset + 8 and
                     _Btf.member(subprocess, "envp")["byte"] == path_offset + 16,
                     "BTF keeps argv/envp immediately after path",
                     "path@0x%x argv@0x%x envp@0x%x"
                     % (path_offset, _Btf.member(subprocess, "argv")["byte"],
                        _Btf.member(subprocess, "envp")["byte"]))
        # Every *asserted* offset is compared three ways -- BTF, the contract's member
        # table, kernel_compat.h -- because `path` alone is not the whole object:
        # setup() stores init/cleanup/data (+0x58/+0x60/+0x68) and exec() stores
        # complete/wait/retval (+0x30/+0x50/+0x54). A shim that gets `path` right and
        # the tail wrong corrupts a struct the kernel itself is writing into, so a
        # mis-declared tail must not be able to pass this gate.
        header_members = layout["maplesu_subprocess_info"]["members"]
        asserted_members = asserted["offsetof"].get("maplesu_subprocess_info", {})
        contract_members = {entry.get("name"): entry.get("byteOffset")
                            for entry in claimed.get("members", [])}
        for member in ("complete", "path", "argv", "envp", "wait", "retval",
                       "init", "cleanup", "data"):
            offset = _Btf.member(subprocess, member)["byte"]
            gate.require(asserted_members.get(member) == offset,
                         "kernel_compat.h asserts subprocess_info.%s == BTF" % member,
                         "header %s, BTF 0x%x"
                         % ("0x%x" % asserted_members[member]
                            if member in asserted_members else "missing", offset))
            gate.require(header_members.get(member) == offset,
                         "kernel_compat.h offsetof(subprocess_info, %s) == BTF"
                         % member,
                         "header %s, BTF 0x%x"
                         % ("0x%x" % header_members[member]
                            if member in header_members else "missing", offset))
            gate.require(contract_members.get(member) == offset,
                         "contract subprocess_info.%s == BTF" % member,
                         "contract %s, BTF 0x%x"
                         % ("0x%x" % contract_members[member]
                            if member in contract_members else "missing", offset))
        gate.check(True, "struct subprocess_info shim holds",
                   "0x%x bytes, path@0x%x, argv@0x%x, envp@0x%x; tail asserted "
                   "through data@0x%x"
                   % (subprocess["size"], path_offset,
                      _Btf.member(subprocess, "argv")["byte"],
                      _Btf.member(subprocess, "envp")["byte"],
                      _Btf.member(subprocess, "data")["byte"]), fatal=False)

    # -- BTF identity and the contract's own ABI ledger --------------------- #
    gate.require(btf.blob_offset == contract.get("btf", {}).get("magicOffset"),
                 "BTF magic offset == contract", "0x%x vs %s"
                 % (btf.blob_offset, contract.get("btf", {}).get("magicOffset")))
    gate.require(len(btf.types) - 1 == contract.get("btf", {}).get("numTypes"),
                 "BTF type count == contract", "%d vs %s"
                 % (len(btf.types) - 1, contract.get("btf", {}).get("numTypes")))
    gate.require(btf.type_bytes == contract.get("btf", {}).get("typeBytes"),
                 "BTF type bytes == contract")
    gate.require(btf.string_bytes == contract.get("btf", {}).get("stringBytes"),
                 "BTF string bytes == contract")
    abi = contract.get("abiChecks", {})
    # "unresolved" means the claim could not be parsed out of a template (the numbers
    # are tokens now); it is not evidence for or against the image, and the values that
    # matter are checked against BTF by the other gates.
    gate.require(abi.get("status") in ("match", "unresolved")
                 and not abi.get("mismatches"),
                 "contract abiChecks says match", "status=%r mismatches=%r"
                 % (abi.get("status"), abi.get("mismatches")))
    gate.check(True, "compile is the shim gate",
               "the build succeeded, so every _Static_assert held; BTF and the "
               "header now agree on %d sizes and %d offsets"
               % (len(asserted["sizeof"]),
                  sum(len(table) for table in asserted["offsetof"].values())),
               fatal=False)
    gate.extras["btfFacts"] = {
        "btfBlobOffset": "0x%x" % btf.blob_offset,
        "structModule": {"ids": module_ids, "size": "0x%x" % module["size"],
                         "nameOffset": "0x%x" % offsets["name"],
                         "initOffset": "0x%x" % offsets["init"],
                         "exitOffset": "0x%x" % offsets["exit"]},
        "structKprobe": {"ids": sorted(entry[0] for entry in btf.structs("kprobe")),
                         "size": "0x%x" % btf.struct("kprobe")["size"],
                         "addrOffset": "0x%x" % _Btf.member(
                             btf.struct("kprobe"), "addr")["byte"],
                         "symbolNameOffset": "0x%x" % _Btf.member(
                             btf.struct("kprobe"), "symbol_name")["byte"]},
        "structSelinuxState": {
            "ids": sorted(entry[0] for entry in btf.structs("selinux_state")),
            "size": "0x%x" % btf.struct("selinux_state")["size"],
            "enforcingOffset": "0x%x" % _Btf.member(
                btf.struct("selinux_state"), "enforcing")["byte"]},
        "structSubprocessInfo": {
            "ids": sorted(entry[0] for entry in btf.structs("subprocess_info")),
            "size": "0x%x" % btf.struct("subprocess_info")["size"],
            "pathOffset": "0x%x" % _Btf.member(
                btf.struct("subprocess_info"), "path")["byte"]},
    }


_GATE_FUNCTIONS = {
    "G1": _gate_layout, "G2": _gate_plt, "G3": _gate_imports,
    "G4": _gate_cleanup, "G5": _gate_patch_plan, "G6": _gate_kcfi,
    "G7": _gate_struct_shim,
}


# --------------------------------------------------------------------------- #
# The public entry point and the CLI.
# --------------------------------------------------------------------------- #

def _all_failed(reason: str) -> dict:
    gates = [{"id": gate_id, "name": name, "ok": False,
              "detail": "gate could not be evaluated: " + reason,
              "checks": [], "extras": {}} for gate_id, name, _function in GATE_TABLE]
    return {"ok": False, "gates": gates, "imports": [],
            "result": "gate failure: " + reason, "patchPlan": None}


def run_gates(module_path, image_path, contract_path, root=True,
              header_path=None, build_flags=None) -> dict:
    """Run G1-G7 against one module, this image, and this contract.

    Returns {"ok", "gates": [{"id", "name", "ok", "detail", ...}], "imports",
    "result"} plus "patchPlan"/"imageFacts" for the build record.  `root=False`
    skips G3/G5/G7: those encode the resident-root design and the IR module is
    still governed by the legacy `check()` above.

    `build_flags` is the compiler flag list the caller recorded; when omitted the
    build record beside the artifact (or beside the sources) is used. G6 asserts
    -fsanitize=kcfi and -ffixed-x18 are in it -- a flag cannot be read out of a .ko.
    """
    module_path, image_path = Path(module_path), Path(image_path)
    contract_path = Path(contract_path)
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except Exception as error:                    # noqa: BLE001 - reported
        return _all_failed("contract %s is unreadable: %r"
                           % (contract_path, error))
    try:
        ctx = _Context(module_path, image_path, contract, contract_path,
                       header_path=header_path, build_flags=build_flags, root=root)
    except SystemExit as error:
        return _all_failed("module is not a loadable ELF64 object (legacy parser: "
                           "%s)" % error)
    except Exception as error:                    # noqa: BLE001 - reported
        return _all_failed("%s: %s" % (type(error).__name__, error))

    gates = []
    for gate_id, name, _function in GATE_TABLE:
        gate = _Gate(gate_id, name)
        if not root and gate_id in ("G3", "G5", "G7"):
            gate.skipped = True
            gate.skip_reason = ("skipped (root=False): this gate encodes the "
                                "resident-root design; the IR module is governed "
                                "by the legacy check()")
            gates.append(gate.result())
            continue
        try:
            _GATE_FUNCTIONS[gate_id](ctx, gate)
        except Exception as error:                # noqa: BLE001 - reported
            gate.error = "%s: %s" % (type(error).__name__, error)
        gates.append(gate.result())
    ok = all(gate["ok"] for gate in gates)
    result = "all gates pass" if ok else ("gate failure: " + ", ".join(
        gate["id"] for gate in gates if not gate["ok"]))
    return {"ok": ok, "gates": gates, "imports": list(ctx.imports),
            "result": result, "engine": "loader_contract.run_gates",
            "patchPlan": ctx.patch_plan,
            "imageFacts": {key: value for key, value in ctx.image_facts.items()}}


def _gates_main(argv) -> int:
    parser = argparse.ArgumentParser(
        prog="loader_contract.py",
        description="Offline replica of the kernel module loader plus the seven "
                    "G1-G7 gates for maplesu_root.ko.")
    parser.add_argument("--root", required=True, metavar="KO",
                        help="the built root module to check")
    parser.add_argument("--image", required=True, metavar="IMAGE",
                        help="the kernel image the contract was derived from")
    parser.add_argument("--contract", required=True, metavar="JSON",
                        help="contracts/<uname>.json")
    parser.add_argument("--json", default=None, metavar="OUT",
                        help="write the full result (checks + plan) here")
    args = parser.parse_args(argv)
    result = run_gates(args.root, args.image, args.contract, root=True)
    for gate in result["gates"]:
        mark = "SKIP" if gate.get("skipped") else ("PASS" if gate["ok"] else "FAIL")
        print("[%s] %-22s %s  %s" % (gate["id"], gate["name"], mark, gate["detail"]))
        for check in gate["checks"]:
            if not check["fatal"]:
                continue
            print("       %s %-60s %s"
                  % ("ok  " if check["ok"] else "FAIL", check["what"],
                     check["detail"]))
    print("imports: " + ", ".join(result["imports"]))
    if result.get("patchPlan"):
        print("patch plan: %s" % result["patchPlan"]["schema"])
    print("RESULT: " + result["result"])
    if args.json:
        output = Path(args.json)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print("wrote " + str(output))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

