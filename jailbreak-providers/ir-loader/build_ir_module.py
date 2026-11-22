"""Build maplesu_ir.ko without a kernel tree, and prove the loader will accept it.

Why not kbuild: this repository has no Linux source tree and no `make`, and the
target is a GKI image whose `struct module` layout is a property of *that* build.
So the module is compiled freestanding with the NDK's clang, linked with ld.lld,
and every loader-visible object is written by hand in ir_glue.S.in. The exact
layout numbers come from the target kernel's own BTF (see contract.json), not
from headers we guessed at.

What this script guarantees, and fails the build if not:
  * ELF is ET_REL / AArch64 / 64-byte section headers, section 0 empty;
  * `.gnu.linkonce.this_module` is exactly sizeof(struct module) with the module
    name at +nameOffset and ABS64 relocations for init/exit at +initOffset/
    +exitOffset;
  * `__versions` exists but carries no `module_layout` name, so
    check_modstruct_version() warns instead of demanding a CRC we cannot supply;
  * `.modinfo` carries the exact vermagic string, and its suffix (the part
    compared when __versions exists) equals contract.vermagicSuffix;
  * the module imports NO kernel symbol at all;
  * init_module's 4-byte KCFI prefix equals the type hash the kernel's
    do_one_initcall checks for `int (void)`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import native_toolchain  # noqa: E402
MODULE_DIR = HERE / "module"
CONTRACT_PATH = HERE / "contract.json"

CLANG_FLAGS = [
    "--target=aarch64-linux-gnu",
    "-ffreestanding",
    "-nostdlib",
    "-fno-builtin",
    "-fno-stack-protector",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-fno-pic",
    "-mno-outline-atomics",
    "-mgeneral-regs-only",
    "-O2",
    "-fsanitize=kcfi",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-c",
]

# The glue is hand-written assembly: only the target and the output belong on the
# command line, and passing the C flags there trips -Werror.
ASM_FLAGS = ["--target=aarch64-linux-gnu", "-c"]

# The kernel calls a module's init through an initcall_t pointer under CFI, so the
# prefix must be the hash for `int (void)`. clang derives it from the type alone.


class BuildError(SystemExit):
    pass


def fail(message: str) -> "BuildError":
    print("build_ir_module: " + message, file=sys.stderr)
    raise SystemExit(message)


# --------------------------------------------------------------------------- #
# Minimal ELF64 reader (enough to verify a relocatable object, nothing more).
# --------------------------------------------------------------------------- #

ET_REL = 1
EM_AARCH64 = 183
SHT_SYMTAB = 2
SHT_RELA = 4
SHT_NOBITS = 8
SHF_ALLOC = 0x2
R_AARCH64_ABS64 = 257


class Elf:
    def __init__(self, path: Path):
        self.path = path
        self.raw = path.read_bytes()
        if self.raw[:4] != b"\x7fELF":
            fail("%s is not an ELF file" % path)
        if self.raw[4] != 2 or self.raw[5] != 1:
            fail("%s is not ELF64 little-endian" % path)
        (self.e_type, self.e_machine, _v, _entry, _phoff, self.e_shoff, _flags,
         self.e_ehsize, _phentsize, _phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", self.raw, 16)
        if self.e_shentsize != 64:
            fail("%s has section header size %d" % (path, self.e_shentsize))
        self.sections = []
        for i in range(self.e_shnum):
            self.sections.append(self._section(i))
        names = self.sections[self.e_shstrndx]
        table = self.raw[names["offset"]: names["offset"] + names["size"]]
        for section in self.sections:
            end = table.find(b"\x00", section["name_off"])
            section["name"] = table[section["name_off"]:end].decode()
        self.symbols = self._symbols()

    def _section(self, index: int) -> dict:
        base = self.e_shoff + index * 64
        (name_off, kind, flags, addr, offset, size, link, info, align,
         entsize) = struct.unpack_from("<IIQQQQIIQQ", self.raw, base)
        return {"index": index, "name_off": name_off, "type": kind, "flags": flags,
                "addr": addr, "offset": offset, "size": size, "link": link,
                "info": info, "align": align, "entsize": entsize}

    def _symbols(self) -> list:
        table = next((s for s in self.sections if s["type"] == SHT_SYMTAB), None)
        if table is None:
            fail("%s has no symtab" % self.path)
        strings = self.sections[table["link"]]
        strtab = self.raw[strings["offset"]: strings["offset"] + strings["size"]]
        out = []
        count = table["size"] // 24
        for i in range(count):
            base = table["offset"] + i * 24
            name_off, info, other, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", self.raw, base)
            end = strtab.find(b"\x00", name_off)
            out.append({"name": strtab[name_off:end].decode(), "info": info,
                        "shndx": shndx, "value": value, "size": size})
        return out

    def section(self, name: str) -> dict | None:
        return next((s for s in self.sections if s["name"] == name), None)

    def section_bytes(self, name: str) -> bytes:
        section = self.section(name)
        if section is None:
            fail("%s has no %s section" % (self.path, name))
        return self.raw[section["offset"]: section["offset"] + section["size"]]

    def symbol(self, name: str) -> dict | None:
        return next((s for s in self.symbols if s["name"] == name), None)

    def relocations(self, section_name: str) -> list:
        target = self.section(section_name)
        if target is None:
            return []
        rela = next((s for s in self.sections
                     if s["type"] == SHT_RELA and s["info"] == target["index"]), None)
        if rela is None:
            return []
        out = []
        for i in range(rela["size"] // 24):
            base = rela["offset"] + i * 24
            offset, info, addend = struct.unpack_from("<QQq", self.raw, base)
            sym_index = info >> 32
            out.append({"offset": offset, "type": info & 0xFFFFFFFF,
                        "symbol": self.symbols[sym_index]["name"], "addend": addend})
        return out


# --------------------------------------------------------------------------- #
# Build steps.
# --------------------------------------------------------------------------- #

def find_tool(ndk: Path, name: str) -> Path:
    candidates = [
        ndk / "toolchains" / "llvm" / "prebuilt" / "windows-x86_64" / "bin" / (name + ".exe"),
        ndk / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / name,
        ndk / "toolchains" / "llvm" / "prebuilt" / "darwin-x86_64" / "bin" / name,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which(name)
    if found:
        return Path(found)
    fail("could not find %s under %s (set --ndk-dir)" % (name, ndk))


def render_glue(contract: dict, out: Path) -> None:
    template = (MODULE_DIR / "ir_glue.S.in").read_text(encoding="utf-8")
    module_name = contract["module"]
    rendered = (template
                .replace("@IR_MODULE_NAME_LENGTH@", str(len(module_name)))
                .replace("@IR_MODULE_NAME@", module_name)
                .replace("@IR_DESCRIPTION@", contract["description"])
                .replace("@IR_LICENSE@", contract["license"])
                .replace("@IR_VERMAGIC@", contract["vermagic"]))
    if "@IR_" in rendered:
        fail("unsubstituted token left in the rendered glue")
    out.write_text(rendered, encoding="utf-8")


def run(command: list) -> None:
    result = subprocess.run([str(part) for part in command],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print(result.stdout.decode(errors="replace"))
        print(result.stderr.decode(errors="replace"), file=sys.stderr)
        fail("command failed: " + " ".join(str(p) for p in command))


def build(ndk: Path, out_dir: Path, contract: dict, canary: bool = False,
          defines: list | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    clang = find_tool(ndk, "clang")
    ld = find_tool(ndk, "ld.lld")

    glue = out_dir / "ir_glue.s"
    render_glue(contract, glue)

    objects = []
    # Build identity from the sources themselves: a log line can then never be
    # ambiguous about which build ran on a device.
    digest = hashlib.sha256()
    digest.update((MODULE_DIR / "maplesu_ir.c").read_bytes())
    digest.update(glue.read_bytes())
    build_id = digest.hexdigest()[:12]
    # Compiler flags and macro definitions are different things: a warning flag must
    # never be turned into "-D-warning" (that is a malformed macro name).
    requested = list(defines or [])
    suppress = []
    # A stub-entry build leaves every helper unused; the product flags treat that as
    # an error, so suppress just those warnings for that build.
    if canary or "IR_CANARY" in requested:
        suppress = ["-Wno-unused-function", "-Wno-unused-variable",
                    "-Wno-unused-const-variable"]
    flags = (list(CLANG_FLAGS) + ['-DIR_BUILD="%s"' % build_id] +
             ["-D" + item for item in requested] +
             (["-DIR_CANARY"] + suppress if canary else suppress))
    for source, flags in (((MODULE_DIR / "maplesu_ir.c"), flags), (glue, ASM_FLAGS)):
        obj = out_dir / (source.stem + ".o")
        run([clang, *flags, str(source), "-o", str(obj)])
        objects.append(obj)

    module = out_dir / ((contract["module"] + "-canary") if canary else contract["module"])
    module = module.with_suffix(".ko")
    run([ld, "-r", "-o", str(module), *objects])
    return module


# --------------------------------------------------------------------------- #
# Contract verification: this is the part that has to be true for the kernel.
# --------------------------------------------------------------------------- #

def check(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def verify(module: Path, contract: dict) -> dict:
    elf = Elf(module)
    facts: dict = {}

    check(elf.e_type == ET_REL, "not ET_REL (got %d)" % elf.e_type)
    check(elf.e_machine == EM_AARCH64, "not AArch64 (got %d)" % elf.e_machine)
    section0 = elf.sections[0]
    check(section0["type"] == 0 and section0["size"] == 0 and section0["addr"] == 0,
          "section 0 is not the required empty SHT_NULL")
    names = elf.sections[elf.e_shstrndx]
    check(elf.raw[names["offset"] + names["size"] - 1] == 0,
          "section name table is not NUL terminated")

    # --- .modinfo ---------------------------------------------------------- #
    modinfo = elf.section_bytes(".modinfo").split(b"\x00")
    tags = {}
    for entry in modinfo:
        if not entry:
            continue
        key, _, value = entry.partition(b"=")
        tags[key.decode()] = value.decode(errors="replace")
    check(tags.get("name") == contract["module"], "modinfo name mismatch")
    check(tags.get("license") == contract["license"], "modinfo license mismatch")
    check(tags.get("vermagic") == contract["vermagic"], "modinfo vermagic mismatch")
    check("depends" in tags, "modinfo has no depends=")
    facts["vermagic"] = tags.get("vermagic")
    # same_magic() compares only what follows the first space once the module has
    # a __versions section, so the suffix is the part that must match the target.
    suffix = " " + " ".join(tags["vermagic"].split(" ")[1:])
    check(suffix == contract["vermagicSuffix"],
          "vermagic suffix %r != contract %r" % (suffix, contract["vermagicSuffix"]))
    facts["vermagicSuffix"] = suffix

    # --- __versions -------------------------------------------------------- #
    versions = elf.section("__versions")
    check(versions is not None, "no __versions section (loader would force-load)")
    check(versions["size"] % 64 == 0, "__versions is not a whole entry")
    raw_versions = elf.section_bytes("__versions")
    entry_count = versions["size"] // 64
    for i in range(entry_count):
        name = raw_versions[i * 64 + 8: (i + 1) * 64].split(b"\x00")[0]
        check(name != b"module_layout",
              "__versions pins module_layout: we cannot supply its CRC")
    facts["versionEntries"] = entry_count

    # --- struct module ----------------------------------------------------- #
    layout = contract["thisModule"]
    this_module = elf.section_bytes(".gnu.linkonce.this_module")
    check(len(this_module) == layout["size"],
          ".gnu.linkonce.this_module is %d bytes, kernel struct module is %d"
          % (len(this_module), layout["size"]))
    name_at = layout["nameOffset"]
    embedded_name = this_module[name_at:].split(b"\x00")[0].decode()
    check(embedded_name == contract["module"],
          "module name inside struct module is %r" % embedded_name)
    facts["thisModuleName"] = embedded_name

    relocs = {r["offset"]: r for r in elf.relocations(".gnu.linkonce.this_module")}
    init_reloc = relocs.get(layout["initOffset"])
    check(init_reloc is not None and init_reloc["type"] == R_AARCH64_ABS64,
          "no ABS64 relocation at struct module .init (+0x%x)" % layout["initOffset"])
    check(init_reloc["symbol"] == "init_module",
          ".init relocates to %r, not init_module" % init_reloc["symbol"])
    exit_reloc = relocs.get(layout["exitOffset"])
    check(exit_reloc is not None and exit_reloc["type"] == R_AARCH64_ABS64,
          "no ABS64 relocation at struct module .exit (+0x%x)" % layout["exitOffset"])
    facts["initReloc"] = init_reloc["symbol"]
    facts["exitReloc"] = exit_reloc["symbol"]

    # --- .ir_spec ---------------------------------------------------------- #
    spec = elf.section(contract["specSection"])
    check(spec is not None, "no %s section" % contract["specSection"])
    check(spec["size"] == contract["specBytes"],
          "%s is %d bytes, expected %d"
          % (contract["specSection"], spec["size"], contract["specBytes"]))
    check(spec["flags"] & SHF_ALLOC, "%s is not allocated" % contract["specSection"])
    spec_text = elf.section_bytes(contract["specSection"]).split(b"\x00")[0]
    check(spec_text.startswith(b"#maplesu-ir-spec"),
          "%s does not start with the spec banner" % contract["specSection"])
    facts["specBytes"] = spec["size"]

    # --- no imports -------------------------------------------------------- #
    imports = sorted({s["name"] for s in elf.symbols
                      if s["shndx"] == 0 and s["name"]})
    check(not imports, "module imports kernel symbols: %s" % ", ".join(imports))
    facts["imports"] = imports

    # --- KCFI prefix on init ----------------------------------------------- #
    init_symbol = elf.symbol("init_module")
    check(init_symbol is not None, "no init_module symbol")
    init_section = elf.sections[init_symbol["shndx"]]
    init_offset = init_section["offset"] + init_symbol["value"]
    prefix = struct.unpack_from("<I", elf.raw, init_offset - 4)[0]
    expected = int(contract["kcfiInitTypeId"], 16)
    check(prefix == expected,
          "init_module KCFI prefix 0x%08x != kernel expectation 0x%08x"
          % (prefix, expected))
    facts["kcfiInitTypeId"] = "0x%08x" % prefix
    facts["initSection"] = init_section["name"]
    facts["initSize"] = init_symbol["size"]

    # --- the patch function is reached by address, not by name ------------- #
    facts["definedSymbols"] = sorted({s["name"] for s in elf.symbols
                                      if s["shndx"] != 0 and s["name"]})
    return facts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ndk-dir", default=str(native_toolchain.provider_ndk()),
                        help="NDK r28c; default is MAPLESU_PROVIDER_NDK or <SDK>/ndk/28.2.13676358")
    parser.add_argument("--out", default=str(HERE / "build"))
    parser.add_argument("--define", action="append", default=[],
                        help="extra -D for the module source (bring-up builds)")
    parser.add_argument("--vermagic", default=None,
                        help="override the vermagic baked into .modinfo (bring-up only)")
    parser.add_argument("--canary", action="store_true",
                        help="build the minimal loader-contract canary instead of the product module")
    parser.add_argument("--verify-only", default=None,
                        help="verify an existing .ko against the contract")
    args = parser.parse_args()

    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if args.vermagic:
        # Bring-up probe: lets one boot compare two vermagic strings against the
        # same running kernel, which is the only way to tell a suffix comparison
        # from a full comparison when the release prefix is unverifiable.
        contract = dict(contract)
        contract["vermagic"] = args.vermagic
        contract["vermagicSuffix"] = " " + " ".join(args.vermagic.split(" ")[1:])
    out_dir = Path(args.out)

    if args.canary:
        module = build(Path(args.ndk_dir), out_dir, contract, canary=True)
        print("canary: " + str(module))
        return 0

    if args.verify_only:
        module = Path(args.verify_only)
    else:
        module = build(Path(args.ndk_dir), out_dir, contract, defines=args.define)

    facts = verify(module, contract)
    digest = hashlib.sha256(module.read_bytes()).hexdigest()
    report = {
        "module": str(module),
        "sha256": digest,
        "bytes": module.stat().st_size,
        "contract": str(CONTRACT_PATH),
        "facts": facts,
    }
    (out_dir / "build.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
