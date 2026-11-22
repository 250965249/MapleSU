"""Describe a boot backend without running its constructors or SDK initializers."""
import hashlib
import io
from pathlib import Path

def describe_backend(path: Path, *, arm64=True):
    from elftools.elf.elffile import ELFFile

    data = path.read_bytes()
    elf = ELFFile(io.BytesIO(data))
    if elf.elfclass != 64 or not elf.little_endian or elf["e_type"] != "ET_DYN":
        raise ValueError("backend must be a little-endian ELF64 DSO")
    if arm64 and elf["e_machine"] != "EM_AARCH64":
        raise ValueError("backend must be Android ARM64")
    symbols = elf.get_section_by_name(".dynsym")
    entries = [s for s in symbols.iter_symbols()
               if s.name == "maplesu_environment_policy_start" and s["st_shndx"] != "SHN_UNDEF"
               and s["st_info"]["bind"] == "STB_GLOBAL" and s["st_info"]["type"] == "STT_FUNC"
               and s["st_other"]["visibility"] == "STV_DEFAULT"] if symbols else []
    if len(entries) != 1:
        raise ValueError("backend is missing its public boot entry")
    note = elf.get_section_by_name(".note.gnu.build-id")
    if note is None or note["sh_offset"] + note["sh_size"] > 4096:
        raise ValueError("backend build identity must fit in the first file page")
    notes = list(note.iter_notes())
    if len(notes) != 1 or notes[0]["n_name"] != "GNU" or notes[0]["n_type"] != "NT_GNU_BUILD_ID":
        raise ValueError("backend has an invalid build identity")
    digest = hashlib.sha256(data).hexdigest()
    return dict(sha256=digest, size=len(data), buildId=notes[0]["n_desc"],
                fileName=f"libmaplesu_policy_boot.{digest}.so",
                noteOffset=note["sh_offset"], noteHex=note.data().hex())


def write_identity(path: Path, identity):
    note = bytes.fromhex(identity["noteHex"])
    path.write_text(
        "// Generated boot helper/backend pairing; do not edit.\n#pragma once\n"
        f'#define MAPLESU_POLICY_BACKEND_FILE "{identity["fileName"]}"\n'
        f'#define MAPLESU_POLICY_BACKEND_SIZE {identity["size"]}\n'
        f'#define MAPLESU_POLICY_BACKEND_NOTE_OFFSET {identity["noteOffset"]}\n'
        'static const unsigned char maplesu_policy_backend_note[] = {' +
        ','.join(map(str, note)) + '};\n', encoding="utf-8", newline="\n")
