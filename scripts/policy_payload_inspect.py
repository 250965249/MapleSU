"""Inspect our KSU-derived ARM64 PIC candidate before considering SDK loading."""
import hashlib
from elftools.elf.elffile import ELFFile

ENTRIES = ["maplesu_policy_view_prepare", "maplesu_policy_view_handles",
           "maplesu_policy_view_context", "maplesu_policy_view_access",
           "maplesu_policy_view_setprocattr", "maplesu_policy_view_status_open",
           "maplesu_policy_view_status_read", "maplesu_policy_view_status_mmap",
           "maplesu_policy_view_filter", "maplesu_policy_view_creds_changed", "maplesu_policy_view_receive"]
# PACIASP is a landing pad until a dynamic-SCS kernel replaces it with SCS_PUSH.
# Public SDK entries need a separate BTI C instruction that survives that patch.
LANDINGS = {0xd503245f}

def inspect_payload(path, kernel_symbols):
    def require(test, reason):
        if not test:
            raise ValueError("POLICY_PAYLOAD_" + reason)
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        require(elf["e_machine"] == "EM_AARCH64" and elf["e_type"] == "ET_DYN" and
                elf.elfclass == 64 and elf.little_endian, "FORMAT")
        loads = [seg for seg in elf.iter_segments() if seg["p_type"] == "PT_LOAD"]
        require(loads and max(s["p_vaddr"] + s["p_memsz"] for s in loads) < 8 << 20, "SIZE")
        require(all(not (s["p_flags"] & 1 and s["p_flags"] & 2) for s in loads), "WX")
        require(not any(s["p_type"] in {"PT_INTERP", "PT_TLS"} for s in elf.iter_segments()), "PROGRAM")
        require(not any(s.name in {"__jump_table", ".init_array", ".fini_array", "__ex_table"}
                        and s["sh_size"] for s in elf.iter_sections()), "UNREGISTERED_SECTION")
        dyn = elf.get_section_by_name(".dynsym")
        require(dyn is not None, "DYNSYM")
        imports = sorted({s.name for s in dyn.iter_symbols() if s["st_shndx"] == "SHN_UNDEF" and s.name})
        require(all(name in kernel_symbols for name in imports), "IMPORT")
        tags = list(elf.get_section_by_name(".dynamic").iter_tags())
        require(not any(t["d_tag"] in {"DT_NEEDED", "DT_TEXTREL", "DT_REL", "DT_RELR", "DT_INIT", "DT_FINI"}
                        for t in tags), "DYNAMIC")
        relocs = [r["r_info_type"] for sec in elf.iter_sections()
                  if sec["sh_type"] == "SHT_RELA" and sec["sh_flags"] & 2 for r in sec.iter_relocations()]
        require(set(relocs) <= {1025, 1026, 1027}, "RELOCATION")
        def code(address, size):
            for seg in loads:
                if seg["p_flags"] & 1 and seg["p_vaddr"] <= address and address + size <= seg["p_vaddr"] + seg["p_filesz"]:
                    return seg.data()[address - seg["p_vaddr"]:address - seg["p_vaddr"] + size]
            raise ValueError("POLICY_PAYLOAD_CODE_RANGE")
        landings = {}
        for name in ENTRIES:
            entries = dyn.get_symbol_by_name(name)
            require(entries and len(entries) == 1 and entries[0]["st_info"]["type"] == "STT_FUNC", "ENTRY")
            instruction = int.from_bytes(code(entries[0]["st_value"], 4), "little")
            require(instruction in LANDINGS, "BTI_ENTRY:" + name)
            landings[name] = hex(instruction)
        bti = any(note["n_name"] == "GNU" and note["n_type"] == "NT_GNU_PROPERTY_TYPE_0" and
                  any(p["pr_type"] == "GNU_PROPERTY_AARCH64_FEATURE_1_AND" and p["pr_data"] & 1
                      for p in note["n_desc"])
                  for sec in elf.iter_sections() if sec["sh_type"] == "SHT_NOTE" for note in sec.iter_notes())
        require(bti, "BTI_NOTE")
        alternatives = []
        alt = elf.get_section_by_name(".altinstructions")
        if alt:
            data = alt.data()
            require(len(data) % 12 == 0, "ALTERNATIVE_SIZE")
            for at in range(0, len(data), 12):
                original = alt["sh_addr"] + at + int.from_bytes(data[at:at+4], "little", signed=True)
                replacement = alt["sh_addr"] + at + 4 + int.from_bytes(data[at+4:at+8], "little", signed=True)
                oldlen, newlen = data[at+10:at+12]
                require(oldlen > 0 and oldlen == newlen and oldlen % 4 == 0, "ALTERNATIVE_LENGTH")
                alternatives.append(dict(original=original, replacement=replacement,
                    capability=int.from_bytes(data[at+8:at+10], "little"),
                    originalHex=code(original, oldlen).hex(), replacementHex=code(replacement, newlen).hex()))
        return dict(passed=True, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            bytes=path.stat().st_size, imports=imports, dynamicRelocations=sorted(set(relocs)),
            relocationCount=len(relocs), branchLandings=landings, btiProperty=True,
            jumpLabelSites=False, alternatives=alternatives,
            alternativesApplied=False, kernelExecution=False)
