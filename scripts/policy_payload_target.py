"""Capture exact-image loader metadata from a DDK vmlinux (read-only, no pyelftools)."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

HOOKS = ["sel_write_context", "sel_write_access", "selinux_setprocattr", "sel_open_handle_status",
         "sel_read_handle_status", "sel_mmap_handle_status", "sk_filter_trim_cap", "commit_creds", "__skb_try_recv_datagram"]
LOADER = ["set_memory_nx", "set_memory_rw", "set_memory_ro", "set_memory_x"]

def capture(root, output, source=None):
    source = source or root / "source"
    alternative_header = (source / "arch/arm64/include/asm/alternative.h").read_text()
    alternative_abi = re.search(r"\b(void|int)\s+apply_alternatives_module\s*\(", alternative_header)
    assert alternative_abi, "native alternatives prototype missing"
    symbols = {}
    for row in (root / "System.map").read_text().splitlines():
        fields = row.split()
        if len(fields) == 3:
            symbols.setdefault(fields[2], []).append(int(fields[0], 16))
    auto_config = (root / "include/config/auto.conf").read_bytes()
    config = dict(line.split("=", 1) for line in auto_config.decode().splitlines()
                  if line.startswith("CONFIG_"))
    target_config = (root / ".config").read_bytes() if (root / ".config").exists() else None
    if target_config is not None:
        target_values = dict(line.split("=", 1) for line in target_config.decode().splitlines()
                             if line.startswith("CONFIG_"))
        # Kconfig emits escaped, quoted strings in .config and raw strings in auto.conf.
        unquoted_values = {
            name: re.sub(r'\\([\\"])', r'\1', value[1:-1])
            if len(value) >= 2 and value.startswith('"') and value.endswith('"') else value
            for name, value in target_values.items()
        }
        if target_values != config and unquoted_values != config:
            raise ValueError("target .config options differ from auto.conf")
    cache = next(n for n in ["caches_clean_inval_pou", "__flush_icache_range"] if n in symbols)
    required = HOOKS + LOADER + [cache, "apply_alternatives_module"]
    assert all(len(symbols.get(n, [])) == 1 for n in required), "loader/hook symbol missing or ambiguous"
    with (root / "vmlinux").open("rb") as f:
        def read(at, length):
            f.seek(at)
            data = f.read(length)
            assert len(data) == length
            return data
        h = struct.unpack("<16sHHIQQQIHHHHHH", read(0, 64))
        assert h[0][:6] == b"\x7fELF\x02\x01" and h[2] == 183
        phdrs = [struct.unpack("<IIQQQQQQ", read(h[5] + i * h[9], 56)) for i in range(h[10])]
        def memory(address, length):
            p = next(p for p in phdrs if p[0] == 1 and p[3] <= address and address + length <= p[3] + p[5])
            return read(p[2] + address - p[3], length)

        def native_entries(address, original):
            # Native get_alt_insn() rebases branches out of the replacement.
            # Only complete verified alternatives are admitted, never masks.
            variants = {original}
            first = symbols["__alt_instructions"][0]
            last = symbols["__alt_instructions_end"][0]
            for at in range(first, last, 12):
                old, new, feature, oldlen, newlen = struct.unpack("<iiHBB", memory(at, 12))
                old, new = at + old, at + 4 + new
                if old >= address + len(original) or old + oldlen <= address:
                    continue
                if feature & 0x8000 or oldlen != newlen or oldlen % 4 or oldlen > 256:
                    raise ValueError("unverified native alternative")
                patched = bytearray(memory(new, newlen))
                for offset in range(0, newlen, 4):
                    instruction = struct.unpack_from("<I", patched, offset)[0]
                    # Cache alternatives use B/BL. Reject other PC-relative
                    # forms here until their native relocation is covered.
                    if instruction & 0x7c000000 == 0x14000000:
                        displacement = instruction & 0x03ffffff
                        if displacement & 0x02000000:
                            displacement -= 0x04000000
                        target = new + offset + displacement * 4
                        if not new <= target <= new + newlen:
                            delta = target - (old + offset)
                            if delta % 4 or not -(1 << 27) <= delta < 1 << 27:
                                raise ValueError("native alternative branch range")
                            instruction = instruction & 0xfc000000 | ((delta // 4) & 0x03ffffff)
                    elif (instruction & 0x9f000000 in (0x10000000, 0x90000000) or
                          instruction & 0x3b000000 == 0x18000000 or
                          instruction & 0xff000010 == 0x54000000 or
                          instruction & 0x7e000000 in (0x34000000, 0x36000000)):
                        raise ValueError("unverified native alternative PC-relative instruction")
                    struct.pack_into("<I", patched, offset, instruction)
                begin, end = max(old, address), min(old + oldlen, address + len(original))
                for entry in tuple(variants):
                    changed = bytearray(entry)
                    changed[begin-address:end-address] = patched[begin-old:end-old]
                    variants.add(bytes(changed))
                if len(variants) > 16:
                    raise ValueError("too many native alternative variants")
            return sorted(entry.hex() for entry in variants)
        ids = []
        for p in phdrs:
            if p[0] != 4:
                continue
            data = read(p[2], p[5])
            at = 0
            while at + 12 <= len(data):
                ns, ds, kind = struct.unpack_from("<III", data, at)
                start = at + 12
                desc = start + ((ns + 3) & ~3)
                assert desc + ds <= len(data)
                if kind == 3 and data[start:start+ns] == b"GNU\0":
                    ids.append(data[desc:desc+ds].hex())
                at = desc + ((ds + 3) & ~3)
        assert len(set(ids)) == 1 and len(ids[0]) >= 16, "kernel GNU build ID missing or ambiguous"
        fingerprints = []
        native_code = []
        # ARM64 assembly string primitives have a fixed C ABI but may have no
        # BTF FUNC record. Retain exact native/alternative entry evidence.
        native_names = [cache] + [n for n in ("memcpy", "memset", "strlen", "strcmp") if n in symbols]
        for n in HOOKS + native_names:
            address = symbols[n][0]
            p = next(p for p in phdrs if p[0] == 1 and p[1] & 1 and p[3] <= address and address + 16 <= p[3] + p[5])
            code = read(p[2] + address - p[3], 16)
            item = dict(name=n, first16=code.hex())
            if n not in HOOKS:
                item["runtimeFirst16"] = native_entries(address, code)
            (fingerprints if n in HOOKS else native_code).append(item)
        native_scs = None
        scs_function = None
        scs_arguments = None
        if config.get("CONFIG_DYNAMIC_SCS") == "y":
            # Small read-only capture of the actual kernel patcher and helper
            # for offline instruction replay; no large vmlinux copy is needed.
            scs_function = next(n for n in ["__pi_scs_patch", "scs_patch"] if n in symbols)
            header = (source / "arch/arm64/include/asm/scs.h").read_text()
            signature = re.search(r"\b(?:__pi_)?scs_patch\s*\(([^;]*)\)\s*;", header)
            assert signature, "native SCS prototype missing"
            parameters = signature[1].split(",")
            scs_arguments = len(parameters)
            assert scs_arguments == 2 or (scs_arguments == 3 and "bool" in parameters[2]), "native SCS ABI unknown"
            helper_name = scs_function.replace("scs_patch", "scs_handle_fde_frame")
            entry, helper = symbols[scs_function][0], symbols[helper_name][0]
            functions = [int(row.split()[0], 16) for row in (root / "System.map").read_text().splitlines()
                         if len(row.split()) == 3 and row.split()[1] in ("t", "T") and
                         "$" not in row.split()[2]]
            last_function = min(at for at in functions if at > max(entry, helper))
            first, last = min(entry, helper) & ~4095, (last_function + 4095) & ~4095
            p = next(p for p in phdrs if p[0] == 1 and p[1] & 1 and p[3] <= first and last <= p[3] + p[5])
            data = read(p[2] + first - p[3], last - first)
            path = output.with_name("native-scs.bin")
            path.write_bytes(data)
            extra_text = []
            for name in ("offset_to_ptr", "skip_xleb128", "scs_patch_loc", "dcache_clean_pou"):
                for address in symbols.get(name, []):
                    page = address & ~4095
                    if first <= page < last or page in {item["base"] for item in extra_text}:
                        continue
                    segment = next(p for p in phdrs if p[0] == 1 and p[1] & 1 and
                                   p[3] <= page and page + 4096 <= p[3] + p[5])
                    block = read(segment[2] + page - segment[3], 4096)
                    filename = f"native-scs-helper-{len(extra_text)}.bin"
                    output.with_name(filename).write_bytes(block)
                    extra_text.append(dict(base=page, file=filename, sha256=hashlib.sha256(block).hexdigest()))
            rodata = []
            # Clang lowers the opcode switch into a PC-relative jump table.
            # Capture only referenced read-only pages, never the whole image.
            for at in range(min(entry, helper), last_function, 4):
                insn = struct.unpack_from("<I", data, at - first)[0]
                kind = insn & 0x9f000000
                if kind not in (0x90000000, 0x10000000):
                    continue
                imm = ((insn >> 5) & 0x7ffff) << 2 | ((insn >> 29) & 3)
                if imm & (1 << 20):
                    imm -= 1 << 21
                address = ((at & ~4095) + (imm << 12) if kind == 0x90000000 else at + imm) & ~4095
                if first <= address < last:
                    continue
                if address in {item["base"] for item in rodata}:
                    continue
                segment = next(p for p in phdrs if p[0] == 1 and
                               p[3] <= address and address + 4096 <= p[3] + p[5])
                block = read(segment[2] + address - segment[3], 4096)
                filename = f"native-scs-rodata-{len(rodata)}.bin"
                output.with_name(filename).write_bytes(block)
                rodata.append(dict(base=address, file=filename, sha256=hashlib.sha256(block).hexdigest()))
            native_scs = dict(base=first, entry=entry, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
                              strlen=symbols["strlen"][0], rodata=rodata, extraText=extra_text)
            if "strcmp" in symbols:
                native_scs["strcmp"] = symbols["strcmp"][0]
    page = next(size * 1024 for size in [4, 16, 64] if config.get(f"CONFIG_ARM64_{size}K_PAGES") == "y")
    record = dict(buildId=ids[0], pageSize=page, hooks=fingerprints,
        dynamicScs=config.get("CONFIG_DYNAMIC_SCS") == "y", cacheFunction=cache,
        alternativesReturnsStatus=alternative_abi[1] == "int", nativeCodeAbi=native_code,
        requiredLoaderSymbols=required, release=(root / "include/config/kernel.release").read_text().strip(),
        configSha256=hashlib.sha256(auto_config).hexdigest(),
        scope="Exact image identity and hook bytes, not OEM image family or runtime capability acceptance")
    if target_config is not None:
        record.update(targetConfigSha256=hashlib.sha256(target_config).hexdigest(),
                      targetConfigBytes=len(target_config))
    if native_scs:
        record["nativeScsReplay"] = native_scs
        record["scsFunction"] = scs_function
        record["scsArguments"] = scs_arguments
    output.write_text(json.dumps(record, indent=2) + "\n")
    print("Captured exact-image metadata:", record["release"], ids[0])

if __name__ == "__main__":
    capture(Path(sys.argv[1]), Path(sys.argv[2]))
