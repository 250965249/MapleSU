"""Measured inputs for the resident SDK transport and environment ABI."""
from pathlib import Path
import struct

REQUEST_PROTOCOL = "../../runtime/ultra/authorization/request_protocol.h"
LEGACY_HOOK_PRIVATE = "../../runtime/ultra/authorization/legacy_hook_private.h"

SYMBOLS = ("_text", "__arm64_sys_execve", "kallsyms_lookup_name", "copy_from_user_nofault",
    "copy_to_user_nofault", "copy_from_kernel_nofault", "copy_to_kernel_nofault", "vfree", "get_random_bytes",
    "set_memory_ro", "set_memory_rw", "set_memory_nx", "set_memory_x", "prepare_creds",
    "commit_creds", "get_task_cred", "__put_cred", "__start_notes", "__stop_notes")
SOURCES = ("boot_sdk_build.py", "boot_sdk_abi.h", "module/boot_sdk_protocol.h",
    "module/boot_sdk_allocator.h", "module/maplesu_boot_sdk.c", "module/boot_sdk_call.S",
    REQUEST_PROTOCOL, LEGACY_HOOK_PRIVATE)
ENV_SYMBOLS = ("do_execveat_common", "avc_denied", "filldir64", "slow_avc_audit")


def stage_protocol(output):
    """Stage the unique request wire definition used by the SDK and bridge."""
    source = Path(__file__).resolve().parent / REQUEST_PROTOCOL
    (output / "request_protocol.h").write_bytes(source.read_bytes())
    source = Path(__file__).resolve().parent / LEGACY_HOOK_PRIVATE
    (output / "legacy_hook_private.h").write_bytes(source.read_bytes())


def allocator_names(symbols):
    for suffix in ("", "_noprof"):
        names = ("vmalloc" + suffix, "__vmalloc_node_range" + suffix)
        if all(symbols.address(name) is not None for name in names):
            return names
    return None


def release_name(symbols):
    return next((name for name in ("module_memfree", "execmem_free")
                 if symbols.address(name) is not None), None)


def kernel_notes(image, symbols):
    start, end = symbols.address("__start_notes"), symbols.address("__stop_notes")
    if start is None or end is None or not 0 < start < end <= len(image) or end - start > 512:
        return None
    notes = image[start:end]
    # A non-empty GNU build ID must be present in the retained note block.
    at, found = 0, False
    while at + 12 <= len(notes):
        names, size, kind = struct.unpack_from("<III", notes, at)
        name_at = at + 12
        value_at = name_at + ((names + 3) & ~3)
        next_at = value_at + ((size + 3) & ~3)
        if next_at > len(notes):
            return None
        found |= kind == 3 and notes[name_at:name_at + names] == b"GNU\0" and size >= 16
        at = next_at
    return notes.hex() if found and at == len(notes) else None


def _logical_immediate(word):
    """AArch64 DecodeBitMasks for the 64-bit ORR-immediate wrapper operands."""
    size = ((word >> 22 & 1) << 6 | (~(word >> 10) & 63)).bit_length() - 1
    if not 1 <= size <= 6:
        raise ValueError("invalid vmalloc logical immediate")
    width = 1 << size
    ones, rotation = (word >> 10 & 63) & (width - 1), (word >> 16 & 63) & (width - 1)
    if ones == width - 1:
        raise ValueError("reserved vmalloc logical immediate")
    mask, value = (1 << width) - 1, (1 << (ones + 1)) - 1
    value = ((value >> rotation) | (value << (width - rotation))) & mask
    return sum(value << at for at in range(0, 64, width))


def vmalloc_facts(image, symbols):
    """Recognize the measured wrapper; unknown instruction shapes stay gated.

    All variable operands, including VMALLOC bounds and the runtime pgprot
    selector, come from this image. No host kernel constants enter the call.
    """
    names = allocator_names(symbols)
    if names is None:
        return None
    at = symbols.address(names[0])
    profiled = names[0].endswith("_noprof")
    if at is None or at < 0 or at + 20 > len(image):
        return None
    canonical_lr = not profiled and struct.unpack_from("<I", image, at + 16)[0] & 0x9f00001f == 0x90000008
    count = 27 if profiled else 30 if canonical_lr else 26
    if at + count * 4 > len(image):
        return None
    w = struct.unpack_from("<%dI" % count, image, at)
    fixed = {0: 0xd503233f, 1: 0xd10083ff, 2: 0xa9017bfd, 3: 0x910043fd,
        4: 0xd50320ff, 13: 0x7100011f, 16: 0x9a8a0125, 18: 0xaa1f03e6,
        19: 0x12800007, 20: 0xf90003fe, 22: 0xa9417bfd, 23: 0x910083ff,
        24: 0xd50323bf, 25: 0xd65f03c0}
    masked = {5: (0x9f00001f, 0x90000008), 6: (0xffe0001f, 0xd2800009),
        7: (0xffc003ff, 0x39400108), 8: (0xffe0001f, 0xf2e00009),
        9: (0xff8003ff, 0xb20003e2), 10: (0xff8003ff, 0xb200012a),
        11: (0xff8003ff, 0xb20003e3), 12: (0xffe0001f, 0x52800001),
        14: (0xffe0001f, 0xf2a00002), 15: (0xffe0001f, 0xf2c00003),
        17: (0xffe0001f, 0x52800004), 21: (0xfc000000, 0x94000000)}
    # 6.12 adds allocation profiling and a stack canary; recover the same
    # nine-argument call from its measured wrapper, including CSEL polarity.
    branch_at, adrp_at, flag_at = 21, 5, 7
    start_at, end_at, start_movk, end_movk = 9, 11, 14, 15
    align_at, gfp_at, prot_at, prot_hi, prot_set = 12, 17, 6, 8, 10
    if profiled:
        fixed = {0: 0xd503233f, 1: 0xd10103ff, 2: 0xa9037bfd, 3: 0x9100c3fd,
            4: 0xd5384108, 6: 0xf81f83a8, 7: 0xd50320ff, 8: 0xf81f03bf,
            9: 0xd503201f, 19: 0x7100011f, 22: 0x9a891145,
            23: 0xaa1f03e6, 24: 0x12800007, 25: 0xf90003fe}
        masked = {5: (0xffc003ff, 0xf9400108),
            10: (0x9f00001f, 0x90000008), 11: (0xffe0001f, 0xd2800009),
            12: (0xff8003ff, 0xb20003e2), 13: (0xffc003ff, 0x39400108),
            14: (0xffe0001f, 0xf2e00009), 15: (0xff8003ff, 0xb20003e3),
            16: (0xff8003ff, 0xb200012a), 17: (0xffe0001f, 0x52800001),
            18: (0xffe0001f, 0xf2a00002), 20: (0xffe0001f, 0xf2a00003),
            21: (0xffe0001f, 0x52800004), 26: (0xfc000000, 0x94000000)}
        branch_at, adrp_at, flag_at = 26, 10, 13
        start_at, end_at, start_movk, end_movk = 12, 15, 18, 20
        align_at, gfp_at, prot_at, prot_hi, prot_set = 17, 21, 11, 14, 16
    elif canonical_lr:
        # 6.1 canonicalizes the return address before passing the ninth argument.
        fixed = {0: 0xd503233f, 1: 0xd10083ff, 2: 0xa9017bfd, 3: 0x910043fd,
            5: 0xd50320ff, 7: 0xb25963c9, 8: 0x9249bfca, 9: 0xf24903df,
            12: 0x9a890149, 16: 0x7100011f, 18: 0x9a8a0165,
            22: 0xaa1f03e6, 23: 0x12800007, 24: 0xf90003e9,
            26: 0xa9417bfd, 27: 0x910083ff, 28: 0xd50323bf, 29: 0xd65f03c0}
        masked = {4: (0x9f00001f, 0x90000008), 6: (0xffe0001f, 0xd280000b),
            10: (0xffc003ff, 0x39400108), 11: (0xffe0001f, 0xf2e0000b),
            13: (0xff8003ff, 0xb200016a), 14: (0xff8003ff, 0xb20003e2),
            15: (0xff8003ff, 0xb20003e3), 17: (0xffe0001f, 0x52800001),
            19: (0xffe0001f, 0xf2a00002), 20: (0xffe0001f, 0xf2c00003),
            21: (0xffe0001f, 0x52800004), 25: (0xfc000000, 0x94000000)}
        branch_at, adrp_at, flag_at = 25, 4, 10
        start_at, end_at, start_movk, end_movk = 14, 15, 19, 20
        align_at, gfp_at, prot_at, prot_hi, prot_set = 17, 21, 6, 11, 13
    if any(w[i] != word for i, word in fixed.items()) or any(
            w[i] & mask != word for i, (mask, word) in masked.items()):
        return None
    branch = w[branch_at] & 0x3ffffff
    if branch & 0x2000000:
        branch -= 0x4000000
    if at + branch_at * 4 + branch * 4 != symbols.address(names[1]):
        return None
    immediate = (w[adrp_at] >> 5 & 0x7ffff) << 2 | (w[adrp_at] >> 29 & 3)
    if immediate & 0x100000:
        immediate -= 0x200000
    flag = ((at + adrp_at * 4) & ~4095) + immediate * 4096 + (w[flag_at] >> 10 & 4095)
    start = _logical_immediate(w[start_at]) & ~(0xffff << 16) | (w[start_movk] >> 5 & 0xffff) << 16
    end_shift = 16 if profiled else 32
    end = _logical_immediate(w[end_at]) & ~(0xffff << end_shift) | (w[end_movk] >> 5 & 0xffff) << end_shift
    prot = (w[prot_at] >> 5 & 0xffff) | (w[prot_hi] >> 5 & 0xffff) << 48
    image_size = struct.unpack_from("<Q", image, 16)[0]
    if (image[56:60] != b"ARM\x64" or image_size < len(image) or
            not 0 < flag < image_size or not (1 << 63) < start < end < 1 << 64):
        return None
    base = symbols.address("_text")
    if base != 0:
        return None
    return {"MSU_BS_ALLOCATOR_NOPROF": int(profiled), "MSU_BS_IMAGE_BYTES": image_size,
        "MSU_BS_VM_START_MAG": (1 << 64) - start, "MSU_BS_VM_END_MAG": (1 << 64) - end,
        "MSU_BS_VM_ALIGN": w[align_at] >> 5 & 0xffff, "MSU_BS_VM_GFP": w[gfp_at] >> 5 & 0xffff,
        "MSU_BS_VM_PROT": prot, "MSU_BS_VM_PROT_SET": prot | _logical_immediate(w[prot_set]),
        "MSU_BS_VM_PROT_FLAG": flag}


def environment_facts(btf, symbols):
    """The legacy packet encodes filename's register, not its BTF ordinal."""
    def plain(i):
        t = btf.types[i]
        while t["kind"] in (8, 9, 10, 11, 18):
            t = btf.types[t["size"]]
        return t

    def proto(name):
        hits = [t for t in btf.types[1:] if t["kind"] == 12 and t["name"] == name]
        return btf.types[hits[0]["size"]] if len(hits) == 1 else None

    base = symbols.address("_text")
    free_name = release_name(symbols)
    if free_name is None:
        return {}
    offsets = {name: symbols.address(name) for name in ENV_SYMBOLS + (free_name,)}
    if any(at is None or not 0 < at - base <= 0xffffffff for at in offsets.values()):
        return {}
    signatures = {"do_execveat_common": [(1, 4), (2, None), (4, 16), (4, 16), (1, 4)],
        "avc_denied": [(1, 4), (1, 4), (1, 2), (1, 4), (1, 1), (1, 1), (1, 4), (2, None)],
        "filldir64": [(2, None), (2, None), (1, 4), (1, 8), (1, 8), (1, 4)],
        "slow_avc_audit": [(1, 4), (1, 4), (1, 2), (1, 4), (1, 4), (1, 4), (1, 4), (2, None)],
        free_name: [(2, None)]}
    prototypes = {}
    for name, signature in signatures.items():
        p = proto(name)
        if not p or p["vlen"] != len(signature):
            return {}
        params = [plain(v["type"]) for v in p["params"]]
        if any(t["kind"] != kind or size is not None and t["size"] != size
               for t, (kind, size) in zip(params, signature)):
            return {}
        prototypes[name] = params
    if proto(free_name)["size"] != 0:
        return {}
    filename_ptr = prototypes["do_execveat_common"][1]
    filename = plain(filename_ptr["size"])
    if (filename["kind"] != 4 or filename["name"] != "filename" or
            btf.member(filename, "name")["byte"] != 0 or
            plain(btf.member(filename, "name")["type"])["kind"] != 2):
        return {}
    try:
        combined, effective_bits = btf.field_layout("task_struct", "seccomp.mode")
    except (KeyError, ValueError, RuntimeError):
        return {}
    if combined & 7 or effective_bits != 32:
        return {}
    # The SDK clears task.seccomp.mode (4B), not the enclosing seccomp object.
    seccomp = combined // 8
    if not 0 < seccomp <= 32767:
        return {}
    return {"MSU_BS_ENVIRONMENT": 1, "MSU_BS_EXECMEM_FREE": int(free_name == "execmem_free"),
        "MSU_BS_EXECVE_OFFSET": offsets["do_execveat_common"] - base,
        "MSU_BS_EXECVE_REG": 1, "MSU_BS_EXECVE_CHAR": 0,
        "MSU_BS_FILLDIR_OFFSET": offsets["filldir64"] - base,
        "MSU_BS_SECCOMP_OFFSET": seccomp,
        "MSU_BS_AUDIT_OFFSET": offsets["slow_avc_audit"] - base}


def _static_facts(b, image, symbols, probe_size, bridge):
    if not bridge or any(symbols.address(name) is None for name in SYMBOLS):
        return {}
    flush = next((name for name in ("caches_clean_inval_pou", "__flush_icache_range")
                  if symbols.address(name) is not None), None)
    if flush is None:
        return {}
    notes = kernel_notes(image, symbols)
    if notes is None:
        return {}
    btf = b.Btf(image)

    def plain(type_id):
        t = btf.types[type_id]
        while t["kind"] in (8, 9, 10, 11):
            t = btf.types[t["size"]]
        return t

    def prototype(name):
        functions = [t for t in btf.types[1:] if t["kind"] == 12 and t["name"] == name]
        return btf.types[functions[0]["size"]] if len(functions) == 1 else None

    names = allocator_names(symbols)
    if names is None:
        return {}
    vm = vmalloc_facts(image, symbols)
    proto = prototype(names[1])
    if not vm or not proto or proto["vlen"] != 9:
        return {}
    params = [plain(p["type"]) for p in proto["params"]]
    if ([(p["kind"], p["size"]) for p in params[:5]] != [(1, 8)] * 4 + [(1, 4)] or
        params[5]["kind"] != 4 or params[5]["size"] != 8 or
        [(m["name"], m["byte"]) for m in params[5]["members"]] != [("pgprot", 0)] or
        (plain(params[5]["members"][0]["type"])["kind"],
         plain(params[5]["members"][0]["type"])["size"]) != (1, 8) or
        [(p["kind"], p["size"]) for p in params[6:8]] != [(1, 8), (1, 4)] or
        params[8]["kind"] != 2):
        return {}

    def member(st, field):
        return btf.member(btf.struct(st), field)["byte"]

    if btf.struct("kprobe")["size"] != probe_size:
        raise ValueError("boot SDK kprobe layout differs from contract")
    suid = member("cred", "suid")
    if (member("cred", "sgid") != suid + 4 or member("cred", "euid") != suid + 8 or
        member("cred", "securebits") != suid + 24):
        # The fixed SDK's JIT epilogue writes high result words at these offsets.
        return {}
    usage = btf.member(btf.struct("cred"), "usage")
    usage_type = btf.types[usage["type"]]
    while usage_type["kind"] in (8, 9, 10, 11):
        usage_type = btf.types[usage_type["size"]]
    if usage_type["size"] not in (4, 8) or \
        [(m["name"], m["byte"]) for m in usage_type["members"]] != [("counter", 0)]:
        return {}
    # Reject renamed or expanded helper ABIs rather than guessing call frames.
    for name, count in {names[0]: 1, "vfree": 1, "get_random_bytes": 2,
        "copy_from_kernel_nofault": 3, "copy_to_kernel_nofault": 3,
        "copy_from_user_nofault": 3, "copy_to_user_nofault": 3,
        "prepare_creds": 0, "commit_creds": 1, "get_task_cred": 1, "__put_cred": 1,
        "set_memory_ro": 2, "set_memory_rw": 2, "set_memory_x": 2, "set_memory_nx": 2}.items():
        functions = [t for t in btf.types[1:] if t["kind"] == 12 and t["name"] == name]
        if len(functions) != 1 or btf.types[functions[0]["size"]]["vlen"] != count:
            return {}
    # These cache helpers are assembly (no BTF FUNC record); their two-address
    # ABI is also used by the existing resident policy bridge.
    base = symbols.address("_text")
    kallsyms = symbols.address("kallsyms_lookup_name") - base
    if not 0 < kallsyms <= 0xffffffff:
        return {}
    environment = environment_facts(btf, symbols)
    return dict(defines={"MSU_BS_STATIC_BOOTSTRAP": 1, "MSU_BS_KPROBE_SIZE": probe_size,
        "MSU_BS_KP_ADDR": member("kprobe", "addr"),
        "MSU_BS_KP_NAME": member("kprobe", "symbol_name"),
        "MSU_BS_KP_PRE": member("kprobe", "pre_handler"),
        "MSU_BS_REGS_PC": bridge["defines"]["MSU_PH_REGS_PC"],
        "MSU_BS_PAGE_BYTES": bridge["defines"]["MSU_PH_PAGE_BYTES"],
        "MSU_BS_TASK_CRED": member("task_struct", "cred"),
        "MSU_BS_CRED_SUID": suid, "MSU_BS_CRED_SECUREBITS": suid + 24,
        "MSU_BS_CRED_USAGE": usage["byte"], "MSU_BS_CRED_USAGE_SIZE": usage_type["size"],
        "MSU_BS_KALLSYMS": kallsyms, **vm, "MSU_BS_ENVIRONMENT": 0, **environment},
        lookupSymbols=list(SYMBOLS) + list(names) + [flush] +
            [name for name in ("vmalloc_user", "vmalloc_user_noprof") if symbols.address(name) is not None] +
            (list(ENV_SYMBOLS) + [release_name(symbols)] if environment else []),
        capabilities=7 if environment else 3, environmentAbi=bool(environment), kernelNotesHex=notes)


def derive(b, image, symbols, probe_size, bridge):
    """Compile the runtime-layout entry independently of legacy image facts."""
    required = tuple(name for name in SYMBOLS if name not in ("__start_notes", "__stop_notes"))
    if not bridge or any(symbols.address(name) is None for name in required):
        return {}
    page = bridge.get("defines", {}).get("MSU_PH_PAGE_BYTES")
    names = allocator_names(symbols)
    flush = next((name for name in ("caches_clean_inval_pou", "__flush_icache_range")
                  if symbols.address(name) is not None), None)
    if page not in (4096, 16384, 65536) or names is None or flush is None:
        return {}
    try:
        static = _static_facts(b, image, symbols, probe_size, bridge)
    except (KeyError, ValueError, StopIteration):
        static = {}
    if static:
        return static
    optional = [name for name in ("vmalloc", "vmalloc_noprof", "__vmalloc_node_range",
                "__vmalloc_node_range_noprof", "___vmalloc_node_range", "___vmalloc_node_range_noprof",
                "vmalloc_user", "vmalloc_user_noprof") + ENV_SYMBOLS +
                ("module_memfree", "execmem_free") if symbols.address(name) is not None]
    return dict(defines={"MSU_BS_STATIC_BOOTSTRAP": 0, "MSU_BS_PAGE_BYTES": page,
        "MSU_BS_ALLOCATOR_NOPROF": int(names[0].endswith("_noprof")),
        "MSU_BS_ENVIRONMENT": 1, "MSU_BS_EXECVE_REG": 1, "MSU_BS_EXECVE_CHAR": 0,
        "MSU_BS_EXECMEM_FREE": int(release_name(symbols) == "execmem_free")},
        lookupSymbols=list(dict.fromkeys(list(required) + list(names) + [flush] + optional)),
        capabilities=3, environmentAbi=True, kernelNotesHex="")


def header(facts):
    result = ("/* Boot SDK ABI measured from the target image and BTF. */\n" +
              "\n".join("#define %s %d" % pair for pair in facts["defines"].items()) + "\n")
    if facts["defines"].get("MSU_BS_STATIC_BOOTSTRAP", 1):
        result += ("#define MSU_BS_KERNEL_NOTES_BYTES %d\n" % (len(facts["kernelNotesHex"]) // 2) +
                   "#define MSU_BS_KERNEL_NOTES {" + ",".join(
                       str(v) for v in bytes.fromhex(facts["kernelNotesHex"])) + "}\n")
    return result
