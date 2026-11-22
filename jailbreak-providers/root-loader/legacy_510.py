"""ABI measurements for the Android 12 5.10 image that carries no BTF.

Instruction anchors come from this image's disassembly. The reference module
supplies struct module's section size; its name/init slots are also checked
against the image. This is deliberately separate from the BTF gate.
"""


def image_layouts(b, contract, image, symbols):
    proof = contract["abiEvidence"]
    if proof["schema"] != "maplesu.legacy-510-instructions.v1":
        raise b.GateFailure("unknown 5.10 instruction ABI schema")
    if b.sha256_bytes(image) != contract["imageSha256"]:
        raise b.GateFailure("5.10 instruction ABI image SHA256 mismatch")
    symbols_path = b.PROJECT_ROOT / contract["symbolsPath"]
    reference_path = b.PROJECT_ROOT / proof["referenceModulePath"]
    for path, digest in ((symbols_path, proof["symbolsSha256"]),
                         (reference_path, proof["referenceModuleSha256"])):
        if b.sha256_file(path) != digest:
            raise b.GateFailure("5.10 ABI evidence SHA256 mismatch: " + str(path))
    reference = b.Elf(reference_path)
    section = reference.section(".gnu.linkonce.this_module")
    evidence = []

    def measure(function, offset, expected, kind):
        start = symbols.address(function)
        if start is None:
            raise b.GateFailure("5.10 ABI anchor function missing: " + function)
        word = b.read_uint32(image, start + offset)
        if word != expected:
            raise b.GateFailure("5.10 ABI instruction changed: %s+0x%x" % (function, offset))
        if kind == "movz":
            value = ((word >> 5) & 0xffff) << (((word >> 21) & 3) * 16)
        elif kind == "imm12":
            value = (word >> 10) & 0xfff
        elif kind == "uoff":
            value = ((word >> 10) & 0xfff) << (word >> 30)
        elif kind == "pair64":
            value = (word >> 15) & 0x7f
            value = (value - 128 if value & 64 else value) * 8
        evidence.append({"function": function, "offset": hex(offset),
                         "address": hex(start + offset), "instruction": hex(word),
                         "decoded": value})
        return value

    module = {"size": section["size"], "members": {
        "name": measure("load_module", 0x36c, 0x91006117, "imm12"),
        "init": measure("do_init_module", 0x58, 0xf940ca80, "uoff"),
        "exit": measure("__do_sys_delete_module", 0x3a8, 0xf941ded5, "uoff"),
        "cfi_check": measure("load_module", 0x28c0, 0xf9008a88, "uoff")}}
    body = reference.section_bytes(section)
    if body[module["members"]["name"]:].split(b"\x00", 1)[0] != b"dfroot":
        raise b.GateFailure("5.10 reference module name disagrees with image slot")
    init = [r for r in reference.relocations(section["name"]) if r["symbol"] == "init_module"]
    if len(init) != 1 or init[0]["offset"] != module["members"]["init"]:
        raise b.GateFailure("5.10 reference module init disagrees with image slot")

    addr = measure("register_kprobe", 0x38, 0xa942a000, "pair64")
    list_offset = measure("aggr_post_handler", 0x20, 0x91004015, "imm12")
    probe = {"size": measure("register_kprobe", 0x36c, 0x52801102, "movz"),
             "members": {"addr": addr, "symbol_name": addr + 8,
                         "pre_handler": list_offset + measure("aggr_pre_handler", 0x5c, 0xf9401aa8, "uoff"),
                         "post_handler": list_offset + measure("aggr_post_handler", 0x6c, 0xf9401ec8, "uoff"),
                         "flags": measure("register_kprobe", 0x3b8, 0xb9008009, "uoff")}}
    selinux = {"size": measure("selinux_init", 0x28, 0x52800b02, "movz"),
               "members": {"enforcing": measure("selinux_init", 0x54, 0x39000268, "uoff"),
                           "initialized": measure("security_load_policy", 0x324, 0x91000b68, "imm12")}}
    path = measure("call_usermodehelper_setup", 0x70, 0xa903dc08, "pair64")
    init = measure("call_usermodehelper_setup", 0x84, 0xa905d414, "pair64")
    subprocess = {"size": measure("call_usermodehelper_setup", 0x40, 0x52800e02, "movz"),
                  "members": {"path": path, "argv": path + 8, "init": init, "cleanup": init + 8,
                              "envp": measure("call_usermodehelper_setup", 0x80, 0xf9002416, "uoff"),
                              "data": measure("call_usermodehelper_setup", 0x8c, 0xf9003413, "uoff"),
                              "complete": measure("call_usermodehelper_exec", 0x16c, 0xf9001a68, "uoff"),
                              "wait": measure("call_usermodehelper_exec", 0x164, 0xb9005274, "uoff"),
                              "retval": measure("call_usermodehelper_exec", 0x214, 0xb9405674, "uoff")}}
    checks = [(module["size"], contract["thisModule"]["size"]),
              (module["members"]["cfi_check"], contract["cfi"]["checkMemberOffset"]),
              (probe["size"], contract["kprobe"]["size"]),
              (probe["members"]["addr"], contract["kprobe"]["addrOffset"]),
              (probe["members"]["symbol_name"], contract["kprobe"]["symbolNameOffset"]),
              (selinux["size"], contract["selinuxState"]["size"])]
    checks += [(module["members"][name], contract["thisModule"][name + "Offset"])
               for name in ("name", "init", "exit")]
    checks += [(selinux["members"][name], contract["selinuxState"][name + "Offset"])
               for name in ("enforcing", "initialized")]
    spi = contract["structOffsets"]["subprocessInfo"]
    checks += [(subprocess["size"], spi["size"]), (path, spi["path"])]
    members = {m["name"]: m["byteOffset"] for m in spi["members"]}
    checks += [(value, members.get(name)) for name, value in subprocess["members"].items()]
    if any(actual != declared for actual, declared in checks):
        raise b.GateFailure("5.10 ABI contract disagrees with image/reference measurements")
    if contract.get("printkSymbol") != "printk" or symbols.address("__ksymtab_printk") is None:
        raise b.GateFailure("5.10 printk export is not measured")
    return {"source": "image instructions + reference module", "module": module,
            "kprobe": probe, "selinux_state": selinux, "subprocess_info": subprocess,
            "instructions": evidence,
            "referenceModule": {"path": b.rel(reference_path), "sha256": b.sha256_file(reference_path),
                                "moduleSizeSource": ".gnu.linkonce.this_module section"}}


def gate_struct_shim(b, ctx, gate):
    layouts = ctx.image_layouts
    asserted = b.header_assertions(ctx.contract, ctx.header)
    for name in ("kprobe", "selinux_state", "subprocess_info"):
        shim = "maplesu_" + name
        measured = layouts[name]
        gate.require(asserted["sizeof"].get(shim) == measured["size"],
                     shim + " size agrees with measured ABI")
        for member, offset in measured["members"].items():
            if name == "kprobe" and member not in ("addr", "symbol_name"):
                continue
            gate.require(asserted["offsetof"].get(shim, {}).get(member) == offset,
                         shim + "." + member + " agrees with measured ABI")
    if ctx.is_l3:
        for name in ("maplesu_probe", "maplesu_avc_probe"):
            gate.require(ctx.elf.symbol(name)["size"] == layouts["kprobe"]["size"],
                         name + " allocates the full measured kprobe")
    gate.extras["instructionAbi"] = layouts
