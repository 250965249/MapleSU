"""Legacy LTO/cross-DSO CFI ABI for measured 5.10/5.15 images.

KCFI artifacts never enter this path. The compiler generates the real 64-bit
__cfi_check and canonical jump tables; no prefix rewriting is used here.
Unicorn executes only the linked check function for host-side positive/negative
ABI tests. The check ELF is diagnostic output and is never packaged.
"""
from pathlib import Path
import datetime
import importlib.util
import json
import shutil
import struct

_LAYOUT_SPEC = importlib.util.spec_from_file_location("legacy_510", Path(__file__).with_name("legacy_510.py"))
legacy_510 = importlib.util.module_from_spec(_LAYOUT_SPEC)
_LAYOUT_SPEC.loader.exec_module(legacy_510)

CLANG_FLAGS = ["-flto", "-fsanitize=cfi", "-fsanitize-cfi-cross-dso",
               "-fvisibility=hidden",
               "-DMAPLESU_LEGACY_CFI=1"]


def enabled(contract):
    return (contract.get("cfi") or {}).get("mode") == "clang-cfi"


def image_facts(b, contract, image_path=None):
    image = Path(image_path or b.PROJECT_ROOT / contract["imagePath"]).read_bytes()
    symbols = b.SymbolTable(b.PROJECT_ROOT / contract["symbolsPath"])
    slowpath_name = contract["cfi"].get("slowpath", "__cfi_slowpath_diag")
    slowpath = symbols.address(slowpath_name)
    if slowpath is None or symbols.address("__cfi_check") is None:
        raise b.GateFailure("image does not carry cross-DSO CFI runtime")
    facts = {"mode": "clang-cfi"}
    for label, site in contract["cfi"]["sites"].items():
        start = symbols.address(site["function"])
        if start is None:
            raise b.GateFailure("CFI dispatch function missing: " + site["function"])
        call = start + site["callOffset"]
        insn = b.read_uint32(image, call)
        imm = insn & 0x3ffffff
        target = call + ((imm - (1 << 26) if imm & (1 << 25) else imm) << 2)
        if insn >> 26 != 0b100101 or target != slowpath:
            raise b.GateFailure("CFI anchor is not a BL to " + slowpath_name)
        # The ABI passes the 64-bit type ID in x0. Require all four lanes rather
        # than interpreting an arbitrary immediate or a stale 32-bit KCFI pin.
        value, lanes = None, set()
        for at in range(max(start, call - 64), call, 4):
            word = b.read_uint32(image, at)
            movz, movk = b.decode_movz(word), b.decode_movk(word)
            if movz and movz[0] == 0 and word >> 31:
                value = movz[1] << (movz[2] * 16)
                lanes = {(word >> 21) & 3}
            elif movk and movk[0] == 0 and value is not None and word >> 31:
                shift = ((word >> 21) & 3) * 16
                value = (value & ~(0xffff << shift)) | (movk[1] << shift)
                lanes.add(shift // 16)
        if lanes != {0, 1, 2, 3} or value != int(site["typeId"], 16):
            raise b.GateFailure("image CFI type does not equal contract: " + label)
        facts[label] = {**site, "address": hex(start), "callAddress": hex(call),
                        "typeId": "0x%016x" % value}
    return facts


def l3_facts(b, contract, image, symbols, cfi, layouts=None):
    btf = None if layouts else b.Btf(image)
    probe = layouts["kprobe"] if layouts else btf.struct("kprobe")
    member_offset = (lambda name: probe["members"][name]) if layouts else \
                    (lambda name: btf.member(probe, name)["byte"])
    # These are the actual C shim's ABI fields, not assumptions inferred from
    # the presence of a kernel version string.
    for name, expected in (("addr", 0x28), ("symbol_name", 0x30),
                            ("pre_handler", 0x40), ("post_handler", 0x48)):
        if member_offset(name) != expected:
            raise b.GateFailure("legacy kprobe member layout mismatch: " + name)
    dispatch = {}
    for key, member in b.L3_CALLBACK_MEMBERS.items():
        dispatch[key] = {**cfi[key], "member": member,
                         "memberOffset": hex(member_offset(member)),
                         "anchorsPresent": [cfi[key]["function"]],
                         "anchorsAbsent": [], "attributedSites": [cfi[key]]}
    target = symbols.address(b.L3_PRCTL_SYMBOL)
    if target is None:
        raise b.GateFailure("legacy image has no prctl kprobe target")
    kprobe = {"symbol": "aggr_pre_handler", "address": cfi["preHandler"]["address"],
              "extent": None, "cfiTypeIds": [cfi[k]["typeId"] for k in dispatch],
              "callbackAnchors": contract["l3"]["callbackAnchors"], "dispatch": dispatch}
    return {"kprobe": kprobe, "callbackPins": {}, "callbackDispatch": dispatch,
            "callbackPrefixPolicy": "clang-cfi-dispatcher", "contractCallbacks": {},
            "callbackSize": probe["size"],
            "referenceKcfi": {k: int(cfi[k]["typeId"], 16) for k in dispatch},
            "probedSymbol": {"symbol": b.L3_PRCTL_SYMBOL, "address": hex(target),
                             "entryInstruction": hex(b.read_uint32(image, target))},
            "credSource": b.derive_cred_source(image, symbols),
            "rootSubject": b.derive_l3_subject_facts(image, symbols),
            "selinux": {**contract["selinuxState"], "writtenByModule": False},
            "statusView": b.derive_l3_status_view(image, symbols, contract),
            "policyBridge": b.derive_l3_policy_bridge(image, symbols, probe["size"])}


class CheckExecutor:
    """Run the exact packaged object's CFI dispatcher after normal ELF relocation."""
    def __init__(self, b, module, ld, directory):
        try:
            import unicorn
            from unicorn import arm64_const
        except ImportError as error:
            raise b.BuildError("legacy CFI host verification requires unicorn>=2.1,<3") from error
        self.uc, self.regs = unicorn, arm64_const
        path = directory / "cfi-check.elf"
        # No stubs or second compilation: lld relocates the already-built .ko.
        # Imports receive sentinel addresses which the checker must never call.
        runner = b.Runner()
        runner([ld, "--entry=__cfi_check", "-Ttext=0x100000", "-o", path,
                *["--defsym=%s=0x700000" % name for name in b.Elf(module).imports()], module])
        self.commands = runner.commands
        self.elf = b.Elf(path)
        self.check = self.address("__cfi_check")
        self.failure = self.address("__cfi_check_fail")
        self.failure_size = self.elf.symbol("__cfi_check_fail")["size"]
        self.return_address = 0x800000

    def address(self, name):
        symbol = self.elf.symbol(name)
        if symbol is None or symbol["shndx"] == 0:
            raise ValueError("CFI check ELF has no " + name)
        return symbol["value"]

    def accepts(self, type_id, target):
        u, r = self.uc, self.regs
        machine = u.Uc(u.UC_ARCH_ARM64, u.UC_MODE_ARM)
        pages = set()
        for section in self.elf.sections:
            if section["flags"] & 2 and section["size"]:
                first = section["addr"] & ~0xfff
                last = (section["addr"] + section["size"] + 0xfff) & ~0xfff
                pages.update(range(first, last, 0x1000))
        pages.add(self.return_address)
        for page in sorted(pages):
            machine.mem_map(page, 0x1000)
        for section in self.elf.sections:
            if section["flags"] & 2 and section["size"] and section["type"] != 8:
                machine.mem_write(section["addr"], self.elf.section_bytes(section))
        machine.reg_write(r.UC_ARM64_REG_X0, type_id)
        machine.reg_write(r.UC_ARM64_REG_X1, target)
        machine.reg_write(r.UC_ARM64_REG_X2, 0)
        machine.reg_write(r.UC_ARM64_REG_LR, self.return_address)
        rejected = []
        def stop_on_failure(uc, address, size, user):
            word = int.from_bytes(uc.mem_read(address, 4), "little")
            if (self.failure <= address < self.failure + self.failure_size
                    and word == 0xd42aa040):  # BRK #0x5502
                rejected.append(True)
                uc.emu_stop()
        machine.hook_add(u.UC_HOOK_CODE, stop_on_failure)
        # Unexpected instruction/fault is a verifier failure, not a valid rejection.
        machine.emu_start(self.check, self.return_address, count=512)
        pc = machine.reg_read(r.UC_ARM64_REG_PC)
        if not rejected and pc != self.return_address:
            raise ValueError("CFI dispatcher neither returned nor rejected the call")
        return not rejected


def cfi_checks(b, context, ld, directory):
    elf = context.elf
    check = elf.symbol("__cfi_check")
    if check is None or check["shndx"] == 0:
        raise b.GateFailure("compiler-generated __cfi_check is missing")
    section = elf.symbol_section(check)
    if section["align"] < 4096 or check["value"] % 4096:
        raise b.GateFailure("__cfi_check must be page-aligned for the CFI shadow")
    check_offset = (context.image_layouts["module"]["members"]["cfi_check"]
                    if context.image_layouts else
                    context.btf.member(context.btf.struct("module"), "cfi_check")["byte"])
    if check_offset != context.contract["cfi"]["checkMemberOffset"]:
        raise b.GateFailure("module.cfi_check offset disagrees with measured image ABI")
    executor = CheckExecutor(b, context.module, ld, directory)
    pairs = [("init_module", "initCheckSite"), ("cleanup_module", "exitCheckSite")]
    if context.is_l3:
        pairs += [("maplesu_l3_pre", "preHandler"), ("maplesu_avc_pre", "preHandler")]
        if elf.symbol("maplesu_status_read_pre"):
            pairs.append(("maplesu_status_read_pre", "preHandler"))
        for name in ("maplesu_policy_control_pre", "msu_policy_pre", "msu_boot_sdk_pre", "msu_boot_sdk_allocator_pre"):
            if elf.symbol(name):
                pairs.append((name, "preHandler"))
    checks = []
    for name, label in pairs:
        type_id = int(context.image_facts[label]["typeId"], 16)
        address = executor.address(name)
        body = elf.symbol(name + ".cfi")
        if body is None or elf.symbol_section(body)["name"].startswith(".init") and label != "initCheckSite":
            raise b.GateFailure("resident CFI implementation missing: " + name)
        wrong_types = {0, type_id ^ 1} | {int(context.image_facts[k]["typeId"], 16)
                       for k in ("initCheckSite", "exitCheckSite", "preHandler", "postHandler")
                       if k != label}
        checks.append({"symbol": name, "typeId": hex(type_id),
                       "acceptsCorrectType": executor.accepts(type_id, address),
                       "rejectsWrongType": all(not executor.accepts(t, address) for t in wrong_types),
                       "rejectsWrongAddress": all(not executor.accepts(type_id, a) for a in
                                                  (address - 1, address + 1, address + 2,
                                                   executor.address(name + ".cfi"))),
                       "bodySection": elf.symbol_section(body)["name"]})
    return checks, executor.commands


def gate_cfi(b, ctx, gate):
    for flag in CLANG_FLAGS:
        gate.require(flag in ctx.cflags, "legacy CFI flag: " + flag)
    gate.require("-fsanitize=kcfi" not in ctx.cflags, "legacy CFI does not use KCFI prefixes")
    for row in ctx.cfi_checks:
        for key in ("acceptsCorrectType", "rejectsWrongType", "rejectsWrongAddress"):
            gate.require(row[key], row["symbol"] + ": " + key)
    gate.extras["cfiChecks"] = ctx.cfi_checks
    # Only the compiler's fail routine may contain its expected trap.
    fail = ctx.elf.symbol("__cfi_check_fail")
    traps = 0
    for section in ctx.elf.sections:
        if not section["flags"] & b.SHF_EXECINSTR:
            continue
        for at in range(0, section["size"] - 3, 4):
            imm = b.decode_brk(b.read_uint32(ctx.elf.section_bytes(section), at))
            if imm is not None:
                traps += 1
                gate.require(imm == 0x5502 and fail["shndx"] == section["index"] and
                             fail["value"] <= at < fail["value"] + fail["size"],
                             "trap is confined to compiler CFI failure handler")
    gate.require(traps == 1, "one compiler-generated CFI failure trap")
    if ctx.is_l3:
        for name in ("maplesu_l3_pre", "maplesu_avc_pre"):
            gate.require(not b.nocfi_covers(ctx.source, name), name + " retains CFI")


def run(args, b):
    log = b.Log(echo=not args.quiet, verbose=args.verbose)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    contract_path = b.resolve_contract(args.contract)
    try:
        if args.module == b.L2_MODULE or args.evidence or args.gate_engine == "loader-contract":
            raise b.BuildError("legacy CFI supports root/L3 with measured legacy gates only")
        contract = b.load_contract(contract_path)
        image_path = Path(args.image) if args.image else b.PROJECT_ROOT / contract["imagePath"]
        if b.sha256_file(image_path) != contract["imageSha256"]:
            raise b.GateFailure("legacy image SHA256 disagrees with measured contract")
        facts = image_facts(b, contract, image_path)
        image = image_path.read_bytes()
        symbols = b.SymbolTable(b.PROJECT_ROOT / contract["symbolsPath"])
        layouts = (legacy_510.image_layouts(b, contract, image, symbols)
                   if contract.get("abiEvidence") else None)
        l3 = l3_facts(b, contract, image, symbols, facts, layouts) if args.module == b.L3_MODULE else None
        log("%s: measured legacy Clang CFI (%s)" % (args.module, contract["kernelRelease"]))
        for key in contract["cfi"]["sites"]:
            log("  %s: %s at %s" % (key, facts[key]["typeId"], facts[key]["callAddress"]))
        module = out / (args.module + ".ko")
        ld = b.find_tool(Path(args.ndk_dir), "ld.lld")
        if args.verify_only:
            report = json.loads((out / "build.json").read_text(encoding="utf-8"))
            flags = report["cflags"]
            header = Path(report["header"])
            commands = report["commands"]
        else:
            built = b.build(Path(args.ndk_dir), out / "staging", contract, log,
                            args.extra_flag, module=args.module, l3_facts=l3)
            module, flags = built["module"], built["cflags"]
            header, commands = Path(built["header"]), built["commands"]
        context = b.VerifyContext(module, contract, contract_path, image_path, log,
                                  cflags=flags, helper_path=args.helper_path, module_key=args.module,
                                  header_path=header, image_facts=facts, l3_image_facts=l3,
                                  image_layouts=layouts,
                                  l3_callbacks=l3["referenceKcfi"] if l3 else None)
        context.legacy_cfi = True
        context.cfi_checks, check_commands = cfi_checks(b, context, ld, out)
        gates = []
        for key, name in context.gates:
            name = {"G6": "legacy Clang CFI", "L3-1": "64-bit callback CFI",
                    "L3-5": "CFI failure trap only"}.get(key, name)
            gate = b.Gate(key, name)
            try:
                if key in ("G6", "L3-1", "L3-5"):
                    gate_cfi(b, context, gate)
                elif key == "L3-4":
                    for row in context.cfi_checks:
                        if row["symbol"] != "init_module":
                            gate.require(row["bodySection"] == ".text",
                                         row["symbol"] + " implementation is resident")
                elif key == "G7" and layouts:
                    gate.name = "struct shim vs measured instructions/reference"
                    legacy_510.gate_struct_shim(b, context, gate)
                else:
                    b.GATE_FUNCTIONS[key](context, gate)
            except b._CheckFailed:
                pass
            gates.append(gate.result())
            log(b.gate_line(gates[-1]))
        ok = all(gate["ok"] for gate in gates)
        if not ok:
            raise b.GateFailure("legacy gates failed: " + ", ".join(g["id"] for g in gates if not g["ok"]))
        published = out / (args.module + ".ko")
        if not args.verify_only:
            shutil.copyfile(module, published)
        extras = {g["id"]: g["extras"] for g in gates}
        report = {"module": args.module, "modulePath": b.rel(published),
                  "sha256": b.sha256_file(published), "bytes": published.stat().st_size,
                  "kernelRelease": contract["kernelRelease"], "header": str(header),
                  "contract": {"path": b.rel(contract_path), "sha256": b.sha256_file(contract_path)},
                  "image": {"path": b.rel(image_path), "sha256": b.sha256_file(image_path)},
                  "commands": commands, "verificationCommands": check_commands,
                  "cflags": flags, "compileFlags": flags, "gates": gates,
                  "gateResult": {"ok": True, "engine": "legacy CFI + shared non-CFI gates"},
                  "facts": {"cfi": facts, "cfiChecks": context.cfi_checks,
                            "modulePolicyBridge": (l3 or {}).get("policyBridge", {}),
                            "instructionAbi": layouts,
                            "imports": context.elf.imports(),
                            "helperPath": extras.get("G5", {}).get("helperPath"),
                            "handoverMode": extras.get("G5", {}).get("handoverMode"),
                            "rootSubject": (l3 or {}).get("rootSubject")},
                  "sources": {str(p): b.sha256_file(p) for p in
                              (Path(__file__), b.HERE / "build_root_module.py", context.source_path,
                               b.MODULE_DIR / "kernel_compat.h", b.MODULE_DIR / "maplesu_selinux_hide.h",
                               b.HERE / "selinux_hide_abi.h", Path(legacy_510.__file__),
                               *(b.HERE / name for name in b.policy_build.SOURCES))},
                  "verifiedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        (out / "build.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        log("RESULT: all legacy CFI and shared gates pass")
        return 0
    except (b.BuildError, b.GateFailure, OSError, ValueError) as error:
        log("ERROR: %s" % error)
        log("RESULT: FAILED")
        return 1
    finally:
        log.save(Path(args.transcript) if args.transcript else out / "verify-build.txt")
