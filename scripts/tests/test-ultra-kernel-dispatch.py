"""Replay the production Ultra execve dispatcher; never access a device or live credential."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile

from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
from unicorn import arm64_const as R
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--require-block-isolation", action="store_true")
parser.add_argument("--kernel", type=Path, help="Read-only decoded boot kernel for generated-body comparison")
parser.add_argument("--require-boot-execution-guards", action="store_true")
args = parser.parse_args()
if args.require_boot_execution_guards and not args.kernel:
    parser.error("--require-boot-execution-guards needs --kernel")
args.output.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.gettempdir()) / "MapleSU-ultra-module-policy-20261107/execve-dispatch"
work.mkdir(parents=True, exist_ok=True)
directory = ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel"
sources = [directory / (s + ".kt") for s in
           ("UltraKernelA64", "UltraKernelShellcode", "UltraKernelKallsyms", "UltraKernelGenerateException",
            "UltraKernelBtf", "UltraKernelMetadataRebase", "UltraKernelRequestV2")]
hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
harness = work / "EmitDispatch.kt"
harness.write_text('''package dev.maplesu.manager.ultrakernel
private val syms = linkedMapOf(
    "die" to 0x100000, "arm64_notify_die" to 0x110000, "do_execveat_common" to 0x120000,
    "__drm_puts_coredump" to 0x130000, "__drm_printfn_coredump" to 0x140000,
    "drm_dev_printk" to 0x150000, "__dev_printk" to 0x160000, "module_alloc" to 0x170000,
    "module_memfree" to 0x171000, "set_memory_ro" to 0x172000, "set_memory_x" to 0x173000,
    "set_memory_nx" to 0x174000, "set_memory_rw" to 0x175000, "panic" to 0x180000)
private object Symbols : UltraKernelSymbols {
    override val imageSize = 0x200000
    override val summary = "Synthetic offsets only; actual production body generator"
    override fun offsetOf(name: String) = syms[name]
    override fun isSymbolStart(value: Int) = value in syms.values
    override fun nextOffset(offset: Int) = syms.values.filter { it > offset }.minOrNull()
}
fun main(args: Array<String>) {
    val resolver = UltraKernelSymbolResolver(Symbols)
    for (dynamic in listOf(false, true)) for (cred in listOf(0x780, 0x820))
        for ((suid, euid) in listOf(12 to 20, 16 to 24)) {
        val fields = UltraKernelFields(cred, comm = 0x980, credSuid = suid, credEuid = euid,
            execvePrologue = if (dynamic) 0xd10083ff.toInt() else null)
        val roles = linkedMapOf("execve-gate" to syms.getValue("die"),
            "execve-tail" to syms.getValue("die") + UltraKernelBodies.EXECVE_GATE_BYTES,
            "execve-frame" to syms.getValue("arm64_notify_die"),
            "dev-printk" to syms.getValue("__dev_printk"),
            "printfn-bracket" to syms.getValue("__drm_printfn_coredump"),
            "printk-flush" to syms.getValue("drm_dev_printk"))
        for ((role, at) in roles) {
            val body = UltraKernelBodies.generate(role, at, resolver, fields)
            println("$dynamic $cred $suid $euid $role $at " + body.bytes.joinToString("") { "%02x".format(it.toInt() and 255) })
        }
    }
    if (args.isNotEmpty()) {
        val image = java.io.File(args.single()).readBytes()
        val table = UltraKernelKallsymsTable.decode(image)
        val cred = UltraKernelStructOffsets.resolve(table, image, setOf(UltraKernelStructOffsets.CRED), emptyMap())
            .getValue(UltraKernelStructOffsets.CRED)
        val members = UltraKernelStructOffsets.credentialLayout(table, image, cred)
        val fields = UltraKernelFields(cred, credSuid = members.suid, credEuid = members.euid)
        val resolver = UltraKernelSymbolResolver(table)
        println("BOOTFIELD $cred ${members.suid} ${members.euid}")
        for (name in syms.keys) println("BOOTSYMBOL $name ${resolver.require(name)}")
        for ((role, symbol) in linkedMapOf("execve-gate" to "die",
            "printfn-bracket" to "__drm_printfn_coredump", "printk-flush" to "drm_dev_printk")) {
            val at = resolver.require(symbol)
            val expected = UltraKernelBodies.generate(role, at, resolver, fields).bytes
            val actual = image.copyOfRange(at, at + expected.size)
            fun digest(bytes: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            println("BOOT $role $at ${expected.size} ${expected.contentEquals(actual)} ${digest(expected)} ${digest(actual)}")
        }
    }
}
''', encoding="utf-8")
stdlib = cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20")
annotations = cached_jar("org.jetbrains", "annotations", "13.0")
coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
java = str(native_toolchain.jdk_tool("java"))
jar = work / "dispatch.jar"
fingerprint = hashlib.sha256((json.dumps(hashes, sort_keys=True) + harness.read_text() + "jvm-target=17").encode()).hexdigest()
stamp = work / "compiled.sha256"
if not jar.is_file() or not stamp.is_file() or stamp.read_text() != fingerprint:
    result = subprocess.run([java, "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler, stdlib, annotations, coroutines])),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
        "-classpath", os.pathsep.join(map(str, [stdlib, annotations])), "-d", str(jar),
        *map(str, sources), str(harness)], capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    stamp.write_text(fingerprint)
emitted = subprocess.run([java, "-cp", os.pathsep.join(map(str, [jar, stdlib])),
    "dev.maplesu.manager.ultrakernel.EmitDispatchKt", *([str(args.kernel)] if args.kernel else [])],
    capture_output=True, text=True, timeout=30)
if emitted.returncode:
    raise RuntimeError(emitted.stdout + emitted.stderr)
emission = emitted.stdout
bodies = {}
boot_comparison = []
boot_symbols = {}
boot_fields = None
for line in emission.splitlines():
    if line.startswith("BOOTSYMBOL "):
        _, name, at = line.split()
        boot_symbols[name] = int(at)
        continue
    if line.startswith("BOOTFIELD "):
        boot_fields = [int(x) for x in line.split()[1:]]
        continue
    if line.startswith("BOOT "):
        _, role, at, size, matches, expected, actual = line.split()
        boot_comparison.append(dict(role=role, offset=int(at), bytes=int(size),
            matchesCurrentGenerator=matches == "true", generatedSha256=expected, bootSha256=actual))
        continue
    dynamic, cred, suid, euid, role, at, raw = line.split()
    bodies.setdefault((dynamic == "true", int(cred), int(suid), int(euid)), {})[role] = (int(at), bytes.fromhex(raw))
MASK = (1 << 64) - 1
SITES = dict(zip(("module_alloc", "module_memfree", "set_memory_ro", "set_memory_x",
    "set_memory_nx", "set_memory_rw"), (0x170000, 0x171000, 0x172000, 0x173000, 0x174000, 0x175000)))


def replay(dynamic, cred_offset, command, failure=None, valid=True, base=0, seed=0, boot=None,
           filename_length=None, ordinary_name=None, nul_offset=None, layout=(16, 24)):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    if boot:
        u.mem_map(base, (len(boot) + 4095) & ~4095)
        u.mem_write(base, boot)
        assert boot_fields == [cred_offset, *layout], "Reviewed boot reply/task ABI changed"
    else:
        u.mem_map(base + 0x100000, 0x100000)
    u.mem_map(0x4000000, 0x100000)
    if not boot:
        for at, raw in bodies[(dynamic, cred_offset, *layout)].values():
            u.mem_write(base + at, raw)
    task, cred, filename, request, target, buffer = [0x4000000 + i * 0x10000 for i in range(6)]
    stack = 0x40f0000
    key = b"0123456789abcdef" * 3
    u.mem_write(base + (boot_symbols["panic"] if boot else 0x180000), key)
    # Encode the same 18-byte transport used by the reviewed native SDK object.
    plain = struct.pack("<BBQII", command, 0x5a, buffer if command in (48, 51, 53) else target, 4096, 1)
    masks = bytes(2 if b == 1 else 1 for b in plain)
    encoded = bytes(255 if b in (0, 1) else b - 1 for b in plain)
    name = (key if valid else b"X" + key[1:]) + masks + encoded
    rejected_name = filename_length is not None or ordinary_name is not None or nul_offset is not None
    if filename_length is not None:
        name = (name + b"x")[:filename_length]
    if ordinary_name is not None:
        name = ordinary_name
    if nul_offset is not None:
        name = name[:nul_offset] + b"\0" + name[nul_offset+1:]
    text = name + b"\0"
    terminated_length = text.index(0) + 1
    u.mem_write(request, b"\x7f" * 4096)
    u.mem_write(request, text)
    u.mem_write(filename, struct.pack("<Q", request))
    u.mem_write(task + cred_offset, struct.pack("<Q", cred))
    u.mem_write(cred + layout[0], struct.pack("<Q", 0x777788889999aaaa))
    u.mem_write(cred + layout[1], struct.pack("<I", 0 if valid and not rejected_name else 10001))
    u.mem_write(target, b"\x33")
    # Submitted code writes the SDK reply slot and returns. No policy is modified.
    u.mem_write(buffer, struct.pack("<III", 0xd2824680, 0xf9000220, 0xd65f03c0))  # mov x0,#0x1234; str x0,[x17]; ret
    randomizer = random.Random(seed)
    initial = [randomizer.getrandbits(64) for _ in range(31)]
    initial[1] = filename
    for i, value in enumerate(initial):
        u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), value)
    u.reg_write(R.UC_ARM64_REG_SP, stack)
    u.reg_write(R.UC_ARM64_REG_SP_EL0, task)
    events, executed, boundary_accesses = [], [], []
    original = base + (boot_symbols["do_execveat_common"] if boot else 0x120000) + (8 if dynamic else 4)
    imports = {base + (boot_symbols[name] if boot else at): name for name, at in SITES.items()}

    def x(i):
        return u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}"))

    def memory(uc, access, address, size, value, _):
        if request <= address < request + 4096 and address + size > request + terminated_length:
            boundary_accesses.append((address - request, size, access))
            uc.emu_stop()

    def hook(uc, pc, size, _):
        if pc == original:
            u.emu_stop()
            return
        word = int.from_bytes(u.mem_read(pc, 4), "little")
        if pc not in imports and word in (0xd503211f, 0xd503233f, 0xd503751f, 0xd50b7b20, 0xd508751f, 0xd508711f):
            # PAC/cache effects need separate hardware acceptance.
            u.reg_write(R.UC_ARM64_REG_PC, pc + 4)
            return
        if pc == buffer:
            assert x(11) == request and x(17) == cred + layout[0]
            assert u.reg_read(R.UC_ARM64_REG_SP) % 16 == 0
            executed.append(True)
        name = imports.get(pc)
        if not name:
            return
        events.append((name, x(0), x(1)))
        link = x(30)
        value = buffer if name == "module_alloc" else (-12 if name == failure else 0)
        for i in range(18):
            u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), 0xbad000 + i)
        u.reg_write(R.UC_ARM64_REG_X0, value & MASK)
        u.reg_write(R.UC_ARM64_REG_PC, link)

    hooks = [u.hook_add(UC_HOOK_CODE, hook),
             u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory)]
    try:
        u.emu_start(base + (boot_symbols["arm64_notify_die"] if boot else 0x110000) +
            (28 if dynamic else 24), original + 4, count=20000)
    except UcError as error:
        raise AssertionError(("dispatcher replay", bool(boot), command, failure,
            hex(u.reg_read(R.UC_ARM64_REG_PC)), hex(u.reg_read(R.UC_ARM64_REG_SP)),
            [e[0] for e in events])) from error
    assert not boundary_accesses, ("filename boundary", filename_length, ordinary_name, boundary_accesses)
    assert u.reg_read(R.UC_ARM64_REG_PC) == original
    assert [x(i) for i in list(range(8)) + list(range(19, 31))] == [
        initial[i] for i in list(range(8)) + list(range(19, 31))]
    assert u.reg_read(R.UC_ARM64_REG_SP) == stack - (32 if dynamic else 0)
    reply = int.from_bytes(u.mem_read(cred + layout[0], 8), "little")
    names = [e[0] for e in events]
    wrote = bytes(u.mem_read(target, 1)) == b"\x5a"
    for handle in hooks:
        u.hook_del(handle)
    if not valid or rejected_name:
        assert not events and not executed and not wrote and reply == 0x777788889999aaaa
        assert bytes(u.mem_read(request, len(text))) == text
    elif command == 49:
        assert wrote and not events
    elif command == 50:
        assert reply == 0x33 and not events
    elif command in (48, 52, 53):
        assert reply == (buffer if command == 48 else (target if command == 52 else 0))
        assert names == ({48: ["module_alloc"], 52: [], 53: ["module_memfree"]}[command])
    elif boot:
        # Replay the observed legacy bracket as a negative capability fixture.
        # Its permission errors are ignored, so code still runs in this case.
        assert names == ["set_memory_ro", "set_memory_x", "set_memory_rw", "module_memfree"]
        assert executed and reply == 0x1234
    else:
        expected = ["set_memory_ro"]
        if failure != "set_memory_ro":
            expected.append("set_memory_x")
        expected.append("set_memory_nx")
        if failure != "set_memory_nx":
            expected.append("set_memory_rw")
            if failure != "set_memory_rw":
                expected.append("module_memfree")
        assert names == expected, (failure, names)
        assert bool(executed) == (failure not in ("set_memory_ro", "set_memory_x"))
        assert reply == (MASK - 19998 if failure else 0x1234)
    return dict(command=command, valid=valid, failure=failure, writeAccepted=wrote,
                executionAccepted=bool(executed), filenameLength=filename_length,
                nulOffset=nul_offset, credSuid=layout[0], credEuid=layout[1],
                ordinaryName=ordinary_name.decode() if ordinary_name is not None else None)


cases = []
for dynamic, cred, suid, euid in bodies:
    layout = (suid, euid)
    for base in (0, 0x20000000):
        for seed in range(3):
            for command in (48, 49, 50, 51, 52, 53):
                cases.append(replay(dynamic, cred, command, base=base, seed=seed, layout=layout))
            for failed in ("set_memory_ro", "set_memory_x", "set_memory_nx", "set_memory_rw"):
                cases.append(replay(dynamic, cred, 51, failure=failed, base=base, seed=seed, layout=layout))
            cases.append(replay(dynamic, cred, 51, valid=False, base=base, seed=seed, layout=layout))
        for length in (*range(84), 85):
            cases.append(replay(dynamic, cred, 52, base=base, filename_length=length, layout=layout))
        for offset in range(84):
            cases.append(replay(dynamic, cred, 52, base=base, nul_offset=offset, layout=layout))
        for name in (b"", b"/system/bin/sh", b"/system/bin/ip", b"/system/bin/app_process64"):
            cases.append(replay(dynamic, cred, 52, base=base, ordinary_name=name, layout=layout))
environment = replay(False, 0x820, 49)
module = replay(False, 0x820, 49)
boot_replays = []
if args.kernel:
    image = args.kernel.read_bytes()
    for failed in (None, "set_memory_ro", "set_memory_x", "set_memory_rw"):
        boot_replays.append(replay(False, boot_fields[0], 51, failure=failed, boot=image,
                                   layout=tuple(boot_fields[1:])))
unchanged = all(hashlib.sha256(p.read_bytes()).hexdigest() == hashes[p.relative_to(ROOT).as_posix()] for p in sources)
assert unchanged
isolation = not module["writeAccepted"] and environment["writeAccepted"]
boot_guarded = all(not row["executionAccepted"] for row in boot_replays
    if row["failure"] in ("set_memory_ro", "set_memory_x")) if boot_replays else None
blocked = (args.require_block_isolation and not isolation) or (
    args.require_boot_execution_guards and not boot_guarded)
report = dict(recordedAt=datetime.now(timezone.utc).isoformat(), sourceSha256=hashes,
    testScriptSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    sourceUnchanged=unchanged, emittedBodiesSha256=hashlib.sha256(emission.encode()).hexdigest(),
    cases=len(cases), abiPassed=True, moduleOriginIsolationPassed=isolation,
    bootComparison=boot_comparison,
    bootReplay=boot_replays,
    bootPermissionErrorsStopExecution=boot_guarded,
    originFixture="Identical shared-credential requests, caller labels differ only outside the production transport",
    environment=environment, module=module, deviceAccess=False, productionChanged=False,
    limits=["Synthetic offsets, cred/task layout and external permission/allocator functions",
            "Does not prove live dispatcher bytes, sleepability, PAC/BTI/cache hardware or real module enforcement"],
    status="REQUIRED_CAPABILITY_RED" if blocked else "DISPATCH_ABI_PASS_ORIGIN_OPEN")
(args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f'PASS {len(cases)} generated dispatcher cases; Block origin isolation={isolation}; '
      f'boot permission guards={boot_guarded}')
raise SystemExit(1 if blocked else 0)
