"""Execute the production request-v2 AArch64 emitter with captured nofault I/O."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools/specgen"))
import native_toolchain
from specgen.product import cached_jar

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--legacy-baseline", action="store_true")
parser.add_argument("--legacy-shellcode", type=Path, help="Frozen pre-change production source")
parser.add_argument("--real-kernel", type=Path)
parser.add_argument("--real-receipt", type=Path)
parser.add_argument("--real-spec", type=Path)
args = parser.parse_args()
if args.legacy_baseline and not args.legacy_shellcode:
    parser.error("--legacy-baseline needs --legacy-shellcode")
if any((args.real_kernel, args.real_receipt, args.real_spec)) and not all(
        (args.real_kernel, args.real_receipt, args.real_spec)):
    parser.error("real kernel, receipt and spec must be supplied together")
args.output.mkdir(parents=True, exist_ok=True)
directory = ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel"
names = ["UltraKernelA64", "UltraKernelShellcode", "UltraKernelKallsyms",
         "UltraKernelGenerateException", "UltraKernelBtf", "UltraKernelMetadataRebase"]
if not args.legacy_baseline:
    names.append("UltraKernelRequestV2")
sources = [directory / (name + ".kt") for name in names]
if args.legacy_baseline:
    sources[names.index("UltraKernelShellcode")] = args.legacy_shellcode.resolve()
tracked_sources = sources + ([] if args.legacy_baseline else [ROOT / "runtime/ultra/authorization/request_protocol.h"])
hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked_sources}
snapshot = args.output / "source"
snapshot.mkdir(exist_ok=True)
for source in tracked_sources:
    shutil.copyfile(source, snapshot / source.name)
shutil.copyfile(Path(__file__), snapshot / Path(__file__).name)
frozen_sources = [snapshot / source.name for source in sources]
harness = args.output / "EmitRequest.kt"
harness.write_text('''package dev.maplesu.manager.ultrakernel
private val syms = linkedMapOf(
    "die" to 0x100000, "arm64_notify_die" to 0x110000, "do_execveat_common" to 0x120000,
    "__drm_printfn_coredump" to 0x140000, "drm_dev_printk" to 0x150000,
    "__dev_printk" to 0x160000, "module_alloc" to 0x170000, "module_memfree" to 0x171000,
    "copy_from_user_nofault" to 0x176000, "copy_to_user_nofault" to 0x177000,
    "copy_from_kernel_nofault.isra.0" to 0x174000,
    "free_initmem" to 0x178000, "panic" to 0x180000)
private object Symbols : UltraKernelSymbols {
    override val imageSize = 0x200000
    override val summary = "Synthetic symbols; actual production emitter"
    override fun offsetOf(name: String) = syms[name]
    override fun isSymbolStart(value: Int) = value in syms.values
    override fun nextOffset(offset: Int) = syms.values.filter { it > offset }.minOrNull()
}
fun main(args: Array<String>) {
    if (args.isNotEmpty()) {
        val table = UltraKernelKallsymsTable.decode(java.io.File(args.single()).readBytes())
        for (name in listOf("copy_from_user_nofault", "copy_to_user_nofault", "do_execveat_common"))
            println("TARGETSYMBOL $name ${requireNotNull(table.offsetOf(name))}")
        table.offsetOf("copy_from_kernel_nofault")?.let { println("TARGETSYMBOL copy_from_kernel_nofault $it") }
    }
    val resolver = UltraKernelSymbolResolver(Symbols)
    for (alignment in listOf(0, 4)) for (dynamic in listOf(false, true)) for (modern in MODERN_VALUES)
        for (kernelRead in KERNEL_READ_VALUES) {
        if (kernelRead) syms["copy_from_kernel_nofault"] = 0x175000
        else syms.remove("copy_from_kernel_nofault")
        syms["die"] = 0x100000 + alignment
        val fields = UltraKernelFields(cred = 0x780, credSuid = 16, credEuid = 24,
            execvePrologue = if (dynamic) 0xd10083ff.toInt() else null REQUEST_FIELD)
        val roles = linkedMapOf("execve-gate" to (0x100000 + alignment), "execve-frame" to 0x110000)
        REQUEST_ROLE
        for ((role, at) in roles) {
            val body = UltraKernelBodies.generate(role, at, resolver, fields)
            check(UltraKernelA64Verify.invalidWords(body.bytes, body.dataOffsets).isEmpty())
            println("$dynamic $modern $alignment $kernelRead $role $at " + body.bytes.joinToString("") { "%02x".format(it.toInt() and 255) })
        }
    }
}
'''.replace("MODERN_VALUES", "listOf(false)" if args.legacy_baseline else "listOf(false, true)")
    .replace("KERNEL_READ_VALUES", "listOf(false)" if args.legacy_baseline else "listOf(false, true)")
    .replace(" REQUEST_FIELD", "" if args.legacy_baseline else ", requestV2 = modern")
    .replace("REQUEST_ROLE", "" if args.legacy_baseline else
             'if (modern) roles["request-v2"] = syms.getValue("die") + UltraKernelRequestV2.CAVE_OFFSET'), encoding="utf-8")
stdlib = cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20")
annotations = cached_jar("org.jetbrains", "annotations", "13.0")
compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
java = str(native_toolchain.jdk_tool("java"))
jar = args.output / "request.jar"
compiled = subprocess.run([java, "-Xmx512m", "-Djava.io.tmpdir=" + str(args.output.resolve()), "-cp", os.pathsep.join(map(str,
    [compiler, stdlib, annotations, coroutines])), "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
    "-no-stdlib", "-no-reflect", "-jvm-target", "17", "-classpath",
    os.pathsep.join(map(str, [stdlib, annotations])), "-d", str(jar), *map(str, frozen_sources), str(harness)],
    capture_output=True, text=True, timeout=90)
if compiled.returncode:
    raise RuntimeError(compiled.stdout + compiled.stderr)
emitted = subprocess.run([java, "-Djava.io.tmpdir=" + str(args.output.resolve()), "-cp", os.pathsep.join(map(str, [jar, stdlib])),
    "dev.maplesu.manager.ultrakernel.EmitRequestKt", *([str(args.real_kernel)] if args.real_kernel else [])],
    capture_output=True, text=True, timeout=30)
if emitted.returncode:
    raise RuntimeError(emitted.stdout + emitted.stderr)
(args.output / "emitted.txt").write_text(emitted.stdout, encoding="utf-8")
bodies = {}
target_symbols = {}
for line in emitted.stdout.splitlines():
    if line.startswith("TARGETSYMBOL "):
        _, name, at = line.split()
        target_symbols[name] = int(at)
        continue
    dynamic, modern, alignment, kernel_read, role, at, raw = line.split()
    bodies.setdefault((dynamic == "true", modern == "true", int(alignment), kernel_read == "true"), {})[role] = (int(at), bytes.fromhex(raw))

MASK = (1 << 64) - 1
REQUEST_MAGIC, RESPONSE_MAGIC, METADATA_MAGIC = 0x3251534d, 0x3252534d, 0x324d534d
KEY = b"K" * 48
real = None
if args.real_kernel:
    target_receipt = json.loads(args.real_receipt.read_bytes())
    assert hashlib.sha256(args.real_kernel.read_bytes()).hexdigest() == target_receipt["baseKernelSha256"]
    target_records = {r["role"]: r for r in target_receipt["records"]}
    replacements = {}
    for line in args.real_spec.read_text().splitlines():
        if line and not line.startswith("#"):
            at, before, after = line.split("|")
            replacements[int(at)] = bytes.fromhex(after)
    actual_bodies = {}
    for role, record in {"execve-gate": "die+0x0", "execve-frame": "arm64_notify_die+0x0",
                         "request-v2": "request-v2"}.items():
        at = target_records[record]["offset"]
        actual_bodies[role] = (at, replacements[at])
    layout = target_receipt["layout"]["fields"]
    real = dict(bodies=actual_bodies, symbols=target_symbols,
        cred=layout["task_struct.cred"]["offsetBytes"], suid=layout["cred.suid"]["offsetBytes"],
        euid=layout["cred.euid"]["offsetBytes"],
        metadata=target_records["free_initmem+0x0"]["offset"] + 4,
        key=replacements[target_records["panic+0x0"]["offset"]][:48],
        panic=target_records["panic+0x0"]["offset"])


def packet(flag, sub, address, pointer):
    data = struct.pack("<BBQII", flag, sub, address, pointer & 0xffffffff, pointer >> 32)
    mask, encoded = bytearray(), bytearray()
    for value in data:
        choice = next(i for i in range(1, 256) if (value - i) & 255)
        mask.append(choice)
        encoded.append((value - choice) & 255)
    return KEY + mask + encoded + b"\0"


def replay(dynamic, modern, alignment, kernel_read=False, *, command=1, value=0,
           magic=REQUEST_MAGIC, version=2, length=48, reserved=0, sub=0xa2,
           ordinary=False, bad_key=False, from_error=False, from_partial=0, to_error=0,
           completion_error=False, mutation=False, request_pointer=None,
           response_pointer=None, slide=0, actual=False, read_length=256,
           read_reserved=0, kernel_pointer=None, destination_pointer=None,
           args_pointer=None, args_error=0, kernel_error=0, data_to_error=0,
           args_mutation=False):
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    selected = real["bodies"] if actual else bodies[(dynamic, modern, alignment, kernel_read)]
    imports = real["symbols"] if actual else dict(copy_from_user_nofault=0x176000,
        copy_to_user_nofault=0x177000, copy_from_kernel_nofault=0x175000,
        do_execveat_common=0x120000)
    if actual:
        # Frozen B0 324B fixtures retain the 112B stack/cap3 contract.
        kernel_read = len(selected["request-v2"][1]) > 324 and "copy_from_kernel_nofault" in imports
    stack_bytes = 112 if actual and len(selected["request-v2"][1]) == 324 else 384
    capabilities = 7 if kernel_read else 3
    cred_offset, suid, euid = (real["cred"], real["suid"], real["euid"]) if actual else (0x780, 16, 24)
    addresses = list(imports.values()) + [at + len(code) for at, code in selected.values()]
    panic = real["panic"] if actual else 0x180000
    u.mem_map(slide, (max(addresses + [panic + 48]) + 0xfff) & ~0xfff)
    u.mem_map(0x30000000, 0x40000)
    task, cred, filename, name = (0x30001000, 0x30002000, 0x30003000, 0x30004000)
    request, response, stack = 0x30005000, 0x30006000, 0x30030000
    descriptor, output = 0x30007000, 0x30008000
    kernel_source = 0xffff000001200000
    kernel_data = bytes((i * 73 + 19) & 255 for i in range(256))
    u.mem_map(kernel_source, 4096)
    u.mem_write(kernel_source, kernel_data)
    body_stack = stack - 80 - stack_bytes
    request_pointer = request if request_pointer is None else request_pointer
    response_pointer = response if response_pointer is None else response_pointer
    kernel_pointer = kernel_source if kernel_pointer is None else kernel_pointer
    destination_pointer = output if destination_pointer is None else destination_pointer
    args_pointer = descriptor if args_pointer is None else args_pointer
    saved_ids = 0x777788889999aaaa
    request_id = 0xfedcba9876543210
    raw = struct.pack("<IHHIIQQQQ", magic, version, length, command, reserved,
                      request_id, response_pointer, kernel_pointer if command == 3 else value,
                      args_pointer if command == 3 else 0)
    u.mem_write(request, raw)
    u.mem_write(response, bytes(48))
    u.mem_write(descriptor, struct.pack("<QII", destination_pointer, read_length, read_reserved))
    u.mem_write(output - 16, b"\xcc" * 288)
    text = packet(52, sub, saved_ids, request_pointer)
    if actual:
        text = real["key"] + text[48:]
    if ordinary:
        text = b"/system/bin/sh\0"
    if bad_key:
        text = b"X" + text[1:]
    u.mem_write(name, text)
    u.mem_write(filename, struct.pack("<Q", name))
    u.mem_write(task + cred_offset, struct.pack("<Q", cred))
    u.mem_write(cred, bytes([0x56]) * 128)
    u.mem_write(cred + suid, struct.pack("<Q", saved_ids))
    u.mem_write(cred + euid, struct.pack("<I", 10000))
    initial_cred = bytes(u.mem_read(cred, 128))
    for at, code in selected.values():
        u.mem_write(slide + at, code)
    u.mem_write(slide + panic, real["key"] if actual else KEY)
    initial = [0x1234567800000000 + i for i in range(31)]
    initial[1] = filename
    for i, item in enumerate(initial):
        u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), item)
    u.reg_write(R.UC_ARM64_REG_SP, stack)
    u.reg_write(R.UC_ARM64_REG_SP_EL0, task)
    calls, cred_writes, completion_events, snapshots = [], [], [], []
    target = slide + imports["do_execveat_common"] + (8 if dynamic else 4)
    if actual:
        branch_at = selected["execve-frame"][0] + (24 if dynamic else 20)
        word = int.from_bytes(selected["execve-frame"][1][24 if dynamic else 20:28 if dynamic else 24], "little")
        immediate = word & 0x3ffffff
        target = slide + branch_at + (immediate - (0x4000000 if immediate & 0x2000000 else 0)) * 4
    prologue = int.from_bytes(selected["execve-frame"][1][20:24], "little") if dynamic else None
    stack_delta = (prologue >> 10) & 0xfff if dynamic and prologue & 0xffc003ff == 0xd10003ff else 0
    if dynamic and prologue & 0xffc07fff == 0xa9807bfd:
        immediate = (prologue >> 15) & 0x7f
        stack_delta = -(immediate - 128 if immediate & 64 else immediate) * 8

    def x(i):
        return u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}"))

    def writes(uc, access, address, size, content, _):
        if cred <= address < cred + 128:
            cred_writes.append((address - cred, size))

    def execute(uc, pc, size, _):
        if pc == target:
            uc.emu_stop()
            return
        nofault = {slide + imports["copy_from_user_nofault"]: "from",
                   slide + imports["copy_to_user_nofault"]: "to"}
        if "copy_from_kernel_nofault" in imports:
            nofault[slide + imports["copy_from_kernel_nofault"]] = "kernel"
        if pc not in nofault:
            return
        assert u.reg_read(R.UC_ARM64_REG_SP) % 16 == 0
        link, destination, source, count = x(30), x(0), x(1), x(2)
        direction = nofault[pc]
        calls.append((direction, count))
        outcome = 0
        if direction == "from":
            assert body_stack <= destination and destination + count <= body_stack + stack_bytes
            if source == request and count == 48:
                if from_error or from_partial:
                    if from_partial: u.mem_write(destination, bytes(u.mem_read(source, min(count, from_partial))))
                    outcome = -14
                else:
                    snapshot = bytes(u.mem_read(source, count)); snapshots.append(snapshot.hex())
                    u.mem_write(destination, snapshot)
                    if mutation: u.mem_write(request, bytes([0xee]) * 48)
            elif source == descriptor and count == 16:
                if args_error:
                    if args_error > 0: u.mem_write(destination, bytes(u.mem_read(source, min(count, args_error))))
                    outcome = -14
                else:
                    snapshot = bytes(u.mem_read(source, count)); snapshots.append(snapshot.hex())
                    u.mem_write(destination, snapshot)
                    if args_mutation: u.mem_write(descriptor, bytes([0xee]) * 16)
            else:
                outcome = -14
        elif direction == "kernel":
            assert count == read_length and destination == body_stack + 128
            if source != kernel_source or kernel_error:
                if kernel_error > 0 and source == kernel_source:
                    u.mem_write(destination, kernel_data[:min(count, kernel_error)])
                outcome = -14
            else:
                u.mem_write(destination, kernel_data[:count])
        else:
            assert body_stack <= source and source + count <= body_stack + stack_bytes
            if source == body_stack + 128:
                assert count == read_length
                if destination != output or data_to_error:
                    if destination == output and data_to_error > 0:
                        u.mem_write(destination, bytes(u.mem_read(source, min(count, data_to_error))))
                    outcome = -14
                else:
                    u.mem_write(destination, bytes(u.mem_read(source, count)))
            elif destination != response:
                outcome = -14
            else:
                completion_events.append(bytes(u.mem_read(response, 48)))
                if count == 48 and to_error:
                    if to_error > 0: u.mem_write(destination, bytes(u.mem_read(source, to_error)))
                    outcome = -14
                elif count == 4 and completion_error: outcome = -14
                else: u.mem_write(destination, bytes(u.mem_read(source, count)))
        for i in range(18):
            u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), 0xbad00000 + i)
        u.reg_write(R.UC_ARM64_REG_X0, outcome & MASK)
        u.reg_write(R.UC_ARM64_REG_PC, link)

    u.hook_add(UC_HOOK_CODE, execute)
    u.hook_add(UC_HOOK_MEM_WRITE, writes)
    u.emu_start(slide + selected["execve-frame"][0] + (28 if dynamic else 24), target + 4, count=20000)
    assert u.reg_read(R.UC_ARM64_REG_PC) == target
    assert u.reg_read(R.UC_ARM64_REG_SP) == stack - stack_delta
    preserved = list(range(8)) + list(range(18, 31))
    assert [x(i) for i in preserved] == [initial[i] for i in preserved]
    received = bytes(u.mem_read(response, 48))
    is_v2 = modern and sub == 0xa2 and not ordinary and not bad_key
    expected_calls, expected_status, copied = [], None, 0
    if not is_v2:
        assert not calls and not any(received)
        assert bytes(u.mem_read(cred, 128)) == initial_cred
        assert cred_writes == ([] if ordinary or bad_key else [(suid, 8)])
    else:
        assert not cred_writes and bytes(u.mem_read(cred, 128)) == initial_cred
        if from_error or from_partial or request_pointer != request:
            assert calls == [("from", 48)] and not any(received)
        else:
            expected_status = (-22 if (magic, version, length, reserved) !=
                (REQUEST_MAGIC, 2, 48, 0) else (-95 if command not in (1, 2) and not (command == 3 and kernel_read) else 0))
            expected_calls = [("from", 48)]
            if command == 3 and expected_status == 0:
                expected_calls.append(("from", 16))
                if args_error or args_pointer != descriptor: expected_status = -14
                elif read_reserved or not 1 <= read_length <= 256 or kernel_pointer < 0xffff000000000000 or kernel_pointer + read_length - 1 > MASK or not destination_pointer or destination_pointer + read_length - 1 > MASK:
                    expected_status = -22
                else:
                    expected_calls.append(("kernel", read_length))
                    if kernel_error or kernel_pointer != kernel_source: expected_status = -14
                    else:
                        expected_calls.append(("to", read_length))
                        if data_to_error or destination_pointer != output:
                            expected_status = -14
                            if destination_pointer == output and data_to_error > 0: copied = min(read_length, data_to_error)
                        else: copied = read_length
            expected_calls.append(("to", 48))
            if to_error or response_pointer != response:
                assert int.from_bytes(received[:4], "little") == 0
            else:
                expected_calls.append(("to", 4))
                fields = struct.unpack("<IHHIiQQQII", received)
                assert fields[:6] == (0 if completion_error else RESPONSE_MAGIC, 2, 48, command, expected_status, request_id), fields
                expected_result = capabilities if command == 1 else (read_length if command == 3 else value)
                assert fields[6] == (0 if expected_status else expected_result)
                assert completion_events[0] == bytes(48)
                assert int.from_bytes(completion_events[1][:4], "little") == 0
                if not expected_status and command == 1:
                    pointer = fields[7]
                    assert fields[8:] == (48, 2)
                    metadata = struct.unpack("<IHHQqqqII", u.mem_read(pointer, 48))
                    assert metadata[:4] == (METADATA_MAGIC, 2, 48, capabilities)
                    assert pointer + metadata[4] == slide
                    assert pointer + metadata[5] == slide + (real["metadata"] if actual else 0x178004)
                    assert metadata[6:] == (0, 0, 0)
                else: assert fields[7:] == (0, 0, 0)
            assert calls == expected_calls, (calls, expected_calls)
    assert bytes(u.mem_read(output - 16, 16)) == b"\xcc" * 16
    assert bytes(u.mem_read(output, 256)) == kernel_data[:copied] + b"\xcc" * (256 - copied)
    assert bytes(u.mem_read(output + 256, 16)) == b"\xcc" * 16
    return dict(dynamic=dynamic, modern=modern, alignment=alignment, kernelRead=kernel_read,
        capabilities=capabilities, stackBytes=stack_bytes, actualTarget=actual, command=command, value=value, sub=sub,
        ordinary=ordinary, badKey=bad_key, fromError=from_error, toError=to_error,
        completionError=completion_error, mutation=mutation, argsMutation=args_mutation, slide=slide,
        readLength=read_length, readReserved=read_reserved, kernelPointer=kernel_pointer,
        destinationPointer=destination_pointer, argsPointer=args_pointer, argsError=args_error,
        kernelError=kernel_error, dataToError=data_to_error, requestPartial=from_partial,
        calls=calls, credentialWrites=cred_writes, completed=received[:4].hex(),
        response=received.hex(), copiedBytes=copied, expectedStatus=expected_status,
        snapshots=snapshots, abiPreserved=True, outputGuardsPreserved=True)


cases = []
def read_cases(dynamic, modern, alignment, kernel_read, slide, actual=False):
    found = []
    for size in (0, 1, 255, 256, 257):
        found.append(replay(dynamic, modern, alignment, kernel_read, command=3, read_length=size,
                            slide=slide, actual=actual))
    options = (
        dict(read_reserved=1), dict(kernel_pointer=0),
        dict(kernel_pointer=0xfffeffffffffffff), dict(kernel_pointer=MASK, read_length=2),
        dict(kernel_pointer=0xffff000000000000, read_length=1),
        dict(destination_pointer=0), dict(destination_pointer=MASK, read_length=2),
        dict(destination_pointer=1), dict(args_pointer=0),
        dict(from_error=True), dict(from_partial=17),
        dict(args_error=-1), dict(args_error=8), dict(kernel_error=-1), dict(kernel_error=17),
        dict(data_to_error=-1), dict(data_to_error=17),
        dict(to_error=-1), dict(to_error=17), dict(completion_error=True),
        dict(mutation=True), dict(args_mutation=True), dict(mutation=True, args_mutation=True),
        dict(reserved=1), dict(sub=0),
    )
    for values in options:
        found.append(replay(dynamic, modern, alignment, kernel_read, command=3, slide=slide,
                            actual=actual, **values))
    return found


for dynamic, modern, alignment, kernel_read in bodies:
    for slide in (0, 0x20000000):
        cases.append(replay(dynamic, modern, alignment, kernel_read, slide=slide))
        if args.legacy_baseline:
            continue
        for value in (0, MASK, 1 << 63, (-19999) & MASK, 0x12345678fedcba98):
            cases.append(replay(dynamic, modern, alignment, kernel_read, command=2, value=value, slide=slide))
        for options in (dict(magic=0), dict(version=1), dict(length=47), dict(reserved=1),
            dict(command=99), dict(sub=0), dict(ordinary=True), dict(bad_key=True),
            dict(from_error=True), dict(to_error=-1), dict(to_error=17),
            dict(completion_error=True), dict(mutation=True), dict(request_pointer=0),
            dict(request_pointer=0x30033ff0), dict(response_pointer=0)):
            cases.append(replay(dynamic, modern, alignment, kernel_read, slide=slide, **options))
        cases.extend(read_cases(dynamic, modern, alignment, kernel_read, slide))
if real:
    for slide in (0, 0x20000000):
        for command in (1, 2):
            cases.append(replay(True, True, 0, actual=True, command=command,
                value=0xfedcba9876543210, slide=slide))
        for options in (dict(magic=0), dict(command=99), dict(sub=0), dict(ordinary=True),
            dict(from_error=True), dict(to_error=17), dict(mutation=True), dict(completion_error=True)):
            cases.append(replay(True, True, 0, actual=True, slide=slide, **options))
        cases.extend(read_cases(True, True, 0, False, slide, actual=True))
if not args.legacy_baseline:
    # Exactly one existing gate instruction changes; other legacy command branches remain identical.
    for alignment in (0, 4):
        for dynamic, kernel_read in ((dynamic, kernel_read) for dynamic in (False, True) for kernel_read in (False, True)):
            old = bodies[(dynamic, False, alignment, kernel_read)]["execve-gate"][1]
            new = bodies[(dynamic, True, alignment, kernel_read)]["execve-gate"][1]
            assert len(old) == len(new) == 272
            changed = [at for at in range(0, 272, 4) if old[at:at+4] != new[at:at+4]]
            assert len(changed) == 1, changed
    # The shared C/C++ header is the wire contract, independently checked against execution constants.
    header = (snapshot / "request_protocol.h").read_text()
    for token in ("MAPLESU_REQUEST_SELECTOR_FLAG 52u", "MAPLESU_REQUEST_SELECTOR_SUB 0xa2u",
        "MAPLESU_REQUEST_PROTOCOL_VERSION 2u", "MAPLESU_REQUEST_WIRE_BYTES 48u",
        "MAPLESU_RESPONSE_WIRE_BYTES 48u", "MAPLESU_METADATA_WIRE_BYTES 48u",
        "MAPLESU_REQUEST_MAGIC UINT32_C(0x3251534d)", "MAPLESU_RESPONSE_MAGIC UINT32_C(0x3252534d)",
        "MAPLESU_METADATA_MAGIC UINT32_C(0x324d534d)", "MAPLESU_REQUEST_QUERY 1u", "MAPLESU_REQUEST_ECHO64 2u",
        "MAPLESU_REQUEST_READ 3u", "MAPLESU_CAP_READ UINT64_C(4)", "MAPLESU_READ_MAX_BYTES 256u",
        "MAPLESU_REQUEST_STATUS_FAULT (-14)", "sizeof(maplesu_read_v2) == 16",
        "MAPLESU_WIRE_OFFSET(maplesu_read_v2, destination_user, 0)",
        "MAPLESU_WIRE_OFFSET(maplesu_read_v2, length, 8)",
        "MAPLESU_WIRE_OFFSET(maplesu_read_v2, reserved, 12)"):
        assert token in header, token
assert all(hashlib.sha256(p.read_bytes()).hexdigest() == hashes[p.relative_to(ROOT).as_posix()] for p in tracked_sources)
report = dict(recordedAt=datetime.now(timezone.utc).isoformat(), sourceSha256=hashes,
    cases=cases, count=len(cases), deviceAccess=False,
    readCases=sum(case["command"] == 3 for case in cases),
    actualReadCases=sum(case["command"] == 3 and case["actualTarget"] for case in cases),
    realTargetInputs=[dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
        for p in (args.real_kernel, args.real_receipt, args.real_spec)] if real else [],
    status="RED_LEGACY_HAS_NO_INDEPENDENT_RESPONSE" if args.legacy_baseline else "PASS",
    limits=["Synthetic nofault functions; no PAC/BTI/cache hardware or device execution"])
(args.output / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(f'{report["status"]}: {len(cases)} production A64 replay cases')
