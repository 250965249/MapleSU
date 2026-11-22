"""Replay the production Ultra boot filter on an actual boot's AArch64 loader layout."""
import argparse, json, os, random, struct, subprocess, sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as R
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/specgen'))
from specgen.product import cached_jar

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--boot', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--generate', action='store_true', help='Also generate a complete root+filter plan from this pristine image')
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
java = native_toolchain.jdk_tool('java')
stdlib = cached_jar('org.jetbrains.kotlin', 'kotlin-stdlib', '2.4.20')
anno = cached_jar('org.jetbrains', 'annotations', '13.0')
coroutines = cached_jar('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.11.0')
compiler = cached_jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', '2.4.20')
deps = [stdlib, anno, cached_jar('org.jetbrains.kotlinx', 'kotlinx-serialization-json-jvm', '1.11.0'),
        cached_jar('org.jetbrains.kotlinx', 'kotlinx-serialization-core-jvm', '1.11.0'),
        ROOT/'image-core/build/libs/image-core.jar', native_toolchain.android_jar()]
harness = a.output/'EmitVr.kt'
harness.write_text('''package dev.maplesu.manager.ultrakernel
import java.io.File
fun main(args: Array<String>) {
    val kernel = UltraKernelPlan.readKernel(File(args[0]))
    check(!UltraKernelVivoFilter.present(kernel))
    val s = UltraKernelKallsymsTable.decode(kernel)
    val records = if (args.size > 2) UltraKernelSpecGenerator(vivoVrFilter = true)
        .generate(kernel, UltraKernelCredential.of("Aa1".repeat(16))).records
        else UltraKernelVivoFilter.records(kernel)
    val patched = kernel.copyOf()
    for (r in records) r.replacement.copyInto(patched, r.offset.toInt())
    check(UltraKernelVivoFilter.present(patched))
    val bodyRecord = records.single { it.role == "vivo-vr-filter-body" }
    for (slot in listOf(UltraKernelVivoPayload.HDR, UltraKernelVivoPayload.LEN, UltraKernelVivoPayload.COMPRESSED,
        UltraKernelVivoPayload.DISPLACED, UltraKernelVivoPayload.CONTINUE, UltraKernelVivoPayload.RETURN,
        UltraKernelVivoPayload.RELEASE_HDR, UltraKernelVivoPayload.VFREE, UltraKernelVivoPayload.DECOMPRESS)) {
        val at = bodyRecord.offset.toInt() + slot
        patched[at] = (patched[at].toInt() xor 1).toByte()
        check(!UltraKernelVivoFilter.present(patched)) { "Tampered relocation accepted: $slot" }
        patched[at] = (patched[at].toInt() xor 1).toByte()
    }
    val other = records.filter { !it.role.startsWith(UltraKernelVivoFilter.ROLE) }
    val filter = records.filter { it.role.startsWith(UltraKernelVivoFilter.ROLE) }
    check(filter.none { vr -> other.any { vr.offset < it.offset + it.length && it.offset < vr.offset + vr.length } })
    if (args.size > 2) {
        val boot = File(args[0])
        val before = UltraKernelSpec.sha256(boot)
        val flow = UltraKernelFlow(File(args[1], "flow"), UltraKernelFileAssets(File("manager/src/main/assets")), true)
        val prepared = flow.prepare(boot, UltraKernelCredential.of("Aa1".repeat(16)))
        val candidate = requireNotNull(prepared.candidate)
        check(UltraKernelPlan.readKernel(candidate.image).contentEquals(patched))
        check(candidate.image.length() == boot.length())
        check(UltraKernelSpec.sha256(boot) == before)
        check(flow.prepare(candidate.image, prepared.credential).alreadyInstalled)
        println("FLOW containerReadback=true idempotent=true sourceUnchanged=true")
    }
    File(args[1], "replay-kernel.raw").writeBytes(patched)
    println("META " + kernel.size + " " + records.size)
    for (name in listOf("load_module", "vfree", "module_decompress_cleanup"))
        println("SYM $name ${s.offsetOf(name) ?: -1}")
    for (r in filter) println("REC ${r.role} ${r.offset} " + r.replacement.joinToString("") { "%02x".format(it.toInt() and 255) })
}
''', encoding='utf-8')
cp = os.pathsep.join(map(str, deps))
jar = a.output/'replay.jar'
sources = sorted((ROOT/'manager/src/main/java/dev/maplesu/manager/ultrakernel').glob('*.kt'))
build = subprocess.run([str(java), '-Xmx768m', '-cp', os.pathsep.join(map(str, [compiler, stdlib, anno, coroutines])),
    'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '21',
    '-classpath', cp, '-d', str(jar), *map(str, sources), str(harness)], capture_output=True, text=True)
if build.returncode: raise RuntimeError(build.stdout + build.stderr)
emitted = subprocess.run([str(java), '-Xmx768m', '-cp', str(jar)+os.pathsep+cp,
    'dev.maplesu.manager.ultrakernel.EmitVrKt', str(a.boot), str(a.output), *(['generate'] if a.generate else [])],
    capture_output=True, text=True)
if emitted.returncode: raise RuntimeError(emitted.stdout + emitted.stderr)
symbols, records = {}, {}
for line in emitted.stdout.splitlines():
    if line.startswith('SYM '):
        _, name, off = line.split(); symbols[name] = int(off)
    if line.startswith('REC '):
        _, name, off, blob = line.split(); records[name] = (int(off), bytes.fromhex(blob))
raw = (a.output/'replay-kernel.raw').read_bytes()
site = records['vivo-vr-filter-entry'][0]
cave, body = records['vivo-vr-filter-body']
# entry.S's return branch targets the loader's own PAC/SCS return instruction.
def branch_target(at):
    word = struct.unpack_from('<I', raw, at)[0]
    imm = word & 0x3ffffff
    if imm & 0x2000000: imm -= 0x4000000
    return at + imm*4
ret = branch_target(cave + 64)

def elf(modinfo=b'name=vr\0', section=b'.modinfo\0'):
    b = bytearray(512)
    b[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', b, 16, 1, 183, 1)
    struct.pack_into('<Q', b, 40, 64)
    struct.pack_into('<HHHH', b, 56, 0, 64, 3, 1)
    struct.pack_into('<IIQQQQ', b, 128, 0, 3, 0, 0, 320, 64)
    struct.pack_into('<IIQQQQ', b, 192, 1, 1, 0, 0, 400, len(modinfo))
    b[320:320+1+len(section)] = b'\0' + section
    b[400:400+len(modinfo)] = modinfo
    return b

cases = [
    ('exact-vr', elf(), True), ('non-target', elf(b'name=other\0'), False),
    ('prefix', elf(b'name=vr_test\0'), False), ('suffix', elf(b'name=xvr\0'), False),
    ('substring', elf(b'description=name=vr\0'), False), ('vklp-runtime-unchanged', elf(b'name=vklp\0'), False),
    ('second-entry', elf(b'license=GPL\0name=vr\0'), True),
    ('unterminated', elf(b'name=vr'), False), ('wrong-section', elf(section=b'.modinfX\0'), False),
    ('empty', bytearray(), False), ('short-header', bytearray(63), False),
]
bad = elf(); struct.pack_into('<Q', bad, 40, 0xfffffffffffffff0); cases.append(('section-overflow', bad, False))
bad = elf(); struct.pack_into('<Q', bad, 192+32, 0xffffffffffffffff); cases.append(('modinfo-overflow', bad, False))
bad = elf(); struct.pack_into('<H', bad, 18, 62); cases.append(('wrong-arch', bad, False))
bad = elf(); struct.pack_into('<H', bad, 60, 65535); cases.append(('too-many-sections', bad, False))
# Deterministic damaged metadata stays on the original loader path.
rng = random.Random(20261110)
for i in range(32):
    bad = elf(b'name=other\0')
    for _ in range(4):
        at = rng.randrange(64, 320)
        bad[at] ^= 1 << rng.randrange(8)
    cases.append((f'damaged-metadata-{i}', bad, False))
results = []
pac = struct.unpack_from('<I', raw, site-4)[0] in (0xd503233f, 0xd503231f)
for unwind in (('pac', 'dynamic-scs') if pac else ('plain',)):
 for flags in (0, 1, 2, 3, 4):
    for name, image, expected in cases:
        if flags & 4 and symbols['module_decompress_cleanup'] < 0: expected = False
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(0, (len(raw)+4095)&~4095); uc.mem_write(0, raw)
        uc.mem_map(0x4000000, 0x10000)
        uc.mem_map(0x5000000, 0x1000)
        uc.mem_map(0x5100000, 0x10000)
        uc.mem_map(0x6000000, 0x10000)
        caller = 0x6001000
        if unwind == 'dynamic-scs':
            # Android's boot-time alternative rewrites PACIASP/AUTIASP to SCS push/pop.
            uc.mem_write(site-4, struct.pack('<I', 0xf800865e))
            uc.mem_write(ret, struct.pack('<I', 0xf85f8e5e))
        if image: uc.mem_write(0x5100000, bytes(image))
        hdr_off = (struct.unpack_from('<I', body, 16)[0] >> 5) & 65535
        len_off = (struct.unpack_from('<I', body, 20)[0] >> 5) & 65535
        uc.mem_write(0x5000000+hdr_off, struct.pack('<Q', 0x5100000))
        uc.mem_write(0x5000000+len_off, struct.pack('<Q', len(image)))
        saved = {reg: 0x123400000+reg for reg in [R.UC_ARM64_REG_X18, *range(R.UC_ARM64_REG_X19, R.UC_ARM64_REG_X29+1)]}
        saved[R.UC_ARM64_REG_X18] = 0x6008000
        for reg, value in saved.items(): uc.reg_write(reg, value)
        uc.reg_write(R.UC_ARM64_REG_SP, 0x4008000)
        uc.reg_write(R.UC_ARM64_REG_X0, 0x5000000)
        uc.reg_write(R.UC_ARM64_REG_X1, 0x5010000)
        uc.reg_write(R.UC_ARM64_REG_X2, flags)
        uc.reg_write(R.UC_ARM64_REG_X30, caller)
        seen = []
        def hook(vm, address, size, _):
            if address in [symbols['vfree'], symbols['module_decompress_cleanup']]:
                seen.append(('cleanup', address, vm.reg_read(R.UC_ARM64_REG_X0)))
                vm.reg_write(R.UC_ARM64_REG_PC, vm.reg_read(R.UC_ARM64_REG_X30))
            elif address == site+4:
                seen.append(('forward',)); vm.emu_stop()
            elif address == ret:
                seen.append(('filtered',))
        uc.hook_add(UC_HOOK_CODE, hook)
        uc.emu_start(site-4 if pac else site, caller, count=200000)
        filtered = ('filtered',) in seen
        assert filtered == expected, (name, flags, seen)
        if filtered:
            cleanup = symbols['module_decompress_cleanup'] if flags & 4 else symbols['vfree']
            pointer = 0x5000000 if flags & 4 else 0x5100000
            assert seen == [('cleanup', cleanup, pointer), ('filtered',)], (name, seen)
            assert uc.reg_read(R.UC_ARM64_REG_X0) == 0
            assert uc.reg_read(R.UC_ARM64_REG_SP) == 0x4008000
            assert uc.reg_read(R.UC_ARM64_REG_PC) == caller
        else:
            assert seen == [('forward',)], (name, seen)
            assert [uc.reg_read(reg) for reg in [R.UC_ARM64_REG_X0, R.UC_ARM64_REG_X1, R.UC_ARM64_REG_X2]] == [0x5000000, 0x5010000, flags]
        for reg, value in saved.items():
            if reg == R.UC_ARM64_REG_X18 and unwind == 'dynamic-scs' and not filtered: value += 8
            assert uc.reg_read(reg) == value, (name, flags, unwind, reg)
        assert uc.reg_read(R.UC_ARM64_REG_X30) == caller
        results.append(dict(case=name, flags=flags, unwind=unwind, filtered=filtered, passed=True))
summary = dict(boot=str(a.boot), generatedTogether=a.generate, cases=len(results), failures=0,
               loaderSite=site, filterCave=cave, runtimeDeviceTest=False, results=results)
(a.output/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
print(f'ULTRA_VR_REPLAY_OK cases={len(results)} generatedTogether={a.generate} site={site:#x} cave={cave:#x}')
