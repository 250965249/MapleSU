"""Execute the SDK's emitted SELinux eligibility check against isolated credentials."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/maplesu-selinux-20261116/eligibility'
OUT.mkdir(parents=True, exist_ok=True)
source = ROOT / 'runtime/maplesu-sdk/sdk/src/patch/ord071/patch_base.cpp'
text = source.read_text(encoding='utf-8')
start = text.index('void PatchBase::emit_check_current_allow_selinux_to_x10(')
end = text.index('\n}', start) + 2
(OUT / 'eligibility.inc').write_text(text[start:end], encoding='utf-8')
(OUT / 'emit.cpp').write_text(r'''
#include <asmjit/a64.h>
#include <cstdio>
#include <cstdint>
namespace kernel_module {
int cap_count = 2;
uint64_t get_cap_ability_max() { return 0xffffffff; }
int get_caps_cnt() { return cap_count; }
namespace export_symbol {
void get_current(asmjit::a64::Assembler* a, asmjit::a64::GpX reg) {
    a->mov(reg, asmjit::Imm(0x200000));
}
}}
struct PatchBase {
    uint32_t m_cred_offset, m_cred_atomic_usage_size;
    uint32_t m_cred_securebits_offset, m_cred_cap_effective_offset;
    void emit_check_current_allow_selinux_to_x10(asmjit::a64::Assembler*);
};
#include "eligibility.inc"
int main() {
    for (unsigned usage : {4u, 8u}) for (int count : {2, 5}) {
        kernel_module::cap_count = count;
        asmjit::CodeHolder code;
        asmjit::Environment environment;
        environment.setArch(asmjit::Arch::kAArch64);
        if (code.init(environment)) return 1;
        asmjit::a64::Assembler assembler(&code);
        PatchBase patch{0x80, usage, usage + 16, usage == 4 ? 40u : 48u};
        patch.emit_check_current_allow_selinux_to_x10(&assembler);
        if (assembler.finalize() || code.flatten() || code.resolveUnresolvedLinks()) return 2;
        const auto& bytes = code.textSection()->buffer();
        printf("%u %d ", usage, count);
        for (size_t i = 0; i < bytes.size(); ++i) printf("%02x", bytes.data()[i]);
        puts("");
    }
}
''', encoding='utf-8')
build = subprocess.run([
    'docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '-e', 'LC_ALL=C',
    '--mount', f'type=bind,source={ROOT},target=/source,readonly',
    '--mount', f'type=bind,source={OUT},target=/output',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', 'sh', '-ec',
    'c++ -std=c++17 -O0 -DASMJIT_STATIC -DASMJIT_NO_X86 '
    '-I/source/runtime/maplesu-sdk/sdk/third_party/asmjit/1.16.0/src '
    '/output/emit.cpp '
    '/source/runtime/maplesu-sdk/sdk/third_party/asmjit/1.16.0/src/asmjit/core/*.cpp '
    '/source/runtime/maplesu-sdk/sdk/third_party/asmjit/1.16.0/src/asmjit/arm/*.cpp '
    '-pthread -ldl -o /output/emit && /output/emit',
], capture_output=True, text=True, encoding='utf-8', errors='replace')
(OUT / 'build.log').write_text(build.stdout + build.stderr, encoding='utf-8')
if build.returncode:
    raise SystemExit(build.stderr)
checks = []
emitted = set()
for line in build.stdout.splitlines():
    usage, count, encoded = line.split()
    usage, count, body = int(usage), int(count), bytes.fromhex(encoded)
    assert (usage, count) in {(4, 2), (4, 5), (8, 2), (8, 5)} and (usage, count) not in emitted
    assert body, 'assembler emitted no instructions'
    emitted.add((usage, count))
    cases = [
        ('eligible', 0, 0, 0xffffffff, 0xffffffff, 1),
        ('nonzero euid', 1, 0, 0xffffffff, 0xffffffff, 0),
        ('nonzero securebits', 0, 1, 0xffffffff, 0xffffffff, 0),
        ('first capability word below threshold', 0, 0, 0xfffffffe, 0xffffffff, 0),
        ('second capability word below threshold', 0, 0, 0xffffffff, 0xfffffffe, 0),
        ('empty capability words', 0, 0, 0, 0, 0),
        ('multiple rejection conditions', 1, 1, 0, 0, 0),
        ('capability words above threshold', 0, 0, 0x100000000, 0x100000000, 1),
        ('unsigned high-bit capability words', 0, 0, 1 << 63, 1 << 63, 1),
    ]
    if count == 5:
        cases.append(('only fifth capability word below threshold', 0, 0, 0xffffffff, 0xffffffff, 0))
    for name, euid, securebits, first, second, expected in cases:
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(0x100000, 0x1000)
        uc.mem_map(0x200000, 0x2000)
        uc.mem_write(0x100000, body)
        uc.mem_write(0x200080, struct.pack('<Q', 0x201000))
        uc.mem_write(0x201000 + usage + 16, struct.pack('<I', euid))
        uc.mem_write(0x201000 + usage + 32, struct.pack('<I', securebits))
        inherited = 40 if usage == 4 else 48
        caps = [first, second] + [0xffffffff] * (count - 2)
        if name.startswith('only fifth'):
            caps[4] = 0xfffffffe
        uc.mem_write(0x201000 + inherited, struct.pack('<' + 'Q' * count, *caps))
        uc.emu_start(0x100000, 0x100000 + len(body), count=1000)
        actual = uc.reg_read(R.UC_ARM64_REG_X10)
        assert uc.reg_read(R.UC_ARM64_REG_PC) == 0x100000 + len(body), 'check did not terminate'
        checks.append(dict(usage=usage, capCount=count, case=name, actual=actual, expected=expected))
assert emitted == {(4, 2), (4, 5), (8, 2), (8, 5)} and len(checks) == 38, 'incomplete execution matrix'
receipt = dict(sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
               checks=checks, passed=all(c['actual'] == c['expected'] for c in checks))
(OUT / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
assert receipt['passed'], [c for c in checks if c['actual'] != c['expected']]
print(f'PASS production ARM64 eligibility: {len(checks)} cases; deny=0, allow=1')
