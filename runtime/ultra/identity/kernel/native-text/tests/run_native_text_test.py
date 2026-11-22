#!/usr/bin/env python3
"""Exercise transformed native ARM64 dispatch and the exact text-owner provider.

Kernel locking, text patching, allocation and scheduling are explicit host seams.
No result in this runner qualifies real SMP, hardware or target-kernel execution.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[6]


def extract(source: str, marker: str) -> str:
    start = source.index(marker)
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True, help='Unmodified supported kernel source or four-file input')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    script = ROOT / 'scripts/apply-ultra-kprobe-text-owner.py'
    spec = importlib.util.spec_from_file_location('native_transform', script)
    transform = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(transform)
    rows = transform.transformed(args.kernel.resolve())
    arm = rows[Path('arch/arm64/kernel/probes/kprobes.c')].decode()
    markers = [
        'static void __kprobes arch_prepare_ss_slot(',
        'static void __kprobes arch_prepare_simulate(',
        'static void __kprobes arch_simulate_insn(',
        'int __kprobes arch_prepare_kprobe(',
        'void __kprobes arch_arm_kprobe(',
        'void __kprobes arch_disarm_kprobe(',
        'int arch_kprobe_text_owner_patch(',
        'void __kprobes arch_remove_kprobe(',
        'static void __kprobes save_previous_kprobe(',
        'static void __kprobes restore_previous_kprobe(',
        'static void __kprobes set_current_kprobe(',
        'static void __kprobes kprobes_save_local_irqflag(',
        'static void __kprobes kprobes_restore_local_irqflag(',
        'static void __kprobes setup_singlestep(',
        'static int __kprobes reenter_kprobe(',
        'static void __kprobes\npost_kprobe_handler_selected(struct kprobe *cur,',
        'static void __kprobes\npost_kprobe_handler(struct kprobe *cur,',
        'int __kprobes\nkprobe_brk_handler(',
        'int __kprobes\nkprobe_ss_brk_handler(',
    ]
    functions = '\n\n'.join(extract(arm, m) for m in markers)
    core = rows[Path('kernel/kprobes.c')].decode()
    functions += '\n\n' + extract(core, 'static int prepare_kprobe(')
    provider = rows[Path('kernel/kprobe_text_owner.inc')].decode()
    provider = provider[provider.index('#ifdef CONFIG_ARM64') + len('#ifdef CONFIG_ARM64'):provider.rindex('#endif')]
    fixture = Path(__file__).with_name('native_text_fixture.cpp').read_text()
    cpp = output / 'native_text.cpp'
    # Linux LP64 -> Windows LLP64 is an explicit host type seam. The production
    # functions retain all pointer bits and the C allocation gains its C++ cast.
    host = fixture.replace('// EXACT_PROVIDER', provider).replace('// EXACT_ARCH', functions)
    host = re.sub(r'\bunsigned long\b', 'uintptr_t', host)
    host = re.sub(r'\blong\b', 'intptr_t', host)
    host = host.replace('entry = kzalloc(sizeof(*entry), GFP_KERNEL);',
                        'entry = static_cast<decltype(entry)>(kzalloc(sizeof(*entry), GFP_KERNEL));')
    cpp.write_text(host)
    toolchains = sorted((ROOT / '.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))
    cxx = toolchains[-1]
    exe = output / 'native_text.exe'
    command = [str(cxx), '-std=c++17', '-O1', '-I' + str(ROOT / 'runtime/ultra/authorization'),
               str(cpp), '-static', '-o', str(exe)]
    build = subprocess.run(command, capture_output=True, text=True)
    (output / 'compile.log').write_text(build.stdout + build.stderr)
    if build.returncode:
        print(build.stderr)
        return build.returncode
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    (output / 'run.log').write_text(run.stdout + run.stderr)
    report = dict(passed=run.returncode == 0, exitCode=run.returncode,
        command=command, output=run.stdout + run.stderr,
        scope='exact native producer functions; explicit kernel text/RCU/allocator/B-simulator seams; no kernel/SMP/hardware execution',
        inputs=[dict(path=str(k), sha256=hashlib.sha256(v).hexdigest()) for k, v in rows.items()],
        transformSha256=hashlib.sha256(script.read_bytes()).hexdigest())
    (output / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return run.returncode


if __name__ == '__main__':
    sys.exit(main())
