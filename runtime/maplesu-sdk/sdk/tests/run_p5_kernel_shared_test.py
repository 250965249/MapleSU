#!/usr/bin/env python3
"""Execute real kernel shared-value domain functions with kernel API seams."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

from run_p5_kernel_owner_test import extract


SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'runtime/ultra/identity/kernel/manager_management.c'
    text = source.read_text(encoding='utf-8')
    structure = extract(text, 'struct msu_shared_bool {', True)
    signatures = ['static int msu_shared_bool_acquire_domain(',
        'static int msu_shared_bool_create_domain(', 'static int msu_shared_bool_update(']
    functions = '\n\n'.join(extract(text, signature) for signature in signatures)
    # Kernel C is LP64; the host C++ compiler is LLP64. Keep pointer width and
    # spell the implicit C void* conversion explicitly without changing logic.
    host = functions.replace('(unsigned long)', '(uintptr_t)')
    host = host.replace('(void __user *)', '(void *)')
    host = host.replace('address = vmalloc(PAGE_SIZE);', 'address = (u8*)vmalloc(PAGE_SIZE);')
    fixture = SDK / 'tests/p5_kernel_shared_fixture.cpp'
    harness = fixture.read_text(encoding='utf-8').replace('// EXACT_STRUCT', structure)
    harness = harness.replace('// EXACT_FUNCTIONS', host)
    cpp = out / 'kernel_shared.cpp'
    cpp.write_text(harness, encoding='utf-8')
    compiler = sorted((ROOT / '.research/toolchains').glob(
        'llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    exe = out / 'kernel_shared.exe'
    command = [str(compiler), '-std=c++17', '-O1',
        '-I' + str(ROOT / 'runtime/ultra/authorization'), str(cpp), '-static', '-o', str(exe)]
    build = subprocess.run(command, capture_output=True, text=True)
    (out / 'compile.log').write_text(build.stdout + build.stderr, encoding='utf-8')
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    (out / 'run.log').write_text(run.stdout + run.stderr, encoding='utf-8')
    assert run.returncode == 0, run.stdout + run.stderr
    report = dict(passed=True, source=str(source),
        sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        extractedSha256=hashlib.sha256((structure + functions).encode()).hexdigest(),
        fixtureSha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
        command=command, output=run.stdout,
        hostAdaptations=['LP64 unsigned long pointer casts use uintptr_t on LLP64',
            'C implicit void* to byte pointer conversion made explicit for C++',
            'user address annotation removed only at the copy API seam'],
        scope='exact shared create/acquire/store/release bodies; task/owner/VM/lock APIs are seams; no live kernel concurrency')
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
