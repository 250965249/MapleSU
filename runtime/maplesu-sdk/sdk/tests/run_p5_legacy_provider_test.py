#!/usr/bin/env python3
"""Run the production Legacy scope/dispatch with explicit kernel API seams."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = ROOT / 'runtime/ultra/identity/kernel/manager_legacy_hook.inc'
    fixture = SDK / 'tests/p5_legacy_provider_fixture.cpp'
    inputs = [source, fixture, Path(__file__).resolve(),
        ROOT / 'runtime/ultra/authorization/request_protocol.h',
        ROOT / 'runtime/ultra/authorization/legacy_hook_private.h']
    before = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in inputs}
    # Linux is LP64; the Windows C++ host is LLP64. Convert only pointer casts
    # and C implicit void* assignment, leaving executed branches unchanged.
    adapted = source.read_text(encoding='utf-8').replace('(unsigned long)', '(uintptr_t)')
    adapted = adapted.replace('unsigned long ', 'uintptr_t ')
    adapted = adapted.replace('session = kzalloc(', 'session = (msu_management_session*)kzalloc(')
    cpp = out / 'legacy_provider.cpp'
    cpp.write_text(fixture.read_text(encoding='utf-8').replace('// EXACT_FUNCTIONS', adapted), encoding='utf-8')
    compiler = sorted((ROOT / '.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    exe = out / 'legacy_provider.exe'
    command = [str(compiler), '-std=c++20', '-O1', '-I' + str(ROOT / 'runtime/ultra/authorization'), str(cpp), '-static', '-o', str(exe)]
    build = subprocess.run(command, capture_output=True, text=True)
    (out / 'compile.log').write_text(build.stdout + build.stderr, encoding='utf-8')
    assert not build.returncode, build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    (out / 'run.log').write_text(run.stdout + run.stderr, encoding='utf-8')
    assert not run.returncode, run.stdout + run.stderr
    after = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in inputs}
    assert before == after, 'input changed during Legacy provider validation'
    report = dict(passed=True, sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        sourceInputs=before, inputsStable=True, command=command, output=run.stdout,
        scope='actual Legacy provider; current/task/cred/table/kernel helper seams; no live kernel scheduling/device execution')
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
