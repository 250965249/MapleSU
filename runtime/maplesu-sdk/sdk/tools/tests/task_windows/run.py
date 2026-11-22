#!/usr/bin/env python3
"""Extract complete real stack/mm getters; test only their local read windows."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SDK = HERE.parents[2]
ROOT = SDK.parents[2]
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
SOURCE = SDK / 'src/kernel_offsets/task_struct.cpp'
CASES = [(target, 'no-match', length) for target in ['stack', 'mm'] for length in [0, 1, 4, 7, 8, 12, 16, 20]]
CASES += [(target, 'last', length) for target in ['stack', 'mm'] for length in [8, 12, 16, 20]]
CASES += [(target, mode, 20) for target in ['stack', 'mm'] for mode in
          ['first', 'cache-zero', 'cache-hit', 'comm-error', 'read-error', 'cache-write-error', 'cache-read-error']]
CASES += [('stack', mode, 20) for mode in ['legacy', 'task-symbol-error', 'stack-symbol-error', 'legacy-symbol-error']]
CASES += [('mm', mode, 20) for mode in ['mm-get-error', 'mmput-error', 'execute-error', 'current-error']]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--ndk', action='store_true', help='Check the whole production TU with its actual manifest flags')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    snapshot = out / 'inputs'
    snapshot.mkdir(exist_ok=True)
    inputs = [SOURCE, HERE / 'fixture.cpp', HERE / 'fixture.h', Path(__file__).resolve(),
              SDK.parent / 'include/module_err_def.h', SDK / 'manifest/0001_task_struct.o.json',
              SDK / 'tools/sdk_common.py']
    identities = []
    for source in inputs:
        data = source.read_bytes()
        (snapshot / source.name).write_bytes(data)
        identities.append({'path': source.relative_to(ROOT).as_posix(), 'snapshot': 'inputs/' + source.name,
                           'bytes': len(data), 'sha256': sha(data)})
    source = (snapshot / SOURCE.name).read_text(encoding='utf-8')
    fragments = []
    generated = ['#include "fixture.h"\nnamespace kernel_module {\n']
    for name in ['get_task_struct_stack_offset', 'get_task_struct_mm_offset']:
        # Production function ends are column-zero braces; nested blocks remain indented.
        pattern = rf'^KModErr {name}\(uint32_t& offset\) \{{.*?^\}}$'
        matches = list(re.finditer(pattern, source, re.MULTILINE | re.DOTALL))
        assert len(matches) == 1, f'{name}: expected one complete function'
        found = matches[0]
        line = source.count('\n', 0, found.start()) + 1
        text = found.group(0) + '\n'
        (snapshot / (name + '.cpp')).write_text(text, encoding='utf-8')
        fragments.append({'name': name, 'line': line, 'lines': text.count('\n'), 'sha256': sha(text.encode())})
        generated += [f'#line {line} "{SOURCE.as_posix()}"\n', text]
    generated.append('}\n')
    extracted = ''.join(generated)
    (out / 'extracted.cpp').write_text(extracted, encoding='utf-8')
    docker = [shutil.which('docker') or 'docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
              '--read-only', '--tmpfs', '/tmp:rw,size=32m', '--mount', f'type=bind,source={out},target=/work',
              '-w', '/work', '--entrypoint', '/bin/sh', IMAGE]
    commands = []

    def run(name, argv):
        argv = [str(value) for value in argv]
        done = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(done.stdout + done.stderr, encoding='utf-8')
        commands.append({'name': name, 'argv': argv, 'exit': done.returncode})
        return done

    compiled = run('compile', [*docker, '-c', 'exec "$@"', 'sh', 'g++', '-std=c++20', '-O1', '-g',
                   '-fno-omit-frame-pointer', '-fsanitize=address,undefined', '-no-pie', '-I/work/inputs',
                   'inputs/fixture.cpp', 'extracted.cpp', '-o', 'task-windows-test'])
    results = []
    if compiled.returncode == 0:
        script = []
        for target, mode, length in CASES:
            name = f'{target}-{mode}-{length}'
            script += [f'ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 '
                       f'./task-windows-test {target} {mode} {length} > {name}.log 2>&1',
                       f'printf "%s\\n" "$?" > {name}.exit']
        launched = run('cases', [*docker, '-c', '\n'.join(script)])
        if launched.returncode: raise RuntimeError(launched.stderr)
        for target, mode, length in CASES:
            name = f'{target}-{mode}-{length}'
            log = (out / (name + '.log')).read_text(encoding='utf-8', errors='replace')
            rows = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
            results.append({'name': name, 'target': target, 'mode': mode, 'length': length,
                            'exit': int((out / (name + '.exit')).read_text()), 'rows': rows,
                            'asanDiagnostic': 'ERROR: AddressSanitizer:' in log,
                            'ubsanDiagnostic': 'runtime error:' in log})
    else:
        print(compiled.stdout + compiled.stderr)
    ndk = None
    if args.ndk:
        sys.path.insert(0, str(SDK / 'tools'))
        import sdk_common as S
        entry = json.loads((snapshot / '0001_task_struct.o.json').read_text(encoding='utf-8'))
        compiler = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR / 'clang++.exe'
        version = run('ndk-version', [compiler, '--version'])
        flags = S.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        done = run('ndk-compile', [compiler, *flags, '-I', SDK.parent / 'include', '-I', SDK / 'include',
                                  '-fsyntax-only', SOURCE])
        unchanged = sha(SOURCE.read_bytes()) == identities[0]['sha256']
        ndk = {'exit': done.returncode, 'sourceUnchanged': unchanged, 'compilerVersion': version.stdout,
               'flagsProfile': entry['flagsProfile'], 'passed': done.returncode == 0 and unchanged}
    passed = len(results) == len(CASES) and all(row['exit'] == 0 and not row['asanDiagnostic']
        and not row['ubsanDiagnostic'] for row in results) and (ndk is None or ndk['passed'])
    receipt = {'passed': passed, 'image': IMAGE, 'source': identities, 'fragments': fragments,
               'extractedSha256': sha(extracted.encode()), 'commands': commands, 'results': results,
               'ndk': ndk, 'deviceAccess': False, 'officialArtifactsWritten': False,
               'scope': 'unmodified complete production function bodies; cache/symbol/kernel-read/execution seams'}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': passed, 'cases': len(results), 'failures': [row['name'] for row in results
        if row['exit'] or row['asanDiagnostic'] or row['ubsanDiagnostic']], 'ndk': ndk, 'out': str(out)}, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
