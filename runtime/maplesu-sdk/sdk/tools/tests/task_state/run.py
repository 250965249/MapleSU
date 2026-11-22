#!/usr/bin/env python3
"""Extract the whole task-state probe; real std::thread/pipe with boundary fault injection."""
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
SOURCE = SDK / 'src/kernel_offsets/task_struct.cpp'
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
CASES = ['success', 'offset-zero', 'offset-last', 'blocked255', 'blocked256', 'unchanged', 'ambiguous',
         'zero-spurious', 'cache-zero', 'cache-hit', 'cache-read-error', 'cache-read-mutates',
         'cache-read-mutates-failure', 'cache-write-error',
         'pipe-error', 'thread-error', 'current-error', 'current-zero', 'read1-error', 'read2-error', 'read3-error',
         'worker-read-error', 'worker-read-zero', 'wake-error', 'wake-zero',
         'worker-read-eintr', 'wake-eintr', 'both-eintr']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    snapshots = out / 'inputs'
    snapshots.mkdir(exist_ok=True)
    inputs = [SOURCE, HERE / 'fixture.h', HERE / 'fixture.cpp', Path(__file__).resolve(),
              SDK.parent / 'include/module_err_def.h', SDK / 'manifest/0001_task_struct.o.json', SDK / 'tools/sdk_common.py']
    identities = []
    for source in inputs:
        data = source.read_bytes()
        (snapshots / source.name).write_bytes(data)
        identities.append(dict(path=source.relative_to(ROOT).as_posix(), snapshot='inputs/' + source.name,
                               bytes=len(data), sha256=sha(data)))
    source = (snapshots / SOURCE.name).read_text(encoding='utf-8')
    matches = list(re.finditer(r'^KModErr get_task_struct_state_offset\(uint32_t& offset\) \{.*?^\}$',
                              source, re.MULTILINE | re.DOTALL))
    assert len(matches) == 1, 'expected exactly one complete production function'
    found = matches[0]
    fragment = found.group(0) + '\n'
    line = source.count('\n', 0, found.start()) + 1
    (snapshots / 'get_task_struct_state_offset.cpp').write_text(fragment, encoding='utf-8')
    extracted = '#include "fixture.h"\nnamespace kernel_module {\n' + f'#line {line} "{SOURCE.as_posix()}"\n' + fragment + '}\n'
    (out / 'extracted.cpp').write_text(extracted, encoding='utf-8')
    docker = [shutil.which('docker') or 'docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
              '--read-only', '--tmpfs', '/tmp:rw,size=32m', '--mount', f'type=bind,source={out},target=/work',
              '-w', '/work', '--entrypoint', '/bin/sh', IMAGE]
    commands = []

    def run(name, argv):
        argv = [str(value) for value in argv]
        result = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        commands.append(dict(name=name, argv=argv, exit=result.returncode))
        return result

    wrapped = ['pipe', 'read', '__read_chk', 'write', 'close', 'pthread_create', 'pthread_join']
    compiled = run('compile', [*docker, '-c', 'exec "$@"', 'sh', 'g++', '-std=c++20', '-O1', '-g', '-pthread',
                   '-fno-omit-frame-pointer', '-fsanitize=address,undefined', '-no-pie', '-static-libstdc++',
                   '-static-libgcc', '-I/work/inputs', 'inputs/fixture.cpp', 'extracted.cpp',
                   '-Wl,' + ','.join('--wrap=' + name for name in wrapped), '-o', 'task-state-test'])
    results = []
    if compiled.returncode == 0:
        script = ['ulimit -c 0']
        for case in CASES:
            script += ['ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 '
                       f'timeout --signal=KILL 3s ./task-state-test {case} > {case}.log 2>&1',
                       f'printf "%s\\n" "$?" > {case}.exit']
        launched = run('cases', [*docker, '-c', '\n'.join(script)])
        if launched.returncode: raise RuntimeError(launched.stderr)
        for case in CASES:
            log = (out / (case + '.log')).read_text(encoding='utf-8', errors='replace')
            rows = [json.loads(row) for row in log.splitlines() if row.startswith('{')]
            code = int((out / (case + '.exit')).read_text())
            results.append(dict(name=case, exit=code, rows=rows, processTimeout=code == 137,
                                joinableThreadTermination='terminate called without an active exception' in log,
                                asanDiagnostic='ERROR: AddressSanitizer:' in log,
                                leakDiagnostic='ERROR: LeakSanitizer:' in log,
                                ubsanDiagnostic='runtime error:' in log))
    else:
        print(compiled.stdout + compiled.stderr)
    ndk = None
    if args.ndk:
        sys.path.insert(0, str(SDK / 'tools'))
        import sdk_common as S
        entry = json.loads((snapshots / '0001_task_struct.o.json').read_text(encoding='utf-8'))
        compiler = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR / 'clang++.exe'
        flags = S.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        result = run('ndk-compile', [compiler, *flags, '-I', SDK.parent / 'include', '-I', SDK / 'include',
                     '-iquote', SOURCE.parent, '-c', snapshots / SOURCE.name, '-o', out / 'task_struct.o'])
        object_file = out / 'task_struct.o'
        ndk = dict(exit=result.returncode, flagsProfile=entry['flagsProfile'],
                   sourceSha256=identities[0]['sha256'], passed=result.returncode == 0,
                   objectSha256=sha(object_file.read_bytes()) if object_file.exists() else None)
    passed = len(results) == len(CASES) and all(row['exit'] == 0 and not row['asanDiagnostic']
            and not row['ubsanDiagnostic'] and not row['leakDiagnostic'] for row in results) and (ndk is None or ndk['passed'])
    after = [dict(path=path.relative_to(ROOT).as_posix(), bytes=len(path.read_bytes()), sha256=sha(path.read_bytes())) for path in inputs]
    receipt = dict(passed=passed, image=IMAGE, inputs=identities, inputsAfter=after,
                   fragment=dict(line=line, lines=fragment.count('\n'), sha256=sha(fragment.encode())),
                   extractedSha256=sha(extracted.encode()), commands=commands, cases=results, ndk=ndk,
                   deviceAccess=False, officialArtifactsWritten=False,
                   scope='complete unchanged production function; real std::thread/pipe; cache/current/kernel-read boundaries and syscall faults')
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=passed, cases=len(results), failures=[row['name'] for row in results if row['exit']
            or row['asanDiagnostic'] or row['ubsanDiagnostic'] or row['leakDiagnostic']], ndk=ndk, out=str(out)), indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
