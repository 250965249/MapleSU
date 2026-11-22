#!/usr/bin/env python3
"""Compile actual SDK layout consumers and shared parser; capture kernel I/O."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
CASES = ['accessor-overflow-eq', 'accessor-overflow-ne', 'accessor-overflow-address',
         'accessor-overflow-flags', 'accessor-overflow-condition', 'accessor-overflow-interrupted',
         'accessor-overflow-family', 'accessor-overflow-width', 'accessor-csel-unknown', 'accessor-csel-wrong-flags', 'accessor-wrong-converter',
         'accessor-partial-btf-start', 'accessor-partial-btf-stop', 'accessor-concurrent', 'accessor-converter', 'accessor-tail-converter', 'accessor-thunk',
         'accessor-add-mov', 'accessor-task-conflict', 'accessor-unknown-return', 'accessor-branch-outside',
         'accessor-thunk-cycle', 'accessor-execute-error', 'accessor-nonadjacent', 'accessor-real', 'accessor-branch', 'accessor-ambiguous',
         'accessor-truncated', 'accessor-width', 'accessor-symbol-missing', 'accessor-size-missing',
         'accessor-size-offset', 'accessor-size-overflow', 'accessor-read-error', 'accessor-bad-btf',
         'sysfs', 'kernel-symbols', 'field-only', 'invalid', 'truncated', 'width',
         'bounds', 'ambiguous', 'read-error', 'symbol-missing', 'symbol-error',
         'reverse-range', 'large-range', 'errptr-range', 'kernel-read-failure',
         'concurrent', 'live-function-missing', 'live-execute-failure', 'live-errptr',
         'live-variable-null', 'live-variable-address-errptr', 'live-variable-errptr', 'live-strings-failure', 'live-strings-errptr',
         'live-nonempty-strings', 'live-type-errptr',
         'caps-ok', 'caps-zero', 'caps-nonadjacent', 'caps-overlap', 'caps-missing-output',
         'caps-no-unlock', 'caps-truncated', 'caps-read-error', 'caps-symbol-missing']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--case', action='append', default=[])
    parser.add_argument('--btf', type=Path, action='append', default=[])
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = [HERE / 'test_layout.cpp',
               ROOT / 'runtime/maplesu-sdk/sdk/src/module_base/module_base_kernel_btf_resolver.cpp',
               ROOT / 'runtime/maplesu-sdk/sdk/src/kernel_offsets/task_struct.cpp',
               ROOT / 'runtime/maplesu-sdk/sdk/src/kernel_offsets/cred.cpp',
               ROOT / 'runtime/ultra/policy/kernel_layout.cpp']
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=32m',
              '--mount', f'type=bind,source={ROOT},target=/repo,readonly',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    include = [HERE, ROOT / 'runtime/maplesu-sdk/sdk/include',
               ROOT / 'runtime/maplesu-sdk/include', ROOT / 'runtime/ultra/policy']
    compile_cmd = [*docker, 'g++', '-std=c++20', '-O1', '-g', '-pthread',
                   '-ffunction-sections', '-fdata-sections',
                   *['-I/repo/' + path.relative_to(ROOT).as_posix() for path in include],
                   *['/repo/' + path.relative_to(ROOT).as_posix() for path in sources],
                   '-Wl,--gc-sections,--wrap=fopen,--wrap=fread,--wrap=ferror',
                   '-o', 'layout-test']
    if args.sanitize:
        compile_cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie']
    commands = [('compile', compile_cmd)]
    commands += [(case, [*docker, './layout-test', case]) for case in (args.case or CASES)]
    commands += [(f'real-{index}', [*docker, './layout-test', 'real',
                  '/repo/' + btf.resolve().relative_to(ROOT).as_posix()])
                 for index, btf in enumerate(args.btf)]
    identities = [Path(__file__).resolve(), HERE / 'kernel_module_kit_umbrella.h', *sources,
                  ROOT / 'runtime/maplesu-sdk/sdk/include/maplesu_kernel_layout_private.h',
                  ROOT / 'runtime/ultra/policy/kernel_layout.h',
                  HERE / 'fixtures/android12-5.10.h', HERE / 'fixtures/android12-5.10.json',
                  HERE / 'fixtures/seccomp-real.h', HERE / 'fixtures/seccomp-real.json',
                  ROOT / 'runtime/maplesu-sdk/include/module_err_def.h',
                  *[btf.resolve() for btf in args.btf]]
    source_records = [{'path': str(path.relative_to(ROOT)),
                       'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                      for path in identities]
    rows = []
    for name, command in commands:
        done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(done.stdout + done.stderr, encoding='utf-8')
        rows.append({'name': name, 'argv': command, 'exit': done.returncode})
        print(done.stdout + done.stderr, end='')
        if done.returncode:
            break
    unchanged = all(hashlib.sha256((ROOT / row['path']).read_bytes()).hexdigest() == row['sha256']
                    for row in source_records)
    receipt = {'image': IMAGE, 'sanitize': args.sanitize, 'commands': rows,
               'passed': unchanged and len(rows) == len(commands) and all(row['exit'] == 0 for row in rows),
               'sourcesUnchanged': unchanged, 'sources': source_records}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if receipt['passed'] else 1)


if __name__ == '__main__':
    main()
