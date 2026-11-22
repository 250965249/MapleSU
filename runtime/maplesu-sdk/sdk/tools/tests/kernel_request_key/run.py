#!/usr/bin/env python3
"""Exercise the production request sender and identity with a captured transport."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
SDK = ROOT / 'runtime/maplesu-sdk/sdk'
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--suite', choices=['legacy', 'v2', 'read'], default='legacy')
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--red-baseline', action='store_true', help='Skip only dangerous legacy WRITE user pointers on the old TU')
    parser.add_argument('--ndk', action='store_true', help='Compile this production TU using its manifest Android profile')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    # Only the unrelated umbrella and memory declarations are replaced.
    (out / 'kernel_module_kit_umbrella.h').write_text('#pragma once\n#include "module_err_def.h"\n', encoding='utf-8')
    (out / 'module_base_kernel_mem.h').write_text('#pragma once\nnamespace kernel_module { uint32_t get_page_size(); }\n', encoding='utf-8')
    prefix = '/repo/runtime/maplesu-sdk/'
    source_paths = [
        HERE / {'legacy': 'test_key.cpp', 'v2': 'test_v2.cpp', 'read': 'test_read.cpp'}[args.suite],
        ROOT / 'runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp',
        ROOT / 'runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp',
        ROOT / 'runtime/maplesu-sdk/sdk/include/module_base_kernel_request.h',
        ROOT / 'runtime/maplesu-sdk/include/module_err_def.h',
        ROOT / 'runtime/maplesu-sdk/sdk/include/maplesu_request_private.h',
        ROOT / 'runtime/ultra/authorization/request_protocol.h',
    ]
    inputs = [Path(__file__).resolve(), *source_paths]
    if args.ndk:
        inputs += [SDK / 'manifest/0023_module_base_kernel_request.o.json', SDK / 'tools/sdk_common.py']
    def identity(path):
        raw = path.read_bytes()
        return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    before = []
    for path in inputs:
        raw = path.read_bytes()
        row = identity(path)
        snapshot = out / 'inputs' / path.relative_to(ROOT)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(raw)
        row['snapshot'] = str(snapshot.relative_to(out))
        before.append(row)
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=32m',
              '-e', 'ASAN_OPTIONS=detect_leaks=1', '-e', 'UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1',
              *(['-e', 'MAPLESU_BOUNDS_RED=1'] if args.red_baseline else []),
              '--mount', f'type=bind,source={ROOT},target=/repo,readonly',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    compile_cmd = [*docker, 'g++', '-std=c++20', '-O1', '-g', '-pthread',
                   *(['-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie'] if args.sanitize else []),
                   '-I/work', '-I' + prefix + 'sdk/include', '-I' + prefix + 'include',
                   *['/repo/' + path.relative_to(ROOT).as_posix() for path in source_paths[:3]],
                   '-Wl,--wrap=syscall,--wrap=getresuid,--wrap=getresgid,--wrap=__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW',
                   *(['-Wl,--wrap=getpid,--wrap=_Znwm'] if args.suite == 'read' else
                     ['-Wl,--wrap=_Znwm'] if args.suite == 'v2' else []),
                   '-o', 'key-test']
    rows = []
    def run(name, command):
        command = list(map(str, command))
        done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
        output = done.stdout + done.stderr
        (out / (name + '.log')).write_text(output, encoding='utf-8')
        rows.append({'name': name, 'argv': command, 'exit': done.returncode})
        if name in ('compile', 'test', 'compiler-version', 'ndk-version', 'ndk-compile'):
            print(output, end='')
        return done
    run('image', ['docker', 'image', 'inspect', IMAGE])
    run('compiler-version', [*docker, 'g++', '--version'])
    dependency_paths = set()
    for index, path in enumerate(source_paths[:3]):
        result = run('dependencies-' + str(index), [*docker, 'g++', '-std=c++20', '-pthread',
            '-I/work', '-I' + prefix + 'sdk/include', '-I' + prefix + 'include', '-M',
            '/repo/' + path.relative_to(ROOT).as_posix()])
        if result.returncode == 0:
            dependency_paths.update(result.stdout.replace('\\\n', ' ').split(':', 1)[1].split())
    dependencies = []
    names = sorted(dependency_paths)
    for index in range(0, len(names), 80):
        result = run('dependency-hashes-' + str(index // 80), [*docker, 'sha256sum', '--', *names[index:index + 80]])
        for line in result.stdout.splitlines():
            digest, name = line.split(None, 1)
            dependencies.append({'path': name, 'sha256': digest})
    for name, command in [('compile', compile_cmd), ('test', [*docker, './key-test'])]:
        done = run(name, command)
        if done.returncode:
            break
    ndk = None
    if args.ndk:
        sys.path.insert(0, str(SDK / 'tools'))
        import sdk_common as S
        entry = json.loads((SDK / 'manifest/0023_module_base_kernel_request.o.json').read_text(encoding='utf-8'))
        compiler = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR / 'clang++.exe'
        flags = S.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        run('ndk-version', [compiler, '--version'])
        target = out / 'module_base_kernel_request.o'
        depfile = out / 'ndk.d'
        done = run('ndk-compile', [compiler, *flags, '-I', SDK.parent / 'include', '-I', SDK / 'include',
            '-MD', '-MF', depfile, '-MT', 'request-object', '-c', source_paths[1], '-o', target])
        ndk_dependencies = []
        if depfile.exists():
            text = depfile.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1]
            for name in re.findall(r'(?:\\.|[^\s])+', text):
                path = Path(name.replace('\\ ', ' '))
                ndk_dependencies.append(identity(path))
        ndk = {'flagsProfile': entry['flagsProfile'], 'compiler': identity(compiler),
               'dependencies': ndk_dependencies, 'exit': done.returncode,
               'object': identity(target) if target.exists() else None}
    unchanged = all(identity(Path(row['path'])) == {key: row[key] for key in ('path', 'bytes', 'sha256')}
                    for row in before)
    repo_dependencies_unchanged = all(hashlib.sha256((ROOT / row['path'][6:]).read_bytes()).hexdigest() == row['sha256']
                                     for row in dependencies if row['path'].startswith('/repo/'))
    test_log = (out / 'test.log').read_text(encoding='utf-8') if (out / 'test.log').exists() else ''
    receipt = {'image': IMAGE, 'suite': args.suite, 'sanitize': args.sanitize,
               'redBaseline': args.red_baseline, 'dangerousWriteUserPointerCasesSkipped': args.red_baseline,
               'commands': rows, 'passed': all(row['exit'] == 0 for row in rows) and unchanged
                   and repo_dependencies_unchanged and 'runtime error:' not in test_log
                   and 'ERROR: AddressSanitizer:' not in test_log,
               'sources': before, 'sourcesUnchanged': unchanged, 'dependencies': dependencies,
               'repoDependenciesUnchanged': repo_dependencies_unchanged, 'ndk': ndk,
               'generatedHeaders': [identity(out / name) for name in ('kernel_module_kit_umbrella.h', 'module_base_kernel_mem.h')],
               'deviceAccess': False, 'officialArtifactsWritten': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if receipt['passed'] else 1)


if __name__ == '__main__':
    main()
