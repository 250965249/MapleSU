"""Validate optional runtime-scoped caching once; preserve the historical disk suite."""
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


def identity(path):
    data = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = SDK / 'src/module_base/module_base_offset_cache.cpp'
    paths = [source, HERE / 'test_scope.cpp', Path(__file__).resolve(),
             SDK / 'src/kernel_offsets/offsets_internal.h', SDK.parent / 'include/module_err_def.h']
    before = [identity(path) for path in paths]
    for path in paths:
        (out / path.name).write_bytes(path.read_bytes())
    (out / 'kernel_module_kit_umbrella.h').write_text(
        '#pragma once\n#include <cstdint>\n#include "module_err_def.h"\n', encoding='utf-8')
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=32m', '--tmpfs', '/data:rw,size=1m',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    commands = [('compile', [*docker, 'g++', '-std=c++20', '-O1', '-g', '-pthread', '-I/work',
                            'module_base_offset_cache.cpp', 'test_scope.cpp',
                            '-Wl,--wrap=getpid,--wrap=_Znwm', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-no-pie', '-o', 'cache-scope-test']),
                ('test', [*docker, './cache-scope-test'])]
    manifest = compiler = None
    if args.ndk:
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(SDK / 'tools'))
        import sdk_common as common
        manifest_path = SDK / 'manifest/0038_module_base_offset_cache.o.json'
        entry = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
        manifest = identity(manifest_path)
        compiler_path = common.DEFAULT_NDK / common.TOOLCHAIN_SUBDIR / 'clang++.exe'
        compiler = identity(compiler_path)
        paths += [manifest_path, SDK / 'tools/sdk_common.py']
        before += [identity(path) for path in paths[-2:]]
        flags = common.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        commands.append(('ndk', list(map(str, [compiler_path, *flags,
            '-I', SDK.parent / 'include', '-I', SDK / 'include', '-MD', '-MF', out / 'ndk.d',
            '-MT', 'offset-cache-object', '-c', source, '-o', out / 'offset-cache.o']))))
    rows = []
    for name, argv in commands:
        done = subprocess.run(argv, cwd=SDK, capture_output=True, text=True, encoding='utf-8', errors='replace')
        text = done.stdout + done.stderr
        (out / (name + '.log')).write_text(text, encoding='utf-8')
        rows.append({'name': name, 'argv': argv, 'exit': done.returncode,
                     'sanitizerDiagnostic': 'runtime error:' in text or 'ERROR: AddressSanitizer:' in text})
        print(text, end='')
        if done.returncode:
            break
    dependencies = []
    depfile = out / 'ndk.d'
    if depfile.exists():
        text = depfile.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1]
        for token in re.findall(r'(?:\\.|[^\s])+', text):
            path = Path(token.replace('\\ ', ' ').replace('\\:', ':').replace('\\#', '#'))
            dependencies.append(identity(path if path.is_absolute() else SDK / path))
    stable = before == [identity(path) for path in paths]
    passed = stable and len(rows) == len(commands) and all(
        row['exit'] == 0 and not row['sanitizerDiagnostic'] for row in rows)
    receipt = {'passed': passed, 'sourcesUnchanged': stable, 'sources': before, 'commands': rows,
               'manifest': manifest, 'compiler': compiler, 'dependencies': dependencies,
               'scope': 'Actual cache TU; real filesystem/fork plus controlled identity/PID/allocation seams. No kernel operation, official SDK/APK or device.',
               'historicalDiskSuiteRepeated': False, 'deviceOperations': False, 'formalArtifactsChanged': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
