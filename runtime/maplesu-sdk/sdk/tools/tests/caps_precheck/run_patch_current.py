#!/usr/bin/env python3
"""Exercise the actual m072 TU with inert assembler, kernel and affinity seams."""
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
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = {
        Path(__file__).resolve(): 'run_patch_current.py',
        HERE / 'test_patch_current.cpp': 'test_patch_current.cpp',
        HERE / 'patch_current/kernel_module_kit_umbrella.h': 'include/kernel_module_kit_umbrella.h',
        SDK / 'src/patch/patch_current.cpp': 'patch_current.cpp',
        SDK / 'include/default_modules_module_root_patch_base.h': 'include/default_modules_module_root_patch_base.h',
        SDK / 'include/maplesu_caps_private.h': 'include/maplesu_caps_private.h',
        SDK.parent / 'include/kernel_offsets/cred.h': 'include/kernel_offsets/cred.h',
        SDK.parent / 'include/module_err_def.h': 'include/module_err_def.h',
        ROOT / 'runtime/ultra/authorization/request_protocol.h': 'include/request_protocol.h',
    }
    sources = []
    for source, target in paths.items():
        destination = out / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
        sources.append({**identity(source), 'snapshot': target})
    private_header = out / 'include/maplesu_request_private.h'
    private_header.write_text('''#pragma once
#include "module_err_def.h"
#include "request_protocol.h"
namespace kernel_module {
bool maplesu_request_owner_mode();
KModErr maplesu_request_credential_channel(bool&, uint64_t&);
KModErr maplesu_request_owner_root();
KModErr maplesu_request_owner_task_state();
KModErr maplesu_request_owner_caps(const maplesu_caps_v3&);
KModErr maplesu_execute_legacy_credential_frame(const uint8_t*, uint32_t, uint64_t&);
}
''', encoding='utf-8')
    sources.append({**identity(SDK / 'include/maplesu_request_private.h'), 'snapshot': None})
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
              '--read-only', '--tmpfs', '/tmp:rw,size=32m',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    commands = [
        ('compile', [*docker, 'g++', '-std=c++20', '-O1', '-g', '-I/work/include',
                     'test_patch_current.cpp', 'patch_current.cpp',
                     '-Wl,--wrap=sched_getaffinity', '-fsanitize=address,undefined',
                     '-fno-omit-frame-pointer', '-no-pie', '-o', 'patch-current-test']),
        ('test', [*docker, './patch-current-test']),
    ]
    manifest = compiler_identity = None
    if args.ndk:
        sys.path.insert(0, str(SDK / 'tools'))
        import sdk_common as common
        manifest_path = SDK / 'manifest/0072_patch_current.o.json'
        entry = json.loads(manifest_path.read_text(encoding='utf-8'))
        manifest = identity(manifest_path)
        sources.append({**manifest, 'snapshot': None})
        compiler = common.DEFAULT_NDK / common.TOOLCHAIN_SUBDIR / 'clang++.exe'
        compiler_identity = identity(compiler)
        flags = common.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        commands.append(('ndk', list(map(str, [compiler, *flags,
            '-I', SDK.parent / 'include', '-I', SDK / 'include',
            '-MD', '-MF', out / 'ndk.d', '-MT', 'patch-current-object',
            '-c', out / 'patch_current.cpp', '-o', out / 'patch_current.o']))))
        sources.append({**identity(SDK / 'tools/sdk_common.py'), 'snapshot': None})
    rows = []
    for name, argv in commands:
        done = subprocess.run(argv, cwd=SDK, capture_output=True, text=True,
                              encoding='utf-8', errors='replace')
        output = done.stdout + done.stderr
        (out / (name + '.log')).write_text(output, encoding='utf-8')
        rows.append(dict(name=name, argv=argv, exit=done.returncode,
                         sanitizer_diagnostic='runtime error:' in output or 'ERROR: AddressSanitizer:' in output))
        print(output, end='')
        if done.returncode:
            break
    stable = all(identity(Path(row['path'])) == {key: row[key] for key in ('path', 'bytes', 'sha256')}
                 for row in sources)
    dependencies = []
    depfile = out / 'ndk.d'
    if depfile.exists():
        text = depfile.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1]
        for name in re.findall(r'(?:\\.|[^\s])+', text):
            path = Path(name.replace('\\ ', ' ').replace('\\:', ':').replace('\\#', '#'))
            if not path.is_absolute():
                path = SDK / path
            dependencies.append(identity(path))
    passed = stable and len(rows) == len(commands) and all(
        row['exit'] == 0 and not row['sanitizer_diagnostic'] for row in rows)
    receipt = dict(sources=sources, sourcesUnchanged=stable, image=IMAGE,
                   manifest=manifest, compiler=compiler_identity,
                   dependencies=dependencies, commands=rows, passed=passed,
                   scope='Actual m072 TU control flow; stub assembler records emissions; no real instruction execution, kernel memory, archive, device or rollback validation')
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
