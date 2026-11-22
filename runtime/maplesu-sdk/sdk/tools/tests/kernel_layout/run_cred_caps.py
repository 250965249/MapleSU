#!/usr/bin/env python3
"""Small production-TU capability regression; capture snapshots before compiling."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
CASES = ['accessor-ok', 'accessor-zero', 'accessor-nonadjacent',
         'accessor-missing-zero', 'accessor-missing-nonzero', 'accessor-read-error', 'accessor-symbol-error',
         'cap40', 'cap63', 'prctl-eperm', 'btf-ok', 'btf-zero', 'btf-error', 'status', 'snapshot']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--source', type=Path, help='Explicit captured cred.cpp baseline')
    parser.add_argument('--ndk', action='store_true', help='Compile captured TU with its manifest Android profile')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sources = {
        Path(__file__).resolve(): 'run_cred_caps.py',
        (args.source or ROOT / 'runtime/maplesu-sdk/sdk/src/kernel_offsets/cred.cpp').resolve(): 'cred.cpp',
        HERE / 'test_cred_caps.cpp': 'test_cred_caps.cpp',
        HERE / 'kernel_module_kit_umbrella.h': 'include/kernel_module_kit_umbrella.h',
        ROOT / 'runtime/maplesu-sdk/sdk/include/maplesu_kernel_layout_private.h': 'include/maplesu_kernel_layout_private.h',
        ROOT / 'runtime/maplesu-sdk/sdk/include/maplesu_caps_private.h': 'include/maplesu_caps_private.h',
        ROOT / 'runtime/maplesu-sdk/include/module_err_def.h': 'include/module_err_def.h',
        ROOT / 'runtime/maplesu-sdk/include/kernel_offsets/cred.h': 'include/kernel_offsets/cred.h',
        ROOT / 'runtime/maplesu-sdk/include/kernel_offsets/task_struct.h': 'include/kernel_offsets/task_struct.h',
    }
    identities = []
    for source, target in sources.items():
        data = source.read_bytes()
        snapshot = out / target
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(data)
        identities.append({'source': str(source), 'snapshot': target,
                           'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    docker = [shutil.which('docker') or 'docker', 'run', '--rm', '--pull', 'never',
              '--network', 'none', '--read-only', '--tmpfs', '/tmp:rw,size=32m',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    compile_cmd = [*docker, 'g++', '-std=c++20', '-O1', '-g',
                   '-ffunction-sections', '-fdata-sections', '-I/work/include',
                   'test_cred_caps.cpp', 'cred.cpp',
                   '-Wl,--gc-sections,--wrap=prctl,--wrap=fopen,--wrap=ferror,--wrap=fclose',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie',
                   '-o', 'cred-caps-test']
    rows = []
    done = subprocess.run(compile_cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    (out / 'compile.log').write_text(done.stdout + done.stderr, encoding='utf-8')
    rows.append({'name': 'compile', 'argv': compile_cmd, 'exit': done.returncode})
    print(done.stdout + done.stderr, end='')
    if done.returncode == 0:
        for case in CASES:
            command = [*docker, './cred-caps-test', case]
            done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
            (out / f'{case}.log').write_text(done.stdout + done.stderr, encoding='utf-8')
            result = {'name': case, 'argv': command, 'exit': done.returncode,
                      'sanitizer_diagnostic': 'runtime error:' in done.stderr}
            try:
                result['actual'] = json.loads(done.stdout)
            except ValueError:
                result['output'] = done.stdout + done.stderr
            rows.append(result)
            print(done.stdout + done.stderr, end='')
    ndk = None
    if args.ndk:
        sdk = ROOT / 'runtime/maplesu-sdk/sdk'
        sys.path.insert(0, str(sdk / 'tools'))
        import sdk_common as S
        manifest = sdk / 'manifest/0000_cred.o.json'
        entry = json.loads(manifest.read_text(encoding='utf-8'))
        compiler = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR / 'clang++.exe'
        flags = S.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        target = out / 'cred.o'
        depfile = out / 'ndk.d'
        command = list(map(str, [compiler, *flags, '-I', sdk.parent / 'include', '-I', sdk / 'include',
            '-MD', '-MF', depfile, '-MT', 'cred-object', '-c', out / 'cred.cpp', '-o', target]))
        done = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
        (out / 'ndk.log').write_text(done.stdout + done.stderr, encoding='utf-8')
        rows.append({'name': 'ndk', 'argv': command, 'exit': done.returncode})
        dependencies = []
        if depfile.exists():
            text = depfile.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1]
            for name in re.findall(r'(?:\\.|[^\s])+', text):
                path = Path(name.replace('\\ ', ' '))
                data = path.read_bytes()
                dependencies.append({'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        ndk = {'manifest': str(manifest), 'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
               'flagsProfile': entry['flagsProfile'], 'compiler': str(compiler),
               'compilerSha256': hashlib.sha256(compiler.read_bytes()).hexdigest(),
               'dependencies': dependencies,
               'objectSha256': hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None}
    unchanged = all(hashlib.sha256(Path(row['source']).read_bytes()).hexdigest() == row['sha256']
                    for row in identities)
    passed = unchanged and len(rows) == len(CASES) + 1 + int(args.ndk) and all(
        row['exit'] == 0 and not row.get('sanitizer_diagnostic') for row in rows)
    receipt = {'image': IMAGE, 'sources': identities, 'sourcesUnchanged': unchanged,
               'commands': rows, 'passed': passed, 'ndk': ndk,
               'scope': 'captured production source; host seams; no archive or device claim'}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
