"""Compile and run the actual offset-cache TU once, with bounded real-file fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = [ROOT / 'runtime/maplesu-sdk/sdk/src/module_base/module_base_offset_cache.cpp',
               HERE / 'test_cache.cpp', ROOT / 'runtime/maplesu-sdk/include/module_err_def.h', Path(__file__)]
    inputs = []
    for source in sources:
        data = source.read_bytes()
        (out / source.name).write_bytes(data)
        inputs.append(dict(path=str(source), snapshot=source.name, bytes=len(data),
                           sha256=hashlib.sha256(data).hexdigest()))
    (out / 'kernel_module_kit_umbrella.h').write_text(
        '#pragma once\n#include <cstdint>\n#include "module_err_def.h"\n#define FOLDER_HEAD_ROOT_KEY_LEN 16\n',
        encoding='utf-8')
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=32m', '--tmpfs', '/data:rw,size=1m',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    commands = []
    for name, command in [
        ('compile', [*docker, 'g++', '-std=c++20', '-O1', '-I/work',
                     'module_base_offset_cache.cpp', 'test_cache.cpp', '-o', 'cache-test']),
        ('test', [*docker, './cache-test']),
    ]:
        result = subprocess.run(command, capture_output=True)
        (out / (name + '.stdout.log')).write_bytes(result.stdout)
        (out / (name + '.stderr.log')).write_bytes(result.stderr)
        commands.append(dict(name=name, argv=command, exitCode=result.returncode))
        print(name, result.returncode, (result.stdout + result.stderr).decode('utf-8', errors='replace'), flush=True)
        if result.returncode:
            break
    unchanged = all(hashlib.sha256(Path(row['path']).read_bytes()).hexdigest() == row['sha256'] for row in inputs)
    passed = len(commands) == 2 and all(row['exitCode'] == 0 for row in commands) and unchanged
    (out / 'receipt.json').write_text(json.dumps(dict(inputs=inputs, commands=commands,
        inputsUnchanged=unchanged, passed=passed, scope='host cache reader; no SDK/APK or device'), indent=2) + '\n', encoding='utf-8')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
