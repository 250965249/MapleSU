"""Actual source SU handshake and pre-fork TLS regression; no device operations."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--cold-control', action='store_true', help='Remove only the pre-fork call to reproduce child registration.')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
build = args.build.resolve()
build.mkdir(parents=True, exist_ok=True)
docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
          '--tmpfs', '/tmp:rw,size=64m', '--mount', f'type=bind,source={repo},target=/repo,readonly',
          '--mount', f'type=bind,source={build},target=/case', '-w', '/case',
          'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e']
flags = ['g++', '-std=c++17', '-O2', '-ffunction-sections', '-fdata-sections',
         '-I/case', '-I/repo/runtime/maplesu-sdk/sdk/include', '-I/repo/runtime/maplesu-sdk/include']
rows = []


def run(name, command):
    done = subprocess.run(docker + command, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', timeout=90)
    output = done.stdout + done.stderr
    (build / (name + '.log')).write_text(output, encoding='utf-8')
    rows.append(dict(name=name, exitCode=done.returncode, output=output))
    print(name, done.returncode, output.strip(), flush=True)
    return done.returncode


wrapped = ['getuid', 'geteuid', 'getresuid', 'getresgid', 'opendir', 'dirfd', 'closedir',
           'readdir', 'readlinkat', 'close', 'fcntl', 'ioctl', 'syscall']
assert run('su-compile', flags + ['/repo/runtime/maplesu-sdk/sdk/src/payload/su/src/root_grant.cpp',
    '/repo/runtime/tests/ultra_sdk_su_handshake_test.cpp', *[f'-Wl,--wrap={x}' for x in wrapped],
    '-o', 'su-handshake']) == 0
for mode in range(10):
    assert run(f'su-{mode}', ['./su-handshake', str(mode)]) == 0

# The request TU uses no generated assembly here. Keep the unrelated umbrella
# out, while retaining its real request header, TLS types, reset and mode setter.
(build / 'kernel_module_kit_umbrella.h').write_text(
    '#pragma once\n#include "module_err_def.h"\n#include "module_base_kernel_mem.h"\n'
    'namespace kernel_module { uint32_t get_page_size(); }\n', encoding='utf-8')
transport = '/repo/runtime/maplesu-sdk/sdk/src/maplesu/process/fork_pipe.cpp'
if args.cold_control:
    source = (repo / transport.removeprefix('/repo/')).read_text(encoding='utf-8')
    call = '    if (maplesu_request_fork_prepare) maplesu_request_fork_prepare();\n'
    assert source.count(call) == 1
    (build / 'fork-pipe-cold.cpp').write_text(source.replace(call, ''), encoding='utf-8')
    transport = '/case/fork-pipe-cold.cpp'
assert run('tls-compile', flags + [
    '-I/repo/runtime/maplesu-sdk/sdk/src/maplesu/process', transport,
    '/repo/runtime/tests/ultra_sdk_request_fork_tls_test.cpp',
    '-Wl,--wrap=__cxa_thread_atexit', '-Wl,--gc-sections', '-pthread', '-o', 'fork-tls']) == 0
tls_error = run('tls-run', ['./fork-tls'])
receipt = dict(actualSource=True, coldControl=args.cold_control, suCases=10,
               tlsExitCode=tls_error, deviceOperations=0, rows=rows)
(build / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
raise SystemExit(tls_error)
