"""Replay concurrent allocations through the recovered production SDK request IR."""
import argparse
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ir', type=Path, required=True)
parser.add_argument('--build', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
build = args.build.resolve()
build.mkdir(parents=True, exist_ok=True)
ir = args.ir.read_text(encoding='utf-8-sig')
ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
ir = re.sub(r'target datalayout = .*\n', '', ir)
ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
ir += '''
define i64 @test_alloc(i32 %size, ptr %out) {
 %result = call i64 @_ZN13kernel_module31unsafe_request_kernel_alloc_memEjRm(i32 %size, ptr %out)
 ret i64 %result
}
'''
(build / 'request.host.ll').write_text(ir, encoding='utf-8')
script = '''set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -c -ffunction-sections -fdata-sections request.host.ll -o request.host.o
context=
if test -f /repo/runtime/ultra/authorization/request_context.cpp; then
 context=/repo/runtime/ultra/authorization/request_context.cpp
fi
$C/bin/clang++ -std=c++17 -stdlib=libc++ -pthread -I/repo/runtime/maplesu-sdk/include \
 -ffunction-sections -fdata-sections -Wl,--gc-sections \
 -Wl,--wrap=syscall -Wl,--wrap=getresuid -Wl,--wrap=getresgid \
 -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
 /repo/runtime/tests/pro_request_context_test.cpp $context request.host.o -o request-context.test
./request-context.test
'''
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
    '--mount', f'type=bind,source={root},target=/repo,readonly',
    '--mount', f'type=bind,source={build},target=/case', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(build / 'request-context.log').write_text(result.stdout + result.stderr, encoding='utf-8')
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
