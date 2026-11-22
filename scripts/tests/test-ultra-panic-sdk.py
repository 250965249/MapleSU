"""Run the actual repaired SDK IR on a native host with mocked I/O boundaries."""
import argparse
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--build", type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
build = args.build.resolve()
for ordinal, target in [(23, "request"), (25, "executor")]:
    ir = (build / ("m%03d.patched.ll" % ordinal)).read_text()
    ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
    ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
    ir = re.sub(r'target datalayout = .*\n', '', ir)
    ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
    if target == "request":
        ir += """
define i64 @test_request(i64 %address, i32 %size, ptr %out) {
 %result = call i64 @_ZN13kernel_module30unsafe_request_kernel_exec_memEmjRm(i64 %address, i32 %size, ptr %out)
 ret i64 %result
}
"""
    else:
        ir += """
define i64 @test_executor(ptr %code, i32 %size, ptr %out) {
 %result = call fastcc i64 @_ZN13kernel_moduleL22__exec_kernel_asm_funcEPKhjRm(ptr %code, i32 %size, ptr %out)
 ret i64 %result
}
"""
    ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
    (build / (target + '.host.ll')).write_text(ir)
script = f"""
set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
for target in request executor; do
 $C/bin/clang++ -c -ffunction-sections -fdata-sections $target.host.ll -o $target.host.o
 define=
 if [ $target = request ]; then define=-DMAPLESU_TEST_REQUEST; fi
 $C/bin/clang++ -std=c++17 -stdlib=libc++ $define -Wl,--gc-sections \
  -Wl,--wrap=syscall -Wl,--wrap=getresuid -Wl,--wrap=getresgid \
  -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
  /repo/runtime/tests/pro_panic_sdk_test.cpp $target.host.o -o $target.test
 ./$target.test
done
$C/bin/clang++ -std=c++17 -stdlib=libc++ -Wall -Wextra -Werror \
 -I/repo/runtime/maplesu-sdk/include -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
 /repo/runtime/tests/pro_su_lifetime_test.cpp /repo/runtime/ultra/authorization/su_allowlist_writer.cpp -o lifetime.test
./lifetime.test
"""
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={root},target=/repo,readonly', '--mount', f'type=bind,source={build},target=/case', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(build / 'native-regression.log').write_text(result.stdout + result.stderr)
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
