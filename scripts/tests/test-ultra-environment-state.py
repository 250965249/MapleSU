"""Run the SDK's real environment getter and fork framing over boot-state fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from verify_sdk_member_diff import parse_ar

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--ir', type=Path, required=True)
p.add_argument('--archive', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--ndk', type=Path, required=True)
p.add_argument('--fixed', action='store_true')
p.add_argument('--jni', action='store_true')
a = p.parse_args()
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=True)
tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
blob = a.archive.read_bytes()
transport = next(m for m in parse_ar(str(a.archive))['members'] if m['name'] == 'maplesu_fork_helper.o')
bc = out / 'transport.bc'
bc.write_bytes(blob[transport['body_offset']:transport['body_offset'] + transport['size']])
ll = out / 'transport.ll'
subprocess.run([str(tool), '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', str(bc), '-o', str(ll)], check=True, capture_output=True)
for name, source in [('state', a.ir), ('transport', ll)]:
    ir = source.read_text(encoding='utf-8-sig')
    ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
    ir = re.sub(r'target datalayout = .*\n', '', ir)
    ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
    ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
    ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
    ir = ir.replace('@__errno(', '@__errno_location(')
    (out / f'{name}.host.ll').write_text(ir)
cases = {
    'running': 1, 'padded_receipt': 1, 'not_installed': 0, 'protection': 2,
    **dict.fromkeys(['missing_work', 'empty_work', 'stale_work', 'invalid_work', 'initializing',
        'legacy_early_receipt', 'disabled_protection', 'stale_protection', 'empty_boot', 'invalid_boot',
        'bad_flag', 'missing_flag', 'oversize_work', 'work_directory', 'missing_helper', 'missing_version',
        'root_error', 'boot_read_error', 'work_read_error', 'fork_error', 'pipe_error', 'wait_error',
        'child_exit', 'child_signal', 'reply_eof', 'reply_short', 'reply_corrupt', 'wait_mismatch'], 3),
    'wait_eintr': 1, 'read_eintr': 1,
}
extra = '/repo/runtime/ultra/boot/environment_state.cpp' if a.fixed else ''
options = '-std=c++17 -I/repo/runtime/maplesu-sdk/include'
if a.jni:
    assert a.fixed
    headers = out / 'host-include'
    (headers / 'sys').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include/jni.h', headers / 'jni.h')
    (headers / 'sys/system_properties.h').write_text('#pragma once\n#define PROP_VALUE_MAX 92\nextern "C" int __system_property_get(const char*, char*);\n')
    options = '-std=c++20 -DMAPLESU_TEST_JNI_RECEIPTS -I/case/host-include -isystem /repo/runtime/maplesu-sdk/include -isystem /repo/runtime/ultra/third_party/cJSON -isystem /repo/runtime/ultra/third_party/include'
    extra += ' /repo/runtime/ultra/third_party/cJSON/cJSON.cpp'
commands = '\n'.join(f'timeout 5s ./state.test {name} {state} || failed=1' for name, state in cases.items())
script = f'''set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
for name in state transport; do
 $C/bin/clang++ -c -ffunction-sections -fdata-sections $name.host.ll -o $name.host.o
done
$C/bin/clang++ {options} -stdlib=libc++ -ffunction-sections -fdata-sections -Wall -Wextra -Werror \\
 -Wl,--gc-sections -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \\
 -Wl,--wrap=fork -Wl,--wrap=pipe2 -Wl,--wrap=waitpid -Wl,--wrap=fopen -Wl,--wrap=open -Wl,--wrap=read \\
 /repo/runtime/tests/pro_environment_state_test.cpp {extra} state.host.o transport.host.o -o state.test
failed=0
{commands}
exit $failed
'''
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={ROOT},target=/repo,readonly', '--mount', f'type=bind,source={out},target=/case',
    '--entrypoint', 'sh', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
output = result.stdout + result.stderr
(out / 'regression.log').write_text(output)
(out / 'regression.json').write_text(json.dumps(dict(exitCode=result.returncode, cases=cases,
    irSha256=hashlib.sha256(a.ir.read_bytes()).hexdigest(), archiveSha256=hashlib.sha256(blob).hexdigest(),
    actualSdkGetter=True, actualSdkTransport=True, actualJniBridge=a.jni, syntheticKernel=True, deviceAcceptance=False), indent=2) + '\n')
print(output)
raise SystemExit(result.returncode)
