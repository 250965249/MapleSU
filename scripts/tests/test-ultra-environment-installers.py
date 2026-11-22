"""Run real SDK installer entry points with synthetic identity and SELinux xattrs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--candidate', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--baseline', action='store_true')
p.add_argument('--ordinal', type=int, choices=(49, 50, 52))
p.add_argument('--expected-helper', type=Path)
a = p.parse_args()
repo = Path(__file__).resolve().parents[2]
out = a.out.resolve()
out.mkdir(parents=True, exist_ok=True)
specs = [
    (49, '_ZN7maplesu3sdk24unsafe_install_resetpropEv', '/data/ABCDEFGHIJKLMNOPA/resetprop', 400568),
    (50, '_ZN7maplesu3sdk27unsafe_install_webui_loaderEv', '/data/ABCDEFGHIJKLMNOPA/modules/webui_loader', 766320),
    (52, '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv', '/data/ABCDEFGHIJKLMNOP/init', 1215088),
]
commands, inputs = [], []
for ordinal, symbol, path, size in specs:
    if a.ordinal is not None and ordinal != a.ordinal:
        continue
    source = a.candidate / f'm{ordinal:03d}.{"baseline" if a.baseline else "patched"}.ll'
    ir = source.read_text()
    if ordinal == 52:
        payload = re.search(r'^@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE = [^\n]*?\[(\d+) x i(\d+)\]', ir, re.M)
        assert payload, 'Missing embedded bootstrap initializer'
        size = int(payload[1]) * int(payload[2]) // 8
    ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
    ir = re.sub(r'target datalayout = .*\n', '', ir)
    ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
    ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
    ir += f'\ndefine i64 @test_install() {{\n %result = call i64 @{symbol}()\n ret i64 %result\n}}\n'
    ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
    target = f'm{ordinal:03d}'
    reference = ''
    if ordinal == 52 and a.expected_helper:
        helper = a.expected_helper.read_bytes()
        assert len(helper) == size
        # The actual installer personalizes the in-memory payload before its
        # atomic publish. Model that one documented credential slot, then compare
        # every output byte; the fixture credential is not a device secret.
        key = b'ABCDEFGHIJKLMNOP0123456789ABCDEFGHIJKLMNOP012345\0'
        slot = 182886
        helper = helper[:slot] + key + helper[slot + len(key):]
        (out / 'expected-helper.bin').write_bytes(helper)
        reference = ' /case/expected-helper.bin'
    (out / (target + '.host.ll')).write_text(ir)
    publisher = '/repo/runtime/ultra/upgrade/executable_publish.cpp' if '@maplesu_publish_executable(' in ir else ''
    commands.append(f'''$C/bin/clang++ -c -ffunction-sections -fdata-sections {target}.host.ll -o {target}.host.o
$C/bin/clang++ -stdlib=libc++ -std=c++17 -Wall -Wextra -Werror -I/repo/runtime/maplesu-sdk/include \\
 -Wl,--gc-sections -Wl,--wrap=setxattr -Wl,--wrap=fsetxattr -Wl,--wrap=write -Wl,--wrap=fopen -Wl,--wrap=openat -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \\
 /repo/runtime/tests/pro_environment_installers_test.cpp {target}.host.o {publisher} -o {target}.test
./{target}.test {path} repeat {size}{reference} || failed=1
./{target}.test {path} open_failure {size}{reference} || failed=1
./{target}.test {path} write_failure {size}{reference} || failed=1''')
    inputs.append(dict(ordinal=ordinal, sha256=hashlib.sha256(source.read_bytes()).hexdigest()))
script = 'set -eu\ncd /case\nC=/opt/ddk/clang/clang-r510928\nfailed=0\n' + '\n'.join(commands) + '\nexit $failed\n'
result = subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount',
    f'type=bind,source={repo},target=/repo,readonly', '--mount', f'type=bind,source={out},target=/case',
    '--entrypoint', 'sh', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
output = result.stdout + result.stderr
(out / 'regression.log').write_text(output)
(out / 'regression.json').write_text(json.dumps(dict(exitCode=result.returncode, inputs=inputs,
    syntheticRootAndSelinux=True, deviceAcceptance=False,
    expectedHelperSha256=hashlib.sha256(a.expected_helper.read_bytes()).hexdigest() if a.expected_helper else None,
    sourceSha256={n:hashlib.sha256((repo / n).read_bytes()).hexdigest() for n in
                 ['scripts/tests/test-ultra-environment-installers.py', 'runtime/tests/pro_environment_installers_test.cpp',
                  'runtime/ultra/upgrade/executable_publish.cpp', 'runtime/ultra/upgrade/executable_publish.h']}), indent=2) + '\n')
print(output)
raise SystemExit(result.returncode)
