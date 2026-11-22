"""Offline host regression; root, package and proc inputs are isolated fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from verify_sdk_member_diff import parse_ar

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--ndk', type=Path, required=True)
parser.add_argument('--archive', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
build = args.build.resolve()
build.mkdir(parents=True, exist_ok=True)
relative = build.relative_to(root).as_posix()
# Retarget the actual delivered patch-engine IR, not a merely similar Lite source.
members = parse_ar(str(args.archive))['members']
member = next(m for m in members if m['name'] == 'parasite_patch_elf.o')
data = args.archive.read_bytes()[member['body_offset']:member['body_offset'] + member['size']]
(build / 'patch-engine.bc').write_bytes(data)
clang = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
subprocess.run([str(clang), '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir',
    str(build / 'patch-engine.bc'), '-o', str(build / 'patch-engine.ll')], check=True, capture_output=True)
ir = (build / 'patch-engine.ll').read_text()
ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
ir = re.sub(r'target datalayout = .*\n', '', ir)
ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
ir = ir.replace('@stat(', '@maplesu_host_android_stat(')
ir = ir.replace('@__sF = external global [0 x %struct.__sFILE], align 8',
                '@stderr = external global ptr, align 8')
# Bionic stderr is __sF[2]; glibc exposes a FILE* global instead. Adapt only that boundary.
ir = re.sub(r'^(  )(%\d+) = (call [^\n]+?)ptr(?: noundef)? nonnull '
            r'getelementptr inbounds \(\[0 x %struct\.__sFILE\], ptr @__sF, i64 0, i64 2\)([^\n]*)$',
            lambda m: '  %host_stderr_' + m[2][1:] + ' = load ptr, ptr @stderr, align 8\n' +
            m[1] + m[2] + ' = ' + m[3] + 'ptr %host_stderr_' + m[2][1:] + m[4], ir, flags=re.M)
assert '@__sF' not in ir
(build / 'patch-engine.host.ll').write_text(ir)
script = f'''set -eu
C=/opt/ddk/clang/clang-r510928
cd /repo/{relative}
$C/bin/clang++ -c -ffunction-sections -fdata-sections patch-engine.host.ll -o patch-engine.host.o
$C/bin/clang++ -std=c++17 -stdlib=libc++ -Wall -Wextra -Werror -Wl,--export-dynamic -ldl -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \\
 -DMAPLESU_PARASITE_HOST_TEST -DMAPLESU_PARASITE_TIMEOUT_MS=1500 \\
 '-DMAPLESU_PARASITE_PROC_ROOT="/tmp/maplesu-parasite-test/proc"' \\
 '-DMAPLESU_PARASITE_PM="/tmp/maplesu-parasite-test/pm"' \\
 '-DMAPLESU_PARASITE_START="/tmp/maplesu-parasite-test/start.sh"' \\
 -I/repo/runtime/maplesu-sdk/include -I. \\
 /repo/runtime/tests/pro_parasite_sdk_test.cpp /repo/runtime/ultra/parasite/parasite_sdk.cpp \\
 patch-engine.host.o \\
 -o parasite.test
./parasite.test libmaplesu_su_env.so
python3 /repo/runtime/tests/pro_su_env_loader_test.py
'''
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={root},target=/repo', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(build / 'native-regression.log').write_text(result.stdout + result.stderr)
(build / 'native-regression.json').write_text(json.dumps({
    'passed': result.returncode == 0, 'archiveSha256': hashlib.sha256(args.archive.read_bytes()).hexdigest(),
    'patchEngineMemberSha256': hashlib.sha256(data).hexdigest(), 'patchEngine': 'delivered SDK IR retargeted to host',
    'checks': result.stdout.count('PASS '), 'network': 'none', 'deviceVerification': False,
}, indent=2) + '\n')
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
