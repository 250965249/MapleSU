"""Replay the SDK's real embedded executable writer with an executing old inode."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--su-ir', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--full', action='store_true')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
ir = args.su_ir.read_text()
writer = re.search(r'define internal fastcc (?:noundef )?i64 @([^ (]*write_su_exec[^ (]*)', ir)[1]
ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
ir = re.sub(r'target datalayout = .*\n', '', ir)
ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
ir += f'\ndefine i64 @test_write(ptr %path) {{\n %result = call fastcc i64 @{writer}(ptr %path)\n ret i64 %result\n}}\n'
ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
(out / 'su-writer.host.ll').write_text(ir)
publisher = '/repo/runtime/ultra/upgrade/executable_publish.cpp' if '@maplesu_publish_executable(' in ir else ''
script = '''set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -c -ffunction-sections -fdata-sections su-writer.host.ll -o su-writer.host.o
$C/bin/clang++ -stdlib=libc++ -std=c++17 -Wall -Wextra -Werror -I/repo/runtime/maplesu-sdk/include \\
 -Wl,--gc-sections -Wl,--wrap=fsetxattr -Wl,--wrap=fchmod -Wl,--wrap=write -Wl,--wrap=fsync -Wl,--wrap=close -Wl,--wrap=renameat -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \\
 /repo/runtime/tests/pro_environment_upgrade_test.cpp su-writer.host.o -o upgrade.test
failed=0
for scenario in fresh busy; do ./upgrade.test "$scenario" || failed=1; done
exit $failed
'''
script = script.replace('su-writer.host.o -o', 'su-writer.host.o ' + publisher + ' -o')
if publisher:
    script = script.replace('-Wall -Wextra', '-DMAPLESU_ATOMIC_PUBLISH -Wall -Wextra')
if args.full:
    assert publisher, '--full requires the patched SDK writer'
    script = script.replace('fresh busy;', 'fresh busy repeat concurrent stale_stage short_write interrupted write_failure zero_write sync_failure directory_sync_failure close_failure rename_failure label_failure mode_failure symlink hardlink foreign_owner;')
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={repo},target=/repo,readonly', '--mount', f'type=bind,source={out},target=/case',
    '--entrypoint', 'sh', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
output = result.stdout + result.stderr
(out / 'regression.log').write_text(output)
(out / 'regression.json').write_text(json.dumps(dict(exitCode=result.returncode,
    inputSha256=hashlib.sha256(args.su_ir.read_bytes()).hexdigest(), deviceAcceptance=False), indent=2) + '\n')
print(output)
raise SystemExit(result.returncode)
