"""Check comm scan boundaries and exact-read fallback without a device."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build', required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
out = args.build.resolve()
out.mkdir(parents=True, exist_ok=True)
script = r'''set -eu
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -std=c++20 -stdlib=libc++ -O1 -Wall -Wextra -Werror \
 -I/repo/runtime/maplesu-sdk/include -I/repo/runtime/ultra/authorization \
 /repo/runtime/tests/task_comm_scan_test.cpp -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
 -o /case/task-comm-scan.test
/case/task-comm-scan.test
$C/bin/clang++ -std=c++20 -stdlib=libc++ -O1 -Wall -Wextra -Werror \
 -I/repo/runtime/tests/task_comm_fixture -I/repo/runtime/maplesu-sdk/include \
 -I/repo/runtime/ultra/authorization \
 /repo/runtime/ultra/authorization/task_comm_scan.cpp /repo/runtime/tests/task_comm_lifecycle_test.cpp \
 -Wl,--wrap=prctl -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu -o /case/task-comm-lifecycle.test
for mode in success initial-get-fail initial-set-fail verify-get-fail mismatch asm-error execute-error invalid-task read-error not-found exception read-exception restore-fail; do
 /case/task-comm-lifecycle.test "$mode"
done
'''
run = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={root},target=/repo,readonly', '--mount',
    f'type=bind,source={out},target=/case', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(out / 'test.log').write_text(run.stdout + run.stderr, encoding='utf-8')
report = dict(passed=run.returncode == 0, deviceRequests=False, output=run.stdout, stderr=run.stderr)
(out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
assert run.returncode == 0, run.stdout + run.stderr
print(run.stdout, end='')
