"""Replay the report's bad helper label through the actual grant transaction.

SELinux decisions are an xattr fixture; this does not certify Xiaomi execution.
"""
import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--transaction', type=Path, default=Path('runtime/ultra/authorization/su_auth_transaction.cpp'))
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--without-context', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
transaction = args.transaction.resolve().relative_to(root).as_posix()
extra = '' if args.without_context else '/repo/runtime/ultra/authorization/su_exec_context.cpp'
script = f'''set -eu
mkdir -p /data/adb
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -stdlib=libc++ -std=c++17 -Wall -Wextra -Werror -I/repo/runtime/maplesu-sdk/include \\
 -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu -Wl,--wrap=fgetxattr -Wl,--wrap=fsetxattr \\
 /repo/runtime/tests/pro_su_execution_test.cpp /repo/{transaction} {extra} -o /tmp/su-execution.test
failed=0
for t in report directory_label already refresh missing symlink foreign_owner relabel_denied bad_readback revoke; do
 /tmp/su-execution.test "$t" || failed=1
done
exit $failed
'''
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={root},target=/repo', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(out / 'su-execution.log').write_text(result.stdout + result.stderr, encoding='utf-8')
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
