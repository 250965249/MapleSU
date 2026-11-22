"""Exercise the real retention store with filesystem failure injection and budget fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--image', default='ghcr.io/ylarod/ddk-min:android15-6.6-20260828')
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
out = args.out.resolve()
out.mkdir(exist_ok=False, parents=True)
script = 'set -eu\nC=/opt/ddk/clang/clang-r510928\ncd /out\n$C/bin/clang++ -stdlib=libc++ -std=c++17 -Wall -Wextra -Werror -I/repo/runtime/maplesu-sdk/include -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu -Wl,--wrap=openat -Wl,--wrap=fsetxattr -Wl,--wrap=write -Wl,--wrap=pread -Wl,--wrap=fstat -Wl,--wrap=fsync -Wl,--wrap=renameat -Wl,--wrap=close /repo/runtime/tests/pro_su_retention_store_test.cpp /repo/runtime/ultra/authorization/su_retention_store.cpp -o store.test\n./store.test\n$C/bin/clang++ -stdlib=libc++ -std=c++17 -Wall -Wextra -Werror -I/repo/runtime/maplesu-sdk/include -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu /repo/runtime/tests/pro_su_lifetime_test.cpp /repo/runtime/ultra/authorization/su_allowlist_writer.cpp -o lifetime.test\n./lifetime.test\n'
command = ['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={root},target=/repo,readonly', '--mount', f'type=bind,source={out},target=/out',
    '--entrypoint', 'sh', args.image, '-c', script]
result = subprocess.run(command, capture_output=True, text=True)
(out / 'native-test.log').write_text(result.stdout + result.stderr, encoding='utf-8')
report = dict(passed=result.returncode == 0 and result.stdout.count('PASS ') == 38 and 'FAIL ' not in result.stdout,
    exitCode=result.returncode, actualHostFilesystem=True, selinuxXattrFixture=True, deviceAcceptance=False,
    command=command, stdout=result.stdout, stderr=result.stderr)
(out / 'durability-report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(result.stdout + result.stderr)
raise SystemExit(0 if report['passed'] else 1)
