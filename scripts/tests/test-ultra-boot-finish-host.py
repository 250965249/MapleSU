"""Check the production completion writer against real disposable Linux files."""
import argparse
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
script = '''set -eu
/opt/ddk/clang/clang-r510928/bin/clang -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror \
 /repo/runtime/ultra/boot/bootstrap_finish.c /repo/runtime/tests/pro_bootstrap_finish_test.c -o /tmp/boot-test
/tmp/boot-test
'''
r = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount', f'type=bind,source={root},target=/repo,readonly',
    '--entrypoint', 'sh', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
a.out.mkdir(parents=True, exist_ok=True)
(a.out / 'host-finish.log').write_text(r.stdout + r.stderr)
cases = [line[5:] for line in r.stdout.splitlines() if line.startswith('PASS ')]
(a.out / 'host-finish.json').write_text(json.dumps(dict(passed=r.returncode == 0, cases=cases,
    actualProductionWriter=True, deviceVerification=False), indent=2) + '\n')
print(r.stdout + r.stderr)
raise SystemExit(r.returncode)
