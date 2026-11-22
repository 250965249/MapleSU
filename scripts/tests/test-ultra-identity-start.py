"""Execute the production launcher in disposable Linux processes; no Android device changes."""
import argparse
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
a.out.mkdir(parents=True, exist_ok=True)
cases = ['valid', 'closed-stdio', 'missing', 'mode', 'owner', 'directory-mode', 'directory-owner',
         'disabled', 'disabled-symlink', 'script-symlink', 'directory-symlink', 'hardlink', 'fifo', 'nonroot']
script = '''set -eu
C=/opt/ddk/clang/clang-r510928
$C/bin/clang -std=c11 -D_GNU_SOURCE -DMAPLESU_IDENTITY_SHELL='"/bin/sh"' -Wall -Wextra -Werror \
 -Wl,--wrap=getuid /repo/runtime/ultra/identity/environment_start.c /repo/runtime/tests/pro_identity_start_test.c -o /tmp/identity-test
for scenario in ''' + ' '.join(cases) + '''; do
 /tmp/identity-test "$scenario"
 # Every path here belongs to this disposable container.
 rm -rf /data
done
'''
r = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount', f'type=bind,source={root},target=/repo,readonly',
                    '--entrypoint', 'sh', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
(a.out / 'launcher.log').write_text(r.stdout + r.stderr)
(a.out / 'launcher.json').write_text(json.dumps(dict(passed=r.returncode == 0, cases=cases, deviceVerification=False), indent=2) + '\n')
print(r.stdout + r.stderr)
raise SystemExit(r.returncode)
