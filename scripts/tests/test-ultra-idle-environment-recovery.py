"""Execute the Manager's actual idle-recovery evidence script over Linux fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import textwrap

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
source = ROOT / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdleEnvironmentRecovery.kt'
source_bytes = source.read_bytes()
text = source_bytes.decode('utf-8')
body = text.split('internal fun evidenceScript(', 1)[1].split('return """', 1)[1].split('""".trimIndent()', 1)[0]
boot = '01234567-89ab-cdef-0123-456789abcdef'
body = textwrap.dedent(body).replace("${'$'}", '$').replace('$bootId', boot)
body = body.replace('/system/bin/id', 'id')
body = body.replace('/system/bin/getprop sys.boot_completed', 'cat "$fixture/android-complete"')
body = body.replace('/proc/sys/kernel/random/boot_id', '"$fixture/proc/boot_id"')
body = body.replace('/proc/uptime', '"$fixture/proc/uptime"')
body = body.replace('/proc/[0-9]*/exe', '"$fixture/proc"/[0-9]*/exe')
body = body.replace('/data', '"$fixture/data"')
body = body.replace("h='$helper'", 'h="$fixture/data/OwnerFixture0001/init"')
assert '$helper' not in body and '$bootId' not in body
assert not re.search(r'(?<![A-Za-z0-9_])/(?:proc|system)/', body)

cases = {}


def add(name, setup='', expected=False):
    assert name not in cases
    cases[name] = (setup, expected)


add('reported-2355-empty-flags-never-executed', expected=True)
add('sentinel-without-final-newline', 'printf "[FATAL] autorun_bootstrap: NEVER EXECUTED" > "$h.log"', True)
add('uptime-exactly-120', 'printf "120.00 0\\n" > "$fixture/proc/uptime"', True)
for value in (1, 2, 3):
    add(f'safe-{value}', f'printf {value} > "$h.safe_flag"')
for suffix in ('boot_fail_protect', 'boot_session.work', 'boot_session.duplicate', 'boot_session.completed'):
    add(suffix.replace('.', '-') + '-nonempty', f'printf active > "$h.{suffix}"')
for role, suffix, required in [('helper', '', True), ('safe', '.safe_flag', True), ('log', '.log', True),
                             ('bfp', '.boot_fail_protect', False), ('work', '.boot_session.work', False),
                             ('duplicate', '.boot_session.duplicate', False), ('completed', '.boot_session.completed', False)]:
    path = '$h' + suffix
    add(role + '-missing', f'rm "{path}"', not required)
    add(role + '-symlink', f'mv "{path}" "$fixture/linked"; ln -s "$fixture/linked" "{path}"')
    add(role + '-dangling-symlink', f'rm "{path}"; ln -s "$fixture/missing" "{path}"')
    add(role + '-hardlink', f'ln "{path}" "$fixture/second-link"')
    add(role + '-nonroot', f'chown 12345:12345 "{path}"')
    add(role + '-directory', f'rm "{path}"; mkdir "{path}"')
add('parent-symlink', 'mv "$fixture/data/OwnerFixture0001" "$fixture/actual-owner"; ln -s "$fixture/actual-owner" "$fixture/data/OwnerFixture0001"')
add('data-ancestor-symlink', 'mv "$fixture/data" "$fixture/actual-data"; ln -s "$fixture/actual-data" "$fixture/data"')
add('parent-nonroot', 'chown 12345:12345 "$fixture/data/OwnerFixture0001"')
add('data-ancestor-nonroot', 'chown 12345:12345 "$fixture/data"')
add('data-ancestor-system-owner', 'chown 1000:1000 "$fixture/data"', True)
add('data-world-writable', 'chmod o+w "$fixture/data"')
add('uptime-119', 'printf "119.99 0\\n" > "$fixture/proc/uptime"')
add('uptime-malformed', 'printf invalid > "$fixture/proc/uptime"')
add('android-not-completed', 'printf 0 > "$fixture/android-complete"')
add('boot-mismatch', 'printf old > "$fixture/proc/boot_id"')
add('boot-changes-during-evidence', 'head() { head_calls=$((head_calls + 1)); if [ "$head_calls" -eq 1 ]; then command head "$@"; printf old > "$fixture/proc/boot_id"; else command head "$@"; fi; }; head_calls=0')
add('log-extra-line', 'printf "\\nextra\\n" >> "$h.log"')
add('log-extra-prefix', 'printf "prefix [FATAL] autorun_bootstrap: NEVER EXECUTED\\n" > "$h.log"')
add('log-too-large', 'printf "[FATAL] autorun_bootstrap: NEVER EXECUTED\\n" > "$h.log"; head -c 300 /dev/zero >> "$h.log"')
add('log-empty', ': > "$h.log"')
add('live-helper', 'mkdir "$fixture/proc/123"; ln -s "$h" "$fixture/proc/123/exe"')
add('live-deleted-helper', 'mkdir "$fixture/proc/123"; ln -s "$h (deleted)" "$fixture/proc/123/exe"')
add('other-process-only', 'mkdir "$fixture/proc/123"; ln -s /unrelated/helper "$fixture/proc/123/exe"', True)

commands = ['set -eu', 'base=$(mktemp -d /tmp/maplesu-idle.XXXXXX)',
            "trap 'rm -rf -- \"$base\"' EXIT", 'failed=0']
for name, (setup, expected) in cases.items():
    commands += [f'fixture="$base/{name}"; mkdir -p "$fixture/data/OwnerFixture0001" "$fixture/proc"',
                 'h="$fixture/data/OwnerFixture0001/init"; printf helper > "$h"',
                 'for suffix in safe_flag boot_fail_protect boot_session.work boot_session.duplicate boot_session.completed; do : > "$h.$suffix"; done',
                 'printf "[FATAL] autorun_bootstrap: NEVER EXECUTED\\n" > "$h.log"',
                 f'printf "{boot}\\n" > "$fixture/proc/boot_id"; printf 1 > "$fixture/android-complete"',
                 'printf "360.84 1645.29\\n" > "$fixture/proc/uptime"',
                 'output=$(', setup, body, ')',
                 f"if [ \"$output\" {'=' if expected else '!='} 'MAPLESU_IDLE_BOOT:{boot}' ]; then "
                 f"echo 'PASS {name}'; else echo 'FAIL {name}'; failed=1; fi"]
commands += ['exit $failed']
script = '\n'.join(commands) + '\n'
args.out.mkdir(parents=True, exist_ok=True)
(args.out / 'fixture.sh').write_text(script, encoding='utf-8')
command = ['docker', 'run', '--rm', '-i', '--pull=never', '--network', 'none', '--entrypoint', '/bin/sh',
           'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-s']
result = subprocess.run(command, input=script.encode('utf-8'), capture_output=True, timeout=60)
stdout = result.stdout.decode('utf-8', errors='replace')
stderr = result.stderr.decode('utf-8', errors='replace')
(args.out / 'regression.log').write_text(stdout + stderr, encoding='utf-8')
passed_names = {line[5:] for line in stdout.splitlines() if line.startswith('PASS ')}
source_unchanged = source.read_bytes() == source_bytes
report = dict(passed=result.returncode == 0 and passed_names == set(cases) and source_unchanged,
              executed=True, exitCode=result.returncode, sourceSha256=hashlib.sha256(source_bytes).hexdigest(),
              testSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              fixtureSha256=hashlib.sha256(script.encode('utf-8')).hexdigest(), sourceUnchanged=source_unchanged,
              productionScriptLogic=True, syntheticPaths=True, deviceAcceptance=False, command=command,
              cases={name: dict(expectedIdle=expected, passed=name in passed_names)
                     for name, (_, expected) in cases.items()})
(args.out / 'regression.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(stdout + stderr)
raise SystemExit(0 if report['passed'] else 1)
