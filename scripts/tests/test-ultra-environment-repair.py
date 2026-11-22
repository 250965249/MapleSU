"""Exercise the Manager's read-only completed/idle boot repair script over Linux fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import textwrap

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
source = ROOT / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentUpgrade.kt'
text = source.read_text(encoding='utf-8')
body = text.split('internal fun completedBootRepairScript(', 1)[1].split('return """', 1)[1].split('""".trimIndent()', 1)[0]
boot = '01234567-89ab-cdef-0123-456789abcdef'
body = textwrap.dedent(body).replace("${'$'}", '$').replace('$bootId', boot)
body = body.replace("'$helper'", '"${fixture}/init"')
body = body.replace('/system/bin/getprop sys.boot_completed', 'cat "${fixture}/complete"')
body = body.replace('/proc/sys/kernel/random/boot_id', '"${fixture}/boot"')
body = body.replace('/proc/uptime', '"${fixture}/uptime"')
cases = {
    'completed-missing-work': ('', True),
    'completed-stale-work': ('printf old > "$fixture/init.boot_session.work"', True),
    'completed-empty-work': (': > "$fixture/init.boot_session.work"', True),
    'completed-current-work': (f'printf {boot} > "$fixture/init.boot_session.work"', False),
    'initializing': ('printf 1 > "$fixture/init.safe_flag"', False),
    'protected': ('printf 3 > "$fixture/init.safe_flag"', False),
    'missing-success-marker': ('rm "$fixture/init.safe_flag"', False),
    'bad-success-marker': ('printf bad > "$fixture/init.safe_flag"', False),
    'android-not-completed': ('printf 0 > "$fixture/complete"', False),
    'boot-changed': ('printf old > "$fixture/boot"', False),
    'work-directory': ('mkdir "$fixture/init.boot_session.work"', False),
    'work-symlink': ('ln -s complete "$fixture/init.boot_session.work"', False),
    'work-dangling-symlink': ('ln -s missing "$fixture/init.boot_session.work"', False),
    'flag-symlink': ('mv "$fixture/init.safe_flag" "$fixture/flag"; ln -s flag "$fixture/init.safe_flag"', False),
    'flag-directory': ('rm "$fixture/init.safe_flag"; mkdir "$fixture/init.safe_flag"', False),
    'work-read-error': ('printf old > "$fixture/init.boot_session.work"; head() { case "$3" in *.work) return 1;; esac; command head "$@"; }', False),
    'reported-never-started': (': > "$fixture/init.safe_flag"; : > "$fixture/init.boot_fail_protect"; : > "$fixture/init.boot_session.work"; : > "$fixture/init.boot_session.duplicate"', True),
    'idle-missing-markers': (': > "$fixture/init.safe_flag"', True),
    'idle-too-early': (': > "$fixture/init.safe_flag"; printf "119.99 0\\n" > "$fixture/uptime"', False),
    'idle-android-not-completed': (': > "$fixture/init.safe_flag"; printf 0 > "$fixture/complete"', False),
    'idle-work-active': (f': > "$fixture/init.safe_flag"; printf {boot} > "$fixture/init.boot_session.work"', False),
    'idle-work-stale': (': > "$fixture/init.safe_flag"; printf old > "$fixture/init.boot_session.work"', False),
    'idle-duplicate-active': (f': > "$fixture/init.safe_flag"; printf {boot} > "$fixture/init.boot_session.duplicate"', False),
    'idle-completed-active': (f': > "$fixture/init.safe_flag"; printf {boot} > "$fixture/init.boot_session.completed"', False),
    'idle-protected': (': > "$fixture/init.safe_flag"; printf 1 > "$fixture/init.boot_fail_protect"', False),
    'idle-enabled': (': > "$fixture/init.safe_flag"; printf 1 > "$fixture/init.enable"', False),
    'idle-work-directory': (': > "$fixture/init.safe_flag"; mkdir "$fixture/init.boot_session.work"', False),
    'idle-protection-symlink': (': > "$fixture/init.safe_flag"; ln -s complete "$fixture/init.boot_fail_protect"', False),
    'idle-protection-dangling-symlink': (': > "$fixture/init.safe_flag"; ln -s missing "$fixture/init.boot_fail_protect"', False),
    'missing-helper': ('rm "$fixture/init"', False),
    'helper-symlink': ('mv "$fixture/init" "$fixture/helper"; ln -s helper "$fixture/init"', False),
}
commands = ['set -eu', 'base=$(mktemp -d /tmp/maplesu-repair.XXXXXX)',
            "trap 'rm -rf -- \"$base\"' EXIT", 'failed=0']
for name, (setup, expected) in cases.items():
    commands += [f'fixture="$base/{name}"; mkdir "$fixture"',
                 f'printf {boot} > "$fixture/boot"; printf 1 > "$fixture/complete"; printf 2 > "$fixture/init.safe_flag"',
                 'printf helper > "$fixture/init"; printf "360.84 1645.29\\n" > "$fixture/uptime"',
                 'output=$(', setup, body, ')',
                 f"if [ \"$output\" {'=' if expected else '!='} 'MAPLESU_COMPLETED_BOOT:{boot}' ]; then "
                 f"echo 'PASS {name}'; else echo 'FAIL {name}'; failed=1; fi"]
commands += ['exit $failed']
result = subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-s'], input='\n'.join(commands).encode('utf-8'),
    capture_output=True, timeout=60)
result.stdout = result.stdout.decode('utf-8', errors='replace')
result.stderr = result.stderr.decode('utf-8', errors='replace')
a.out.mkdir(parents=True, exist_ok=True)
(a.out / 'regression.log').write_text(result.stdout + result.stderr, encoding='utf-8')
report = dict(passed=result.returncode == 0 and result.stdout.count('PASS ') == len(cases),
    exitCode=result.returncode, sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    productionScriptLogic=True, syntheticPaths=True, deviceAcceptance=False,
    cases={name: expected for name, (_, expected) in cases.items()})
(a.out / 'regression.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(result.stdout + result.stderr)
raise SystemExit(0 if report['passed'] else 1)
