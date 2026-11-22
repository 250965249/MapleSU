"""Check the three production permission expressions in Android's actual shell.

This is an expression regression, not a full recovery/deployment acceptance.
It uses no Root command and writes no device file.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    args.out.mkdir(parents=True, exist_ok=False)
    targets = [('UltraIdentityRecovery.kt', 'mode', 0o22),
               ('UltraRecoveryKeyStore.kt', 'M', 0o22),
               ('UltraIdleEnvironmentRecovery.kt', 'data_mode', 0o2)]
    script = ['set -u', 'failed=0', 'checks=0']
    inputs = []
    for filename, variable, mask in targets:
        path = root / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra' / filename
        text = path.read_text(encoding='utf-8-sig')
        expressions = re.findall(r'\$\{\x27\$\x27\}\(\(([^\r\n]*?)\)\)', text)
        expressions = [value for value in expressions if "${'$'}" + variable in value and '&' in value]
        assert len(expressions) == 1, (filename, expressions)
        expression = expressions[0].replace("${'$'}", '$')
        inputs.append(dict(path=path.relative_to(root).as_posix(),
                           sha256=hashlib.sha256(path.read_bytes()).hexdigest(), expression=expression))
        for mode in [0o000, 0o600, 0o700, 0o710, 0o711, 0o750, 0o755, 0o770,
                     0o771, 0o775, 0o777, 0o1700, 0o1777, 0o2750, 0o2770]:
            script.extend([
                f'{variable}={mode:o}; actual=$(({expression})); checks=$((checks+1))',
                f'if [ "$actual" -ne {mode & mask} ]; then '
                f'printf "FAIL {filename} mode={mode:o} expected={mode & mask} actual=%s\\n" "$actual"; '
                'failed=$((failed+1)); fi',
            ])
    script.extend(['printf "CHECKS=%s FAILED=%s\\n" "$checks" "$failed"', '[ "$failed" -eq 0 ]'])
    data = ('\n'.join(script) + '\n').encode()
    (args.out / 'device.sh').write_bytes(data)
    adb = [args.adb, '-s', args.serial]

    def boot_id():
        return subprocess.check_output(adb + ['shell', 'cat /proc/sys/kernel/random/boot_id'], timeout=10).decode().strip()

    before = boot_id()
    result = subprocess.run(adb + ['shell', '/system/bin/sh'], input=data, capture_output=True, timeout=20)
    after = boot_id()
    (args.out / 'device.log').write_bytes(result.stdout + result.stderr)
    record = dict(recordedUtc=datetime.now(timezone.utc).isoformat(), device=args.serial,
                  shell='/system/bin/sh', bootBefore=before, bootAfter=after,
                  inputs=inputs, scriptSha256=hashlib.sha256(data).hexdigest(),
                  exitCode=result.returncode, rootCalls=0, deviceWrites=0)
    (args.out / 'RESULT.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    assert before == after, 'BOOT_CHANGED_STOP'
    print(result.stdout.decode('utf-8', 'replace'))
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
