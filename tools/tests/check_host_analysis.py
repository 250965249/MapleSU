"""Check the Windows native build, rejection behavior and optional read-only sample analysis."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inputs():
    paths = [ROOT / 'patch-engine/CMakeLists.txt', ROOT / 'patch-engine/upstream-sources.cmake',
             ROOT / 'scripts/build-host-analysis.ps1', ROOT / 'tools/tests/check_host_analysis.py']
    for name in ('src', 'tests', 'upstream'):
        paths += sorted(path for path in (ROOT / 'patch-engine' / name).rglob('*') if path.is_file())
    return {path.relative_to(ROOT).as_posix(): sha256(path) for path in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path)
    parser.add_argument('--with-plan', action='store_true', help='Validate the experimental in-memory plan; needs --kernel')
    args = parser.parse_args()
    if args.with_plan and not args.kernel:
        parser.error('--with-plan requires --kernel')
    build = ROOT / 'patch-engine/build/windows-x64'
    binaries = {name: sha256(build / f'{name}.exe')
                for name in ('maplesu-kernel-analyze', 'maplesu-native-tests')}
    record = {'schemaVersion': 1, 'passed': False, 'binaries': binaries, 'inputs': inputs(),
              'scope': 'Windows x64 local core checks and read-only analysis; no candidate or partition writes.'}
    evidence = ROOT / '.analysis/native-host-validation.json'
    evidence.parent.mkdir(parents=True, exist_ok=True)
    if args.kernel:
        record['sourceSha256'] = sha256(args.kernel)
    evidence.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    logs = []

    def run(name, binary, arguments, expected_exit, expected):
        result = subprocess.run([str(build / f'{binary}.exe'), *arguments], capture_output=True,
                                timeout=120)
        output = (result.stdout + result.stderr).decode('utf-8', errors='replace').replace('\r\n', '\n')
        logs.append(f'[{name}] exit={result.returncode}\n{output}')
        (ROOT / '.analysis/native-host-validation.log').write_text('\n'.join(logs), encoding='utf-8')
        if result.returncode != expected_exit or not re.search(expected, output, re.MULTILINE):
            raise SystemExit(f'Host {name} failed; see .analysis/native-host-validation.log')
        return output

    output = run('core', 'maplesu-native-tests', [], 0, r'^PASS (\d+) native core checks$')
    record['checks'] = int(re.search(r'^PASS (\d+) native core checks$', output, re.MULTILINE)[1])
    run('usage', 'maplesu-kernel-analyze', [], 2, r'^Usage:')
    with tempfile.TemporaryDirectory(prefix='maplesu-host-rejection-') as directory:
        invalid = Path(directory) / 'invalid.bin'
        invalid.write_bytes(bytes(64))
        before = sha256(invalid)
        run('invalid-magic', 'maplesu-kernel-analyze', ['--symbols', str(invalid)], 1,
            r'^RAW_ARM64_REQUIRED$')
        if sha256(invalid) != before:
            raise SystemExit('Rejected host input was modified')
        missing = Path(directory) / 'missing.bin'
        run('missing-input', 'maplesu-kernel-analyze', ['--symbols', str(missing)], 1,
            r'^INPUT_OPEN_FAILED$')
    record['cliRejections'] = 3
    if args.kernel:
        output = run('symbols', 'maplesu-kernel-analyze', ['--symbols', str(args.kernel.resolve())], 0,
                     r'^SYMBOL_TABLE_OK count=([1-9][0-9]*)$')
        record['symbols'] = int(re.search(r'^SYMBOL_TABLE_OK count=(\d+)$', output, re.MULTILINE)[1])
        if args.with_plan:
            run('plan', 'maplesu-kernel-analyze', ['--plan', str(args.kernel.resolve())], 0,
                r'^PLAN_REPLAY_OK changedBytes=[1-9][0-9]*$')
            record['experimentalPlanReplayed'] = True
        if sha256(args.kernel) != record['sourceSha256']:
            raise SystemExit('Host sample changed during read-only analysis')
        record['sourceUnchanged'] = True
    if inputs() != record['inputs'] or any(sha256(build / f'{name}.exe') != digest
                                          for name, digest in binaries.items()):
        raise SystemExit('Host validation inputs changed during checks')
    record['passed'] = True
    evidence.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(f"PASS {record['checks']} Windows native core checks and 3 CLI rejection checks")
    if args.kernel:
        print(f"Read-only sample: {record['symbols']} unique symbol names; source unchanged")


if __name__ == '__main__':
    main()
