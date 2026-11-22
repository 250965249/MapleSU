"""Exercise module-control reply acceptance with real fork/pipe and waitpid faults."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = ['runtime/ultra/modules/module_control.cpp', 'runtime/tests/module_control_wait_test.cpp',
             'scripts/tests/test-module-control-wait.py']
    inputs = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
    (out / 'module_gate_identity.h').write_text(
        '#pragma once\n#define MAPLESU_GATE_FILE_OFFSET 0\n#define MAPLESU_GATE_BRANCH_OFFSET 0\n'
        '#define MAPLESU_GATE_PHDR_OFFSET 0\n'
        'static constexpr unsigned char maplesu_gate_bytes[] = {0};\n'
        'static constexpr unsigned char maplesu_gate_branch[4] = {};\n'
        'static constexpr unsigned char maplesu_gate_phdr[56] = {};\n', encoding='utf-8')
    scenarios = ['success', 'eintr', 'echild', 'mismatch', 'signal', 'exit']
    command = (
        'set -u\nulimit -c 0\n'
        '/opt/ddk/clang/clang-r510928/bin/clang++ -std=c++17 -stdlib=libc++ -UNDEBUG '
        '-Wall -Wextra -Werror -Wno-packed-non-pod -fsanitize=address,undefined '
        '-Wl,-rpath,/opt/ddk/clang/clang-r510928/lib/x86_64-unknown-linux-gnu '
        '-fno-omit-frame-pointer -I/source/runtime/maplesu-sdk/include -I/output '
        '/source/runtime/ultra/modules/module_control.cpp /source/runtime/tests/module_control_wait_test.cpp '
        '-Wl,--wrap=waitpid -Wl,--wrap=poll -Wl,--wrap=_exit -o /output/control-wait-test || exit $?\n'
        'failed=0\n' + '\n'.join('/output/control-wait-test ' + case + ' || failed=1' for case in scenarios) +
        '\nexit "$failed"\n')
    result = subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount',
        f'type=bind,source={ROOT},target=/source,readonly', '--mount', f'type=bind,source={out},target=/output',
        'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', 'sh', '-c', command],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=55)
    stable = inputs == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
    report = dict(passed=result.returncode == 0 and stable, recordedAt=datetime.now(timezone.utc).isoformat(),
        exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr, cases=len(scenarios),
        scenarios=scenarios, sourceSha256=inputs, inputsUnchanged=stable, deviceAccess=False,
        sanitizers=['ASan', 'UBSan'], scope='Real fork/pipe; waitpid injection after the child reply and actual reap')
    (out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(result.stdout + result.stderr)
    raise SystemExit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
