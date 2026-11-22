"""Run the real boot wire consumer with complete typed producer fixtures."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--red', action='store_true', help='Verify the pre-refactor producer-contract failure')
a = p.parse_args()
output = a.output.resolve()
output.mkdir(parents=True, exist_ok=True)
sources = ['module-policy/src/boot_sdk_layout.cpp', 'module-policy/src/boot_sdk_layout.h',
    'runtime/ultra/policy/kernel_layout.cpp', 'runtime/ultra/policy/kernel_layout.h',
    'jailbreak-providers/root-loader/boot_sdk_abi.h', 'runtime/tests/boot_sdk_facts_test.cpp',
    'scripts/tests/test-boot-sdk-facts.py']
digest = lambda: {n: hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sources}
before = digest()
for n in sources:
    path = output/'source'/n
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((ROOT/n).read_bytes())
run = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--mount', f'type=bind,source={ROOT},target=/source,readonly',
    '--mount', f'type=bind,source={output},target=/output',
    'sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2']
compile_args = ['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-I/source/runtime/ultra/policy',
    '/source/module-policy/src/boot_sdk_layout.cpp', '/source/runtime/tests/boot_sdk_facts_test.cpp',
    '-o', '/output/facts-test']
if not a.red:
    compile_args += ['-DMAPLESU_TEST_FACT_CONSUMER']
commands, results = [], []
runs = [('run-owner', ['/output/facts-test', 'owner']), ('run-abi', ['/output/facts-test', 'abi'])] if a.red else [('run', ['/output/facts-test'])]
for name, args in [('compile', compile_args)] + runs:
    result = subprocess.run(run+args, capture_output=True, text=True, timeout=90)
    (output/(name+'.log')).write_text(result.stdout+result.stderr, encoding='utf-8')
    commands.append(dict(name=name, argv=run+args, exit=result.returncode))
    if name == 'compile' and result.returncode:
        raise RuntimeError(result.stderr)
    if name != 'compile':
        expected = result.returncode == 1 and 'FAIL production accepted incomplete fact:' in result.stderr
        results.append(dict(name=name, passed=expected if a.red else result.returncode == 0,
            stdout=result.stdout, stderr=result.stderr, exit=result.returncode))
expected_red = a.red and all(r['passed'] for r in results)
passed = all(r['passed'] for r in results)
report = dict(at=datetime.now(timezone.utc).isoformat(), passed=passed, red=a.red,
    expectedFailureReproduced=expected_red, sanitize=True, commands=commands, results=results,
    sourcesBefore=before, sourcesUnchanged=before==digest(),
    formalArtifactBuilt=False, deviceTest=False,
    scope='Real production wire assembly; BTF producer replaced by typed fixtures, not a device test')
(output/'receipt.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
print(json.dumps(dict(passed=passed, red=a.red, sourcesUnchanged=report['sourcesUnchanged'], output=result.stdout.strip(), error=result.stderr.strip())))
raise SystemExit(0 if passed and report['sourcesUnchanged'] else 1)
