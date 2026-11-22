"""Exercise exact claim scope/VMA bodies; fixture APIs do not establish a target ABI."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'runtime/ultra/identity/kernel/protected_install_kernel.c'
FIXTURE = ROOT / 'runtime/tests/manager_claim_kernel_scope_test.c'
IMAGE = 'sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2'
CASES = ['io-marker', 'io-overridden', 'io-inactive', 'map-no-mm', 'map-empty',
         'map-gap-and-inode-alias', 'map-first', 'map-unmapped', 'map-anonymous', 'map-nonprogress']


def identity(path):
    data = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def extract(text, start, end):
    at = text.index(start)
    finish = text.index(end, at) + len(end)
    return text[at:finish] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    inputs = [SOURCE, FIXTURE, Path(__file__).resolve()]
    before = [identity(path) for path in inputs]
    for path in inputs:
        dest = out / 'source' / path.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(path.read_bytes())
    text = SOURCE.read_text(encoding='utf-8-sig')
    fragments = [extract(text, 'struct msu_io_scope {', '\n};')]
    for declaration in ['static int msu_io_enter(', 'static void msu_io_leave(', 'static bool msu_caller_maps_apk(']:
        fragments.append(extract(text, declaration, '\n}'))
    bodies = out / 'claim-kernel-scope.inc'
    bodies.write_text('\n'.join(fragments), encoding='utf-8')
    compile_args = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', '-I/output',
                    '/source/runtime/tests/manager_claim_kernel_scope_test.c', '-o', '/output/claim-scope-test']
    command = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--mount', f'type=bind,source={out / "source"},target=/source,readonly',
               '--mount', f'type=bind,source={out},target=/output', IMAGE, 'sh', '-c',
               ' '.join(compile_args) + ' && /output/claim-scope-test']
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
    (out / 'run.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    after = [identity(path) for path in inputs]
    executed = [line.removesuffix(': passed') for line in result.stdout.splitlines() if line.endswith(': passed')]
    passed = result.returncode == 0 and executed == CASES and before == after
    receipt = {'atUtc': datetime.now(timezone.utc).isoformat(), 'passed': passed,
               'command': command, 'exitCode': result.returncode, 'sourcesBefore': before,
               'sourcesAfter': after, 'sourceInputsStable': before == after,
               'extractedBodies': identity(bodies), 'expectedCases': CASES, 'executedCases': executed,
               'scope': 'Exact production scope/VMA bodies under fixture layouts/APIs; not an actual kernel TU or target ABI proof',
               'formalArtifactBuilt': False, 'deviceOperations': False, 'partitionWrites': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(result.stdout + result.stderr, end='')
    print(json.dumps({'passed': passed, 'exitCode': result.returncode, 'sourceInputsStable': before == after}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
