"""Exercise real config-proof generation/packaging validation against a built payload."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--reference', required=True, type=Path)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
reference = args.reference.resolve()
proof = json.loads((reference / 'config-equivalence.json').read_text())
profile = next(p for p in proof['profiles'] if 'layout' in p)
before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in reference.iterdir() if p.is_file()}
results = []
with tempfile.TemporaryDirectory(prefix='maplesu-config-profile-tests-') as temporary:
    work = Path(temporary)

    def run(name, mutate, tool, expected):
        target = work / name / reference.name
        shutil.copytree(reference, target)
        mutate(target)
        command = [sys.executable, ROOT / 'scripts' / tool, target]
        if tool == 'build-ultra-policy-bundles.py':
            command.extend(['--output', target.parent / 'bundles.cpp'])
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30)
        passed = result.returncode == 0 if expected is None else result.returncode != 0 and expected in result.stderr
        results.append(dict(name=name, passed=passed, exitCode=result.returncode, expected=expected))
        if not passed:
            raise AssertionError(name + ': ' + result.stdout + result.stderr)

    def corrupt_payload(target):
        path = target / profile['payload']
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)

    def corrupt_layout(target):
        path = target / profile['layout']
        data = json.loads(path.read_text())
        data[0]['size'] += 1
        path.write_text(json.dumps(data))

    def drop_profile(target):
        path = target / 'kernel-compatibility.json'
        data = json.loads(path.read_text())
        data['equivalentConfigs'] = []
        path.write_text(json.dumps(data))

    def unconsumed_profile(target):
        path = target / 'kernel-compatibility.json'
        data = json.loads(path.read_text())
        for item in proof['profiles']:
            for key in item['config']:
                data['config'].pop(key, None)
        data['equivalentConfigs'] = []
        path.write_text(json.dumps(data))

    run('valid-proof', lambda p: None, 'build-ultra-policy-compatibility.py', None)
    run('payload-differs', corrupt_payload, 'build-ultra-policy-compatibility.py', 'Config equivalence payload differs')
    run('layout-differs', corrupt_layout, 'build-ultra-policy-compatibility.py', 'Config equivalence layout differs')
    run('header-differs', lambda p: (p / profile['header']).write_text('#undef CONFIG_OTHER\n'),
        'build-ultra-policy-compatibility.py', 'Config equivalence header differs')
    source = next(n for n in profile['sourceSha256'] if n.endswith('.c'))
    run('source-changed', lambda p: (p / source).write_text('/* stale source proof */\n'),
        'build-ultra-policy-compatibility.py', 'Config equivalence input changed')
    run('valid-package', lambda p: None, 'build-ultra-policy-bundles.py', None)
    run('profile-dropped', drop_profile, 'build-ultra-policy-bundles.py', 'missing compiler-verified config profile')
    run('proof-changed-after-generation', corrupt_payload, 'build-ultra-policy-bundles.py', 'stale compatibility contract')
    run('unconsumed-profile-does-not-block-package', unconsumed_profile, 'build-ultra-policy-bundles.py', None)
    sys.path.insert(0, str(ROOT / 'scripts'))
    spec = importlib.util.spec_from_file_location('config_profiles_tested', ROOT / 'scripts/build-ultra-policy-compatibility.py')
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    contract = json.loads((reference / 'kernel-compatibility.json').read_text())
    declarations = work / 'profiles.json'
    declarations.write_text(json.dumps(dict(schemaVersion=1, profilesBySeries={contract['kernelSeries']:
        [profile['config'] | {'CONFIG_NOT_CONSUMED_BY_THIS_PAYLOAD': 'y'}]})))
    with patch.object(generator, 'PROFILE_POLICY', declarations), patch.object(generator.subprocess, 'run') as compile_call:
        generator.complete_profiles(reference, contract)
        compile_call.assert_not_called()
        empty = dict(contract, config={})
        generator.complete_profiles(reference, empty)
        compile_call.assert_not_called()
    results.append(dict(name='only-consumed-config-differences-require-proof', passed=True))
    nested = reference / 'invalid-nested-proof'
    result = subprocess.run(list(map(str, [sys.executable, ROOT / 'scripts/build-ultra-policy-config-equivalence.py',
        '--reference', reference, '--target-config', reference / 'target.config', '--output', nested])),
        capture_output=True, text=True, timeout=10)
    results.append(dict(name='recursive-output-rejected', passed=result.returncode == 2 and not nested.exists()))
after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in reference.iterdir() if p.is_file()}
record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=all(r['passed'] for r in results) and before == after,
              results=results, referenceUnchanged=before == after, deviceAccess=False)
args.output.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
print(json.dumps(record, indent=2))
raise SystemExit(0 if record['passed'] else 1)
