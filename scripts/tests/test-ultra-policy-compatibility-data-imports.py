"""Compare declaration/no-declaration contracts using real prebuilt ELF inputs; no Kbuild."""
import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from policy_payload_inspect import inspect_payload


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(directory):
    return {p.relative_to(directory).as_posix(): digest(p)
            for p in sorted(directory.rglob('*')) if p.is_file()}


def load_generator(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = ROOT
    module.PROFILE_POLICY = ROOT / 'runtime/ultra/policy/kernel_compatibility_profiles.json'
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payloads', required=True, type=Path)
    parser.add_argument('--baseline-generator', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    payloads = args.payloads.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    generators = {
        'baseline': load_generator(args.baseline_generator.resolve(), 'compatibility_baseline'),
        'current': load_generator(ROOT / 'scripts/build-ultra-policy-compatibility.py', 'compatibility_current'),
    }
    references = sorted(p for p in payloads.iterdir() if (p / 'policy-view.so').is_file())
    btf_references = [p for p in references if (p / 'vmlinux.btf').is_file()]
    assert len(references) == 5 and len(btf_references) == 4
    before = inventory(payloads)
    results, calls = [], []

    def generate(version, directory):
        output = io.StringIO()
        # Missing compiler proofs must fail this focused regression, not trigger Kbuild.
        with patch.object(subprocess, 'run', side_effect=AssertionError('Unexpected compiler invocation')), redirect_stdout(output):
            generators[version].generate(directory)
        record = json.loads((directory / 'kernel-compatibility.json').read_text())
        calls.append(dict(generator=version, directory=directory.name, stdout=output.getvalue(),
                          contractSha256=digest(directory / 'kernel-compatibility.json')))
        return record

    with tempfile.TemporaryDirectory(prefix='contract-imports-', dir=args.output.parent) as temporary:
        work = Path(temporary)
        trees = {version: work / version for version in generators}
        for tree in trees.values():
            shutil.copytree(payloads, tree)
        for reference in btf_references:
            name = reference.name
            records = {}
            for version, tree in trees.items():
                directory = tree / name
                declaration = directory / 'config-declarations.json'
                saved = declaration.read_bytes()
                declaration.unlink()
                try:
                    records[version] = generate(version, directory)
                finally:
                    declaration.write_bytes(saved)
            assert records['baseline'] == records['current']
            results.append(dict(name='without-declarations-old-new-identical', kernel=name, passed=True))
            records = {version: generate(version, tree / name) for version, tree in trees.items()}
            symbols = {line.split()[-1] for line in (reference / 'System.map').read_text().splitlines() if line.split()}
            metadata = json.loads((reference / 'target-identity.json').read_text())
            imports = set(inspect_payload(reference / 'policy-view.so', symbols)['imports'] + metadata['requiredLoaderSymbols'])
            if metadata['dynamicScs']:
                imports.update([metadata['scsFunction'], 'static_key_count', 'dynamic_scs_enabled'])
            expected = sorted(imports & generators['current'].DATA)
            old, current = records['baseline'], records['current']
            assert expected and old['dataImports'] != expected and current['dataImports'] == expected
            assert {k: v for k, v in old.items() if k != 'dataImports'} == {
                k: v for k, v in current.items() if k != 'dataImports'}
            results.append(dict(name='declaration-data-import-completeness', kernel=name, passed=True,
                                baseline=old['dataImports'], current=current['dataImports'], onlyDataImportsChanged=True))
        bundles = {}
        for version, tree in trees.items():
            output = work / (version + '-bundles.cpp')
            command = list(map(str, [sys.executable, ROOT / 'scripts/build-ultra-policy-bundles.py',
                                    *(tree / p.name for p in references), '--output', output]))
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            calls.append(dict(command=command, exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr))
            assert result.returncode == 0, result.stdout + result.stderr
            bundles[version] = output.read_bytes()
        assert bundles['baseline'] == bundles['current']
        results.append(dict(name='old-fixed-bundle-cpp-byte-identical', passed=True,
                            sha256=hashlib.sha256(bundles['current']).hexdigest()))
        for version, tree in trees.items():
            directory = tree / btf_references[-1].name
            declaration = directory / 'config-declarations.json'
            proof = json.loads(declaration.read_text())
            proof['inputSha256']['policy-view.so'] = '0' * 64
            declaration.write_text(json.dumps(proof))
            try:
                generate(version, directory)
            except ValueError as error:
                assert str(error) == 'Stale config declaration proof: policy-view.so'
            else:
                raise AssertionError('Stale declaration accepted: ' + version)
            results.append(dict(name='stale-declaration-' + version, passed=True))
    assert len(results) == 11 and inventory(payloads) == before
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=True, results=results, calls=calls,
                  inputSha256=before, referenceUnchanged=True, compilerInvocations=0, deviceAccess=False,
                  generatorSha256={version: digest(Path(module.__file__)) for version, module in generators.items()})
    args.output.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=True, tests=len(results), referenceUnchanged=True, compilerInvocations=0)))


if __name__ == '__main__':
    main()
