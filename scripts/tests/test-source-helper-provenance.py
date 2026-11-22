"""Check mixed payload/helper provenance coverage using isolated real files."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from source_sdk_delivery import verify_build_provenance


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    cases = []
    directory = ROOT / '.tmp/helper-provenance-tests'
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='run-', dir=directory) as raw:
        root = Path(raw)
        inputs, units = [], []
        for stage in ('payload', 'source-helper', 'source-backend'):
            source, obj = root / (stage + '.cpp'), root / (stage + '.o')
            source.write_text('// Explicit provenance test fixture.\n', encoding='utf-8')
            obj.write_bytes(stage.encode())
            inputs.append({'path': source.name, 'size': source.stat().st_size,
                           'sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'roles': ['tu']})
            units.append({'stage': stage, 'source': source.name, 'build_source': source.name,
                          'object': obj.name, 'bytes': obj.stat().st_size,
                          'sha256': hashlib.sha256(obj.read_bytes()).hexdigest(),
                          'dependencies': [source.name], 'dependency_kind': 'compiler-mmd'})
        child = {'schema': 'maplesu-sdk-source-provenance/1', 'closure_complete': True,
                 'incomplete_reasons': [], 'runtime_acceptance': False,
                 'inputs': inputs[:2], 'translation_units': units[:2]}
        backend = {**child, 'inputs': inputs[2:], 'translation_units': units[2:]}
        proof = {**copy.deepcopy(child),
                 'inputs': copy.deepcopy(inputs), 'translation_units': copy.deepcopy(units),
                 'optional_inputs': [{'path': 'absent-rule.json', 'role': 'build_rule', 'present': False}],
                 'toolchain': {'ndk_root': 'fixture', 'ndk_version': 'fixture', 'target': 'fixture',
                               'versions': {name: 'fixture' for name in ('clang', 'llvm-ar', 'ld.lld')}}}
        baseline = {'provenance': proof, 'stages_run': ['gate'], 'compile': {'rows': []},
                    'compose': {'rows': []}, 'payloads': {'provenance': child},
                    'source_backend': {'provenance': backend}}
        assert verify_build_provenance(baseline, root) == inputs
        cases.append({'name': 'payload helper and backend receipts pass exact coverage', 'status': 'PASS'})

        def reject(name, change, expected):
            report = copy.deepcopy(baseline)
            change(report)
            try:
                verify_build_provenance(report, root)
            except AssertionError as exc:
                assert expected in str(exc), (name, str(exc))
            else:
                raise AssertionError(name + ': accepted changed receipt')
            cases.append({'name': name, 'status': 'PASS'})

        reject('unknown stage', lambda r: r['provenance']['translation_units'][1].update(stage='unknown'),
               'SOURCE_SDK_PROVENANCE_STAGE')
        reject('duplicate helper unit', lambda r: r['provenance']['translation_units'].append(
            copy.deepcopy(r['provenance']['translation_units'][1])), 'SOURCE_SDK_PROVENANCE_UNITS')
        reject('helper omitted from child', lambda r: r['payloads']['provenance']['translation_units'].pop(),
               'SOURCE_SDK_CHILD_COVERAGE')
        reject('helper omitted from parent', lambda r: r['provenance']['translation_units'].pop(1),
               'SOURCE_SDK_CHILD_UNIT')
        reject('helper mislabeled in child', lambda r: r['payloads']['provenance']['translation_units'][1].update(
            stage='payload'), 'SOURCE_SDK_CHILD_UNIT')
        reject('helper duplicated across receipts', lambda r: r.update(assets={'experimental_helper': {
            'provenance': copy.deepcopy(child)}}), 'SOURCE_SDK_CHILD_UNIT')
        reject('helper source drift', lambda r: r['provenance']['inputs'][1].update(sha256='0' * 64),
               'SOURCE_SDK_STALE')
        reject('helper receipt incomplete', lambda r: r['payloads']['provenance'].update(closure_complete=False),
               'SOURCE_SDK_CHILD_PROVENANCE')
        reject('helper receipt claims device acceptance', lambda r: r['payloads']['provenance'].update(runtime_acceptance=True),
               'SOURCE_SDK_CHILD_SCOPE')
        reject('backend child missing', lambda r: r.pop('source_backend'), 'SOURCE_SDK_CHILD_COVERAGE')
        reject('backend omitted from parent', lambda r: r['provenance']['translation_units'].pop(),
               'SOURCE_SDK_CHILD_UNIT')
        reject('backend omitted from child', lambda r: r['source_backend']['provenance']['translation_units'].clear(),
               'SOURCE_SDK_CHILD_INPUTS')
        reject('backend mislabeled as payload', lambda r: r['source_backend']['provenance']['translation_units'][0].update(stage='payload'),
               'SOURCE_SDK_CHILD_UNIT')
        reject('backend source drift', lambda r: r['provenance']['inputs'][2].update(sha256='0' * 64),
               'SOURCE_SDK_STALE')
        assert verify_build_provenance(baseline, root) == inputs
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({'schema': 'maplesu-source-helper-provenance-tests/1',
                                        'cases': cases, 'deviceTested': False}, indent=2) + '\n', encoding='utf-8')
    print(f'{len(cases)} source helper provenance checks PASS')


if __name__ == '__main__':
    main()
