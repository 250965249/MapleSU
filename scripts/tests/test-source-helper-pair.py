"""Validate a real complete-source helper/backend pair and changed receipts."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from source_sdk_delivery import record, source_helper_identity, verify_source_helper_pair


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--helper-report', type=Path, required=True)
    parser.add_argument('--build-root', type=Path)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    helper = args.helper.resolve()
    build_root = args.build_root.resolve() if args.build_root else None
    receipt = json.loads(args.helper_report.read_text(encoding='utf-8'))
    backend = Path(receipt['backend']['source'])
    directory = ROOT / '.tmp/helper-pair-tests'
    directory.mkdir(parents=True, exist_ok=True)
    cases = []
    with tempfile.TemporaryDirectory(prefix='run-', dir=directory) as raw:
        report_path = Path(raw) / 'helper-build.json'
        report_path.write_text(json.dumps(receipt), encoding='utf-8')

        def fixtures(changed=None):
            saved = copy.deepcopy(receipt)
            if changed:
                changed(saved)
            report_path.write_text(json.dumps(saved), encoding='utf-8')
            source = {'helperOrigin': 'source-built', 'helperBuildReport': record(report_path, ROOT)}
            build = {'source_helper': saved, 'assets': {'helper': {
                'builtFromSource': True, 'origin': 'source-built',
                'report': source['helperBuildReport'], 'sha256': record(helper, ROOT)['sha256']}},
                'payloads': {'provenance': copy.deepcopy(receipt['provenance'])}}
            manifest = {'helper': dict(source_helper_identity(helper, receipt), **record(helper, ROOT))}
            return manifest, source, build

        baseline = fixtures()
        assert verify_source_helper_pair(*baseline, helper, backend, ROOT, build_root) == receipt
        cases.append({'name': 'actual source helper backend and padded slot match build receipt', 'status': 'PASS'})

        def reject(name, change, diagnostic):
            values = fixtures()
            change(*values)
            try:
                verify_source_helper_pair(*values, helper, backend, ROOT, build_root)
            except AssertionError as exc:
                assert diagnostic in str(exc), (name, str(exc))
            else:
                raise AssertionError(name + ': accepted changed receipt')
            cases.append({'name': name, 'status': 'PASS'})

        reject('source origin omitted', lambda m, s, b: s.update(helperOrigin='reference-copy'), 'SOURCE_SDK_HELPER_SOURCE_SELECTION')
        reject('reference helper selection', lambda m, s, b: b['assets']['helper'].update(builtFromSource=False), 'SOURCE_SDK_HELPER_SOURCE_SELECTION')
        reject('helper build id drift', lambda m, s, b: m['helper'].update(buildId='0' * 40), 'SOURCE_SDK_HELPER_IDENTITY')
        reject('helper normalized identity drift', lambda m, s, b: m['helper'].update(normalizedSha256='0' * 64), 'SOURCE_SDK_HELPER_IDENTITY')
        reject('parent helper receipt drift', lambda m, s, b: b['source_helper']['surface'].update(sha256='0' * 64), 'SOURCE_SDK_HELPER_BUILD_RECEIPT')
        reject('helper dependency omitted from payload receipt', lambda m, s, b: b['payloads']['provenance']['inputs'].pop(), 'SOURCE_SDK_HELPER_INPUT_RECEIPT')

        for name, change, diagnostic in (
            ('experimental helper receipt', lambda r: r.update(readiness='experimental'), 'SOURCE_SDK_HELPER_SOURCE_READINESS'),
            ('backend hash drift', lambda r: r['backend'].update(sha256='0' * 64), 'SOURCE_SDK_BACKEND_SOURCE_PAIR'),
            ('backend filename drift', lambda r: r['backend'].update(filename='other.so'), 'SOURCE_SDK_BACKEND_SOURCE_PAIR'),
            ('backend note drift', lambda r: r['backend'].update(noteHex='00'), 'SOURCE_SDK_BACKEND_SOURCE_PAIR'),
            ('helper source closure missing', lambda r: r['provenance'].update(closure_complete=False), 'SOURCE_SDK_HELPER_PROVENANCE'),
        ):
            values = fixtures(change)
            try:
                verify_source_helper_pair(*values, helper, backend, ROOT, build_root)
            except AssertionError as exc:
                assert diagnostic in str(exc), (name, str(exc))
            else:
                raise AssertionError(name + ': accepted changed receipt')
            cases.append({'name': name, 'status': 'PASS'})
        assert verify_source_helper_pair(*fixtures(), helper, backend, ROOT, build_root) == receipt

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({'schema': 'maplesu-source-helper-pair-tests/1',
                                        'cases': cases, 'deviceTested': False}, indent=2) + '\n', encoding='utf-8')
    print(f'{len(cases)} actual source helper pairing checks PASS')


if __name__ == '__main__':
    main()
