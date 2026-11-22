"""Exercise actual helper publication receipts without rebuilding SDK or APK."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'runtime/maplesu-sdk/sdk/tools'))
import build_payloads as BP


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--helper-report', type=Path)
    parser.add_argument('--ndk')
    parser.add_argument('--work-dir', type=Path, default=ROOT / '.tmp/helper-payload-tests')
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    if bool(args.helper) != bool(args.helper_report):
        parser.error('--helper and --helper-report must be supplied together')
    args.work_dir.mkdir(parents=True, exist_ok=True)
    cases = []

    def reject(name, action, message):
        try:
            action()
        except ValueError as exc:
            assert message in str(exc), (name, str(exc))
        else:
            raise AssertionError(name + ': accepted invalid input')
        cases.append({'name': name, 'status': 'PASS'})

    with tempfile.TemporaryDirectory(prefix='run-', dir=args.work_dir) as raw:
        work = Path(raw)
        output = work / 'out'
        reject('source requires explicit helper pair',
               lambda: BP.build_all(None, output, None), 'require --source-helper')
        reject('source rejects helper without receipt',
               lambda: BP.build_all(None, output, None, source_helper=work / 'helper'),
               'require --source-helper')
        reject('reference comparison rejects source helper input',
               lambda: BP.build_all(None, output, None, reference_only=True,
                                    source_helper=work / 'helper'), 'does not consume')
        assert not output.exists(), 'invalid source selection wrote payload outputs'
        report_path = work / 'helper-build.json'
        report_path.write_text(json.dumps({'readiness': 'experimental'}), encoding='utf-8')
        reject('experimental helper is not promoted',
               lambda: BP.publish_source_helper(work / 'helper', report_path, work),
               'not a complete-source candidate')

        reference = BP.build_all(None, work / 'reference', None, reference_only=True)
        assert reference['summary'] == {'programs': 4, 'built': 0, 'reference_copy': 4, 'failed': 0}
        for row in reference['programs']:
            assert BP.sha256_file(work / 'reference' / row['asset']) == row['published']['sha256']
        cases.append({'name': 'four explicit reference images remain exact comparison inputs', 'status': 'PASS'})

        if args.helper:
            helper = args.helper.resolve()
            original = json.loads(args.helper_report.read_text(encoding='utf-8'))
            output.mkdir()
            published = BP.publish_source_helper(helper, args.helper_report, output)
            assert (output / 'autorun_bootstrap.bin').read_bytes() == helper.read_bytes()
            assert published['status'] == 'built'
            assert published['backend'] == original['backend']
            cases.append({'name': 'actual source helper publishes exact bytes and backend pair', 'status': 'PASS'})
            for name, change, message in (
                ('output hash drift', lambda r: r['surface'].update(sha256='0' * 64), 'bytes differ'),
                ('output size drift', lambda r: r['surface'].update(bytes=0), 'bytes differ'),
                ('output path drift', lambda r: r.update(out=str(work / 'other-helper')), 'path differs'),
                ('missing source closure', lambda r: r['provenance'].update(closure_complete=False), 'incomplete'),
                ('missing translation units', lambda r: r['provenance'].update(translation_units=[]), 'incomplete'),
                ('experimental receipt', lambda r: r.update(readiness='experimental'), 'not a complete-source'),
            ):
                changed = copy.deepcopy(original)
                change(changed)
                report_path.write_text(json.dumps(changed), encoding='utf-8')
                reject(name, lambda: BP.publish_source_helper(helper, report_path, output), message)
            changed_helper = work / 'changed-helper'
            blob = bytearray(helper.read_bytes())
            blob[-1] ^= 1
            changed_helper.write_bytes(blob)
            changed = copy.deepcopy(original)
            changed['out'] = str(changed_helper)
            report_path.write_text(json.dumps(changed), encoding='utf-8')
            reject('helper content drift',
                   lambda: BP.publish_source_helper(changed_helper, report_path, output), 'bytes differ')
            manifest = BP.build_all({'autorun_bootstrap'}, work / 'source', args.ndk,
                                    source_helper=helper, source_helper_report=args.helper_report)
            assert manifest['input_mode'] == 'source'
            assert manifest['summary'] == {'programs': 1, 'built': 1, 'reference_copy': 0, 'failed': 0}
            assert manifest['provenance']['closure_complete'], manifest['provenance']['incomplete_reasons']
            assert manifest['provenance']['translation_units'] == original['provenance']['translation_units']
            cases.append({'name': 'source-only helper retains full compiler dependency receipt', 'status': 'PASS'})

    result = {'schema': 'maplesu-helper-payload-tests/1', 'cases': cases,
              'actualSourceHelperTested': bool(args.helper), 'deviceTested': False}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f'{len(cases)} helper payload checks PASS; actual source helper tested={bool(args.helper)}')


if __name__ == '__main__':
    main()
