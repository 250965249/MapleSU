"""Validate one real isolated source candidate and reject mutations without rebuilding it."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from source_sdk_delivery import checked, record, verify_source_build_status, verify_source_delivery


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.candidate / 'SDK-RELEASE.json').read_text(encoding='utf-8'))
    source = manifest['sourceBuild']
    build_root = Path(source['buildDirectory']).resolve()
    report_path = checked(source['buildReport'], ROOT, build_root)
    build = json.loads(report_path.read_text(encoding='utf-8'))
    review = source['sourceValidation']['review']
    result = verify_source_delivery(manifest, ROOT)
    rows = [dict(case='real-source-validation-candidate', passed=True, result=result)]

    def rejected(name, changed, review_item=review):
        try:
            verify_source_build_status(changed, report_path, ROOT, build_root, review_item)
        except (AssertionError, KeyError, ValueError) as error:
            rows.append(dict(case=name, passed=True, rejection=str(error)))
        else:
            raise AssertionError('Mutation accepted: ' + name)

    mutations = [
        ('other-stage-failure', lambda b: b['failure'].update(exit_code=5)),
        ('old-producer', lambda b: b['invocation']['argv'].remove('--capture-source-validation')),
        ('compile-failure', lambda b: b['compile']['failures'].append({'idx': 0})),
        ('incomplete-provenance', lambda b: b['provenance'].update(closure_complete=False)),
        ('claimed-device-acceptance', lambda b: b['source_validation'].update(runtime_acceptance=True)),
        ('link-gc-enabled', lambda b: b['source_validation']['link']['argv'].append('-Wl,--gc-sections')),
        ('link-failed', lambda b: b['source_validation']['link'].update(exit_code=1)),
        ('output-stale', lambda b: b['source_validation']['link']['output'].update(sha256='0' * 64)),
    ]
    for name, mutate in mutations:
        changed = copy.deepcopy(build)
        mutate(changed)
        rejected(name, changed)
    rejected('raw-failure-without-explicit-review', build, None)
    stale_review = dict(review, sha256='0' * 64)
    rejected('stale-review', build, stale_review)
    with tempfile.TemporaryDirectory(dir=ROOT / '.tmp', prefix='source-validation-fixture-') as temporary:
        fixture = Path(temporary)
        original_index = json.loads((ROOT / review['path']).read_text(encoding='utf-8'))
        for name, mutate in [
            ('missing-reviewed-member', lambda c: c['members'].pop()),
            ('changed-reviewed-delta', lambda c: c['members'][0]['rawDiffs']['u_extra'].append('unreviewed_import')),
            ('wrong-reviewed-ordinal', lambda c: c['members'][0].update(ordinal=2)),
        ]:
            case = fixture / name
            case.mkdir()
            index = copy.deepcopy(original_index)
            for item in index['reviewFiles']:
                target = case / Path(item['path']).name
                shutil.copyfile(item['path'], target)
                if target.name == 'COVERAGE.json':
                    coverage = json.loads(target.read_text(encoding='utf-8'))
                    mutate(coverage)
                    target.write_text(json.dumps(coverage) + '\n', encoding='utf-8')
                item.update(record(target, ROOT))
            path = case / 'REVIEW-INDEX.json'
            path.write_text(json.dumps(index) + '\n', encoding='utf-8')
            rejected(name, build, record(path, ROOT))
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'RESULT.json').write_text(json.dumps(dict(passed=True, cases=rows,
        scope='One real fresh source candidate; in-memory build mutations and ordinary review-file fixture copies. No SDK source/object/report mutations, build, link, device or partition operation.'), indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=True, cases=len(rows), output=str(output))))


if __name__ == '__main__':
    main()
