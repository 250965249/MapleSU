"""Reject stale module-control wait repair identities and broken historical chains."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from policy_backend_delivery import (MODULE_CONTROL_SOURCE, MODULE_CONTROL_WAIT_SOURCES, digest,
                                     historical_source_matches, verify_module_control_wait_repair)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix='module-control-wait-') as temp:
        root = Path(temp).resolve()
        sources = {}
        for name in MODULE_CONTROL_WAIT_SOURCES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture\n')
            sources[name] = digest(path)
        repair = dict(deliveredArchiveSha256='a'*64, deliveredHelperSha256='b'*64, policyBackendSha256='c'*64,
            sources=sources, baselineSourceSha256='d'*64, baselineMemberSha256='e'*64,
            baselineModuleControl=dict(sourceSha256='d'*64, memberSha256='e'*64),
            memberDiff=dict(changed=[dict(ord=255, name='maplesu_module_control.o', baselineSha256='e'*64,
                candidateSha256='f'*64)], unchanged=257, added=[], removed=[], orderErrors=[]),
            baselineExactReproduction=True, globalAbiPreserved=True, helperUnchanged=True,
            waitTimeoutMilliseconds=10000, baselineHelperSha256='b'*64)
        manifest = dict(archive=dict(sha256='a'*64), helper=dict(sha256='b'*64),
            environmentPolicyBoot=dict(backend=dict(sha256='c'*64)), moduleControlWaitRepair=repair,
            moduleControl=dict(memberSha256='f'*64, memberOrdinal=255, memberName='maplesu_module_control.o',
                               sourceSha256=sources[MODULE_CONTROL_SOURCE]))
        for name in ('requestContextRepair', 'memoryProtectionRepair', 'memoryProtectionRangeRepair'):
            manifest[name] = dict(sources={MODULE_CONTROL_SOURCE:'d'*64})
        fixture = dict(manifest=manifest, members=[dict(ord=i, name=f'fixture{i}.o', sha256='0'*64) for i in range(258)])
        fixture['members'][255] = dict(ord=255, name='maplesu_module_control.o', sha256='f'*64)

        def check(name, mutate=lambda c: None, expected=None):
            candidate = copy.deepcopy(fixture)
            mutate(candidate)
            try:
                verify_module_control_wait_repair(candidate['manifest'], root, candidate['members'])
                passed = expected is None
            except AssertionError as error:
                passed = expected is not None and expected in str(error)
                if not passed:
                    raise
            assert passed, name
            results.append(dict(name=name, passed=True))

        check('paired-history-retained')
        check('optional-old-release', lambda c: c['manifest'].pop('moduleControlWaitRepair'))
        for field, error in [('deliveredArchiveSha256', 'SDK'), ('deliveredHelperSha256', 'HELPER'),
                             ('policyBackendSha256', 'BACKEND')]:
            check('stale-' + error, lambda c: c['manifest']['moduleControlWaitRepair'].update({field:'0'*64}),
                  'MODULE_CONTROL_WAIT_' + error + '_STALE')
        for source in MODULE_CONTROL_WAIT_SOURCES:
            check('required-source-' + Path(source).name,
                  lambda c: c['manifest']['moduleControlWaitRepair']['sources'].pop(source), 'MODULE_CONTROL_WAIT_SOURCE_MISSING')
        check('stale-source', lambda c: c['manifest']['moduleControlWaitRepair']['sources'].update(
            {MODULE_CONTROL_SOURCE:'0'*64}), 'MODULE_CONTROL_WAIT_SOURCE_STALE')
        check('source-traversal', lambda c: c['manifest']['moduleControlWaitRepair']['sources'].update(
            {'../outside.cpp':'0'*64}), 'MODULE_CONTROL_WAIT_SOURCE_STALE')
        check('member-sha', lambda c: c['members'][255].update(sha256='0'*64), 'MODULE_CONTROL_WAIT_MEMBER_STALE')
        check('duplicate-member', lambda c: c['members'][254].update(name='maplesu_module_control.o'), 'MODULE_CONTROL_WAIT_MEMBER_STALE')
        check('current-source-anchor', lambda c: c['manifest']['moduleControl'].update(sourceSha256='0'*64),
              'MODULE_CONTROL_WAIT_BASELINE_CHAIN_STALE')
        check('baseline-source-anchor', lambda c: c['manifest']['moduleControlWaitRepair'].update(baselineSourceSha256='0'*64),
              'MODULE_CONTROL_WAIT_BASELINE_CHAIN_STALE')
        check('baseline-member-anchor', lambda c: c['manifest']['moduleControlWaitRepair'].update(baselineMemberSha256='0'*64),
              'MODULE_CONTROL_WAIT_BASELINE_CHAIN_STALE')
        for name in ('requestContextRepair', 'memoryProtectionRepair', 'memoryProtectionRangeRepair'):
            check('history-' + name, lambda c: c['manifest'][name]['sources'].update({MODULE_CONTROL_SOURCE:'0'*64}),
                  'MODULE_CONTROL_WAIT_HISTORY_STALE')
        for field in ('added', 'removed', 'orderErrors'):
            check('unexpected-' + field, lambda c: c['manifest']['moduleControlWaitRepair']['memberDiff'].update({field:[{}]}),
                  'MODULE_CONTROL_WAIT_MEMBER_STALE')
        for field in ('baselineExactReproduction', 'globalAbiPreserved', 'helperUnchanged', 'waitTimeoutMilliseconds'):
            check('contract-' + field, lambda c: c['manifest']['moduleControlWaitRepair'].update({field:False}),
                  'MODULE_CONTROL_WAIT_CONTRACT')
        assert historical_source_matches(manifest, root, MODULE_CONTROL_SOURCE, 'd'*64)
        assert not historical_source_matches(manifest, root, MODULE_CONTROL_SOURCE, '0'*64)
        assert not historical_source_matches(manifest, root, '../outside.cpp', '0'*64)
        results.append(dict(name='only-explicit-historical-source-accepted', passed=True))
    report = dict(passed=True, cases=len(results), results=results, deviceAccess=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'PASS module control wait delivery: {len(results)} contracts')


if __name__ == '__main__':
    main()
