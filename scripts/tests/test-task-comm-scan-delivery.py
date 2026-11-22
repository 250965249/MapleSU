"""Reject stale pairing or a broken historical m001 repair chain."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from policy_backend_delivery import TASK_COMM_SCAN_SOURCES, digest, verify_task_comm_scan_repair

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
release = json.loads((ROOT / 'runtime/maplesu-sdk/SDK-RELEASE.json').read_text())
compiled = (ROOT / release['environmentPolicyBoot']['backend']['path']).read_bytes()
results = []
with tempfile.TemporaryDirectory(prefix='task-comm-contract-') as temporary:
    root = Path(temporary).resolve()
    sources = {}
    for name in TASK_COMM_SCAN_SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'fixture source\n')
        sources[name] = digest(path)
    snapshot = dict(memberDiff=dict(changed=[dict(ord=1, name='task_struct.o', candidateSha256='d'*64)]))
    repair = dict(deliveredArchiveSha256='a'*64, deliveredHelperSha256='b'*64, policyBackendSha256='c'*64,
        sources=sources, baselineCredentialSnapshotMemberSha256='d'*64,
        memberDiff=dict(changed=[dict(ord=1, name='task_struct.o', baselineSha256='d'*64,
                                     candidateSha256='e'*64)], added=[], removed=[], orderErrors=[]),
        requestIsolationPreserved=True, originalM001TextPreserved=True,
        originalM001RelocationsPreserved=True, canonicalStrongDefinition=True,
        originalOtherGlobalDefinitionsPreserved=True)
    fixture = dict(manifest=dict(archive=dict(sha256='a'*64), helper=dict(sha256='b'*64),
        environmentPolicyBoot=dict(backend=dict(sha256='c'*64)), credentialSnapshotRepair=snapshot,
        taskCommScanRepair=repair), members=[dict(ord=0, name='fixture.o', sha256='0'*64),
            dict(ord=1, name='task_struct.o', sha256='e'*64)], compiled=compiled)

    def check(name, mutate=lambda c: None, expected=None):
        candidate = copy.deepcopy(fixture)
        mutate(candidate)
        try:
            verify_task_comm_scan_repair(candidate['manifest'], root, candidate['members'], candidate['compiled'])
            passed = expected is None
        except AssertionError as error:
            passed = expected is not None and expected in str(error)
            if not passed:
                raise
        assert passed, name
        results.append(dict(name=name, passed=True))

    check('paired-history-preserved')
    check('optional-old-release', lambda c: c['manifest'].pop('taskCommScanRepair'))
    for field, error in (('deliveredArchiveSha256', 'SDK'), ('deliveredHelperSha256', 'HELPER'),
                         ('policyBackendSha256', 'BACKEND')):
        check('pair-' + error.lower(), lambda c: c['manifest']['taskCommScanRepair'].update({field:'0'*64}),
              'TASK_COMM_SCAN_' + error + '_STALE')
    for source in TASK_COMM_SCAN_SOURCES:
        check('required-source-' + Path(source).name,
              lambda c: c['manifest']['taskCommScanRepair']['sources'].pop(source), 'TASK_COMM_SCAN_SOURCE_MISSING')
    check('stale-source', lambda c: c['manifest']['taskCommScanRepair']['sources'].update(
        {'runtime/ultra/authorization/task_comm_scan.cpp':'0'*64}), 'TASK_COMM_SCAN_SOURCE_STALE')
    check('source-path-traversal', lambda c: c['manifest']['taskCommScanRepair']['sources'].update(
        {'../outside.cpp':'0'*64}), 'TASK_COMM_SCAN_SOURCE_STALE')
    check('snapshot-required', lambda c: c['manifest'].pop('credentialSnapshotRepair'), 'TASK_COMM_SCAN_SNAPSHOT_REQUIRED')
    check('old-snapshot-hash-retained', lambda c: c['manifest']['credentialSnapshotRepair']['memberDiff']['changed'][0].update(
        candidateSha256='e'*64), 'TASK_COMM_SCAN_SNAPSHOT_CHAIN_STALE')
    check('explicit-snapshot-anchor', lambda c: c['manifest']['taskCommScanRepair'].update(
        baselineCredentialSnapshotMemberSha256='0'*64), 'TASK_COMM_SCAN_SNAPSHOT_CHAIN_STALE')
    check('diff-baseline-anchor', lambda c: c['manifest']['taskCommScanRepair']['memberDiff']['changed'][0].update(
        baselineSha256='0'*64), 'TASK_COMM_SCAN_SNAPSHOT_CHAIN_STALE')
    check('candidate-member', lambda c: c['members'][1].update(sha256='0'*64), 'TASK_COMM_SCAN_MEMBER_STALE')
    check('duplicate-member', lambda c: c['members'].append(c['members'][1]), 'TASK_COMM_SCAN_MEMBER_STALE')
    for field in ('added', 'removed', 'orderErrors'):
        check('unexpected-diff-' + field, lambda c: c['manifest']['taskCommScanRepair']['memberDiff'].update(
            {field:[{}]}), 'TASK_COMM_SCAN_MEMBER_STALE')
    for field in ('requestIsolationPreserved', 'originalM001TextPreserved', 'originalM001RelocationsPreserved',
                  'canonicalStrongDefinition', 'originalOtherGlobalDefinitionsPreserved'):
        check('required-' + field, lambda c: c['manifest']['taskCommScanRepair'].update({field:False}),
              'TASK_COMM_SCAN_IMPLEMENTATION_CONTRACT')
    for symbol in ('_ZN13kernel_module27get_task_struct_comm_offsetERj', 'maplesu_find_real_cred_offset'):
        check('backend-definition-' + symbol, lambda c: c.update(
            compiled=c['compiled'].replace(symbol.encode() + b'\0', b'x' * len(symbol) + b'\0')),
            'TASK_COMM_SCAN_BACKEND_MISSING')

report = dict(passed=True, cases=len(results), deviceRequests=False,
              results=results, backendSha256=hashlib.sha256(compiled).hexdigest())
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2) + '\n')
print(f'PASS task comm delivery: {len(results)} contracts; historical m001 anchor retained')
