"""Keep historical wait gates strict while validating the real quiet-boot rebinding."""
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from ar_archive import parse_ar
from policy_backend_delivery import verify_module_control_wait_repair


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    members = parse_ar(str(ROOT / manifest['archive']['path']))['members']
    results = []

    def check(name, mutate=lambda m, a: None, error=None):
        candidate, archive = copy.deepcopy(manifest), copy.deepcopy(members)
        mutate(candidate, archive)
        try:
            verify_module_control_wait_repair(candidate, ROOT.resolve(), archive)
            assert error is None, name + ': accepted invalid rebinding'
        except AssertionError as failure:
            assert error is not None and error in str(failure), name + ': ' + str(failure)
        results.append(dict(name=name, passed=True))

    check('real-paired-rebinding')
    check('remove-rebinding-preserves-old-strict-gate', lambda m, a: m.pop('zeroModuleQuietRepair'),
          'MODULE_CONTROL_WAIT_SOURCE_STALE')
    for field in ('baselineHelperSha256', 'deliveredHelperSha256', 'baselineArchiveSha256',
                  'deliveredArchiveSha256', 'policyBackendSha256'):
        check('rebinding-' + field, lambda m, a: m['zeroModuleQuietRepair'].update({field: '0'*64}),
              'QUIET_REBIND_CURRENT_IDENTITY')
    check('source-required', lambda m, a: m['zeroModuleQuietRepair']['sources'].pop('scripts/zero_module_quiet_delivery.py'),
          'QUIET_REBIND_SOURCE_MISSING')
    check('source-stale', lambda m, a: m['zeroModuleQuietRepair']['sources'].update({'scripts/zero_module_quiet_delivery.py': '0'*64}),
          'QUIET_REBIND_EVIDENCE_STALE')
    check('source-traversal', lambda m, a: m['zeroModuleQuietRepair']['sources'].update({'../outside': '0'*64}),
          'QUIET_REBIND_EVIDENCE_STALE')
    check('receipt-stale', lambda m, a: m['zeroModuleQuietRepair']['gateRebindReceipt'].update(sha256='0'*64),
          'QUIET_REBIND_EVIDENCE_STALE')
    check('baseline-archive-stale', lambda m, a: m['zeroModuleQuietRepair']['baselineArchive'].update(sha256='0'*64),
          'QUIET_REBIND_EVIDENCE_STALE')
    check('unrelated-member-changed', lambda m, a: a[12].update(sha256='0'*64), 'QUIET_REBIND_MEMBER_DIFF')
    check('member-order-changed', lambda m, a: a[12].update(ord=11), 'QUIET_REBIND_MEMBER_DIFF')
    check('extra-member', lambda m, a: a.append(a[-1]), 'QUIET_REBIND_MEMBER_COUNT')
    check('helper-normalized', lambda m, a: m['helper'].update(normalizedSha256='0'*64), 'QUIET_REBIND_HELPER_IDENTITY')
    check('helper-build-id', lambda m, a: m['helper'].update(buildId='0'*40), 'QUIET_REBIND_HELPER_IDENTITY')
    check('helper-size', lambda m, a: m['helper'].update(size=12), 'QUIET_REBIND_HELPER_IDENTITY')
    check('helper-keyslot', lambda m, a: m['helper'].update(keySlotOffset=12), 'QUIET_REBIND_KEY_SLOT')
    check('control-normalized', lambda m, a: m['moduleControl'].update(helperNormalizedSha256='0'*64),
          'QUIET_REBIND_CONTROL_IDENTITY')
    check('historical-helper-anchor', lambda m, a: m['moduleControlWaitRepair'].update(baselineHelperSha256='0'*64),
          'MODULE_CONTROL_WAIT_CONTRACT')
    check('historical-wait-member', lambda m, a: m['moduleControlWaitRepair']['memberDiff']['changed'][0].update(candidateSha256='0'*64),
          'MODULE_CONTROL_WAIT_MEMBER_STALE')
    check('historical-helper-unchanged-claim', lambda m, a: m['moduleControlWaitRepair'].update(helperUnchanged=False),
          'MODULE_CONTROL_WAIT_CONTRACT')
    check('false-hardware-acceptance', lambda m, a: m['zeroModuleQuietRepair'].update(deviceAcceptance=True), 'QUIET_REBIND_SCOPE')
    report = dict(passed=True, cases=len(results), results=results, productionImported=False, deviceAccess=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS quiet rebinding: ' + str(len(results)) + ' contracts')


if __name__ == '__main__':
    main()
