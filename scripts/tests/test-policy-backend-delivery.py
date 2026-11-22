"""Exercise the production build gate with the real SDK and captured PLR110 regression."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from policy_backend_delivery import verify_delivery, verify_kernel_read_repair, verify_helper_kernel_read_repair, digest

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--manifest', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
manifest = json.loads(a.manifest.read_text())
results = []

def backend_fixture(symbols, marker):
    names = b'\0.shstrtab\0.strtab\0.symtab\0.text\0'
    strings = b'\0'
    table = bytes(24)
    for name, (section, kind) in symbols.items():
        table += struct.pack('<IBBHQQ', len(strings), kind, 0, section, 0, 0)
        strings += name.encode() + b'\0'
    raw = bytearray(64)
    headers = [bytes(64)]
    for name, kind, data, link, info, entry in (
            ('.shstrtab', 3, names, 0, 0, 0), ('.strtab', 3, strings, 0, 0, 0),
            ('.symtab', 2, table, 2, 1, 24), ('.text', 1, marker, 0, 0, 0)):
        raw.extend(bytes(-len(raw) % 8))
        headers.append(struct.pack('<IIQQQQIIQQ', names.index(name.encode()), kind, 0, 0,
                                   len(raw), len(data), link, info, 8, entry))
        raw.extend(data)
    raw.extend(bytes(-len(raw) % 8))
    raw[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                          1, 183, 1, 0, 0, len(raw), 0, 64, 0, 0, 64, len(headers), 1)
    return bytes(raw) + b''.join(headers)


def kernel_read_contracts():
    canonical = '_ZN13kernel_module23request_kernel_read_memEmPvj'
    prepare = 'maplesu_prepare_kernel_request'
    with tempfile.TemporaryDirectory(prefix='kernel-read-contract-') as temporary:
        root = Path(temporary).resolve()
        sources = {}
        for name in ('runtime/ultra/authorization/kernel_read.cpp', 'scripts/update-ultra-kernel-read.py',
                     'runtime/ultra/authorization/kernel_read_metadata.h',
                     'runtime/maplesu-sdk/include/module_err_def.h', 'runtime/maplesu-sdk/include/aarch64_asm_helper.h',
                     'runtime/maplesu-sdk/include/module_base_kernel_mem.h',
                     'runtime/maplesu-sdk/include/module_base_kernel_symbol_kaddr.h'):
            source = root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b'fixture source\n')
            sources[name] = digest(source)
        repair = dict(deliveredArchiveSha256='a'*64, deliveredHelperSha256='b'*64,
                      policyBackendSha256='c'*64, sources=sources,
                      memberDiff=dict(changed=[dict(ord=23, name='module_base_kernel_request.o', candidateSha256='d'*64)]))
        fixture = dict(manifest=dict(archive=dict(sha256='a'*64), helper=dict(sha256='b'*64),
                                     environmentPolicyBoot=dict(backend=dict(sha256='c'*64)), kernelReadRepair=repair),
                       members=[dict(ord=i, name='fixture.o', sha256='d'*64) for i in range(24)],
                       symbols={canonical: (4, 0x12), prepare: (4, 0x12)}, marker=b'copy_to_user_nofault\0')
        fixture['members'][23]['name'] = 'module_base_kernel_request.o'

        def check(name, mutate=lambda c: None, expected=None):
            candidate = copy.deepcopy(fixture)
            mutate(candidate)
            try:
                verify_kernel_read_repair(candidate['manifest'], root, candidate['members'],
                                          backend_fixture(candidate['symbols'], candidate['marker']))
                passed = expected is None
            except AssertionError as e:
                passed = expected is not None and expected in str(e)
                if not passed: raise
            assert passed, name
            results.append(dict(name=name, passed=True))

        check('kernel-read-contract-paired')
        check('kernel-read-contract-optional', lambda c: c['manifest'].pop('kernelReadRepair'))
        for field, error in (('deliveredArchiveSha256', 'SDK'), ('deliveredHelperSha256', 'HELPER'),
                             ('policyBackendSha256', 'BACKEND')):
            check('kernel-read-contract-' + error.lower(), lambda c: c['manifest']['kernelReadRepair'].update(
                {field: '0'*64}), 'KERNEL_READ_' + error + '_STALE')
        check('kernel-read-source-stale', lambda c: c['manifest']['kernelReadRepair']['sources'].update(
            {'runtime/ultra/authorization/kernel_read.cpp': '0'*64}), 'KERNEL_READ_SOURCE_STALE')
        check('kernel-read-source-missing', lambda c: c['manifest']['kernelReadRepair']['sources'].pop(
            'runtime/ultra/authorization/kernel_read.cpp'), 'KERNEL_READ_SOURCE_MISSING')
        check('kernel-read-source-empty', lambda c: c['manifest']['kernelReadRepair'].update(sources={}),
              'KERNEL_READ_SOURCE_MISSING')
        for source in sources:
            check('kernel-read-required-source-' + Path(source).name,
                  lambda c: c['manifest']['kernelReadRepair']['sources'].pop(source), 'KERNEL_READ_SOURCE_MISSING')
        check('kernel-read-source-path-escape', lambda c: c['manifest']['kernelReadRepair']['sources'].update(
            {'../outside.cpp': '0'*64}), 'KERNEL_READ_SOURCE_STALE')
        check('kernel-read-member-sha', lambda c: c['members'][23].update(sha256='0'*64), 'KERNEL_READ_MEMBER_STALE')
        check('kernel-read-member-order', lambda c: c['members'][23].update(ord=22), 'KERNEL_READ_MEMBER_STALE')
        check('kernel-read-member-name', lambda c: c['members'][23].update(name='other.o'), 'KERNEL_READ_MEMBER_STALE')
        check('kernel-read-member-duplicate', lambda c: c['manifest']['kernelReadRepair']['memberDiff']['changed'].append(
            copy.deepcopy(c['manifest']['kernelReadRepair']['memberDiff']['changed'][0])), 'KERNEL_READ_MEMBER_STALE')
        check('kernel-read-archive-member-duplicate', lambda c: c['members'].append(copy.deepcopy(c['members'][23])),
              'KERNEL_READ_MEMBER_STALE')
        for symbol, label in ((canonical, 'canonical'), (prepare, 'prepare')):
            check('kernel-read-' + label + '-missing', lambda c: c['symbols'].pop(symbol), 'KERNEL_READ_BACKEND_MISSING')
            check('kernel-read-' + label + '-undefined', lambda c: c['symbols'].update(
                {symbol: (0, 0x12)}), 'KERNEL_READ_BACKEND_MISSING')
            check('kernel-read-' + label + '-data-symbol', lambda c: c['symbols'].update(
                {symbol: (4, 0x11)}), 'KERNEL_READ_BACKEND_MISSING')
            for section, kind in ((0xfff1, 'absolute'), (0xfff2, 'common'), (100, 'section-overflow')):
                check('kernel-read-' + label + '-' + kind, lambda c: c['symbols'].update(
                    {symbol: (section, 0x12)}), 'KERNEL_READ_BACKEND_MISSING')
        check('kernel-read-wrapper-is-not-canonical', lambda c: c['symbols'].update(
            {'__wrap_' + canonical: c['symbols'].pop(canonical)}), 'KERNEL_READ_BACKEND_MISSING')
        check('kernel-read-wrapper-coexistence-rejected', lambda c: c['symbols'].update(
            {'__wrap_' + canonical: (4, 0x12)}), 'KERNEL_READ_BACKEND_WRAPPED')
        check('kernel-read-nofault-marker-missing', lambda c: c.update(marker=b'__arch_copy_to_user\0'),
              'KERNEL_READ_NOFAULT_MISSING')


def helper_kernel_read_contracts():
    helper = bytearray(512)
    helper[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + bytes(9),
                             3, 183, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    helper[64:120] = struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, len(helper), len(helper), 4096)
    helper[192:196] = bytes.fromhex('00000014')
    helper[256:272] = b'kernel-read-code'
    delivered = hashlib.sha256(helper).hexdigest()
    report = dict(passed=True, helperSha256='e'*64, baselineHelperSha256='f'*64)
    with tempfile.TemporaryDirectory(prefix='helper-kernel-read-contract-') as temporary:
        root = Path(temporary).resolve()
        sources = {}
        for name in ('runtime/ultra/authorization/helper_kernel_read.cpp', 'runtime/ultra/authorization/helper_kernel_read.S',
                     'scripts/update-ultra-helper-kernel-read.py', 'runtime/ultra/authorization/kernel_read_metadata.h'):
            source = root / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b'fixture source\n')
            sources[name] = digest(source)
        replay = root / 'work/replay.json'
        replay.parent.mkdir(parents=True, exist_ok=True)
        replay.write_text(json.dumps(report))
        repair = dict(deliveredArchiveSha256='a'*64, policyBackendSha256='c'*64,
                      deliveredHelperSha256=delivered, helperSha256='e'*64, baselineHelperSha256='f'*64,
                      sources=sources, entryPatch=dict(offset=192, baselineHex='fd7bbfa9', candidateHex='00000014'),
                      extension=dict(offset=256, address=0x400100, bytes=16,
                                     sha256=hashlib.sha256(helper[256:272]).hexdigest()),
                      callbackReplay=dict(path='work/replay.json', sha256=digest(replay)))
        fixture = dict(manifest=dict(archive=dict(sha256='a'*64), helper=dict(sha256=delivered),
                                     environmentPolicyBoot=dict(backend=dict(sha256='c'*64)), helperKernelReadRepair=repair),
                       helper=helper)

        def check(name, mutate=lambda c: None, expected=None, change_report=None):
            candidate = copy.deepcopy(fixture)
            mutate(candidate)
            evidence = copy.deepcopy(report)
            if change_report:
                change_report(evidence)
            replay.write_text(json.dumps(evidence))
            if change_report:
                candidate['manifest']['helperKernelReadRepair']['callbackReplay']['sha256'] = digest(replay)
            try:
                verify_helper_kernel_read_repair(candidate['manifest'], root, candidate['helper'])
                passed = expected is None
            except AssertionError as e:
                passed = expected is not None and expected in str(e)
                if not passed: raise
            assert passed, name
            results.append(dict(name=name, passed=True))

        check('helper-kernel-read-final-paired-and-baseline-patch-replaced')
        check('helper-kernel-read-optional', lambda c: c['manifest'].pop('helperKernelReadRepair'))
        for field, error in (('deliveredArchiveSha256', 'SDK'), ('policyBackendSha256', 'BACKEND'),
                             ('deliveredHelperSha256', 'HELPER')):
            check('helper-kernel-read-contract-' + error.lower(),
                  lambda c: c['manifest']['helperKernelReadRepair'].update({field: '0'*64}),
                  'HELPER_KERNEL_READ_' + error + '_STALE')
        check('helper-kernel-read-actual-helper-sha', lambda c: c['helper'].__setitem__(128, 1),
              'HELPER_KERNEL_READ_HELPER_STALE')
        check('helper-kernel-read-source-stale', lambda c: c['manifest']['helperKernelReadRepair']['sources'].update(
            {'runtime/ultra/authorization/helper_kernel_read.cpp': '0'*64}), 'HELPER_KERNEL_READ_SOURCE_STALE')
        check('helper-kernel-read-metadata-missing', lambda c: c['manifest']['helperKernelReadRepair']['sources'].pop(
            'runtime/ultra/authorization/kernel_read_metadata.h'), 'HELPER_KERNEL_READ_SOURCE_MISSING')
        for source in sources:
            check('helper-kernel-read-required-source-' + Path(source).name,
                  lambda c: c['manifest']['helperKernelReadRepair']['sources'].pop(source), 'HELPER_KERNEL_READ_SOURCE_MISSING')
        check('helper-kernel-read-source-path-escape', lambda c: c['manifest']['helperKernelReadRepair']['sources'].update(
            {'../outside.c': '0'*64}), 'HELPER_KERNEL_READ_SOURCE_STALE')
        for field, value in (('offset', 193), ('candidateHex', '01000014'), ('baselineHex', '00')):
            check('helper-kernel-read-entry-' + field,
                  lambda c: c['manifest']['helperKernelReadRepair']['entryPatch'].update({field: value}),
                  'HELPER_KERNEL_READ_ENTRY_STALE')
        for field, value in (('offset', 257), ('bytes', 0), ('address', 0x400101), ('sha256', '0'*64)):
            check('helper-kernel-read-extension-' + field,
                  lambda c: c['manifest']['helperKernelReadRepair']['extension'].update({field: value}),
                  'HELPER_KERNEL_READ_EXTENSION_STALE')
        def remove_execute_permission(c):
            struct.pack_into('<I', c['helper'], 68, 4)
            changed = hashlib.sha256(c['helper']).hexdigest()
            c['manifest']['helper']['sha256'] = changed
            c['manifest']['helperKernelReadRepair']['deliveredHelperSha256'] = changed
        check('helper-kernel-read-extension-not-executable', remove_execute_permission, 'HELPER_KERNEL_READ_EXTENSION_STALE')
        check('helper-kernel-read-replay-hash', lambda c: c['manifest']['helperKernelReadRepair']['callbackReplay'].update(
            sha256='0'*64), 'HELPER_KERNEL_READ_REPLAY_STALE')
        check('helper-kernel-read-replay-path-escape', lambda c: c['manifest']['helperKernelReadRepair']['callbackReplay'].update(
            path='../replay.json'), 'HELPER_KERNEL_READ_REPLAY_STALE')
        for field, value in (('passed', False), ('helperSha256', '0'*64), ('baselineHelperSha256', '0'*64)):
            check('helper-kernel-read-replay-' + field, expected='HELPER_KERNEL_READ_REPLAY_UNPAIRED',
                  change_report=lambda r: r.update({field: value}))


kernel_read_contracts()
helper_kernel_read_contracts()


def run(name, mutate, expected=None):
    candidate = copy.deepcopy(manifest)
    mutate(candidate)
    try:
        verify_delivery(candidate, ROOT)
        passed = expected is None
    except AssertionError as e:
        passed = expected is not None and expected in str(e)
        if not passed: raise
    assert passed, name
    results.append(dict(name=name, passed=True))

run('paired-production-artifacts', lambda m: None)
run('kernel-read-sdk-paired', lambda m: m.setdefault('kernelReadRepair', {}).update(
    deliveredArchiveSha256='0'*64), 'KERNEL_READ_SDK_STALE')
run('helper-kernel-read-sdk-paired', lambda m: m.setdefault('helperKernelReadRepair', {}).update(
    deliveredArchiveSha256='0'*64), 'HELPER_KERNEL_READ_SDK_STALE')
run('old-backend-never-packaged-as-new', lambda m: m['environmentPolicyBoot'].pop('delivery'), 'POLICY_BACKEND_STALE')
run('missing-consent-protocol', lambda m: m['environmentPolicyBoot']['delivery'].update(consentRequest=3), 'POLICY_BACKEND_STALE')
run('source-edit-requires-backend-rebuild', lambda m: m['environmentPolicyBoot']['delivery']['sourceSha256'].update(
    {'runtime/ultra/policy/module_policy_config.cpp': '0'*64}), 'POLICY_BACKEND_SOURCE_STALE')
run('dynamic-layout-schema-edit-requires-backend-rebuild', lambda m: m['environmentPolicyBoot']['delivery']['sourceSha256'].update(
    {'runtime/ultra/policy/policy_layout_slots.h': '0'*64}), 'POLICY_BACKEND_SOURCE_STALE')
run('dynamic-accessor-edit-requires-payload-rebuild', lambda m: m['environmentPolicyBoot']['delivery']['sourceSha256'].update(
    {'runtime/ultra/policy/kernel/policy_dynamic_layout.h': '0'*64}), 'POLICY_BACKEND_SOURCE_STALE')
run('paired-helper-required', lambda m: m['environmentPolicyBoot'].update(entryHelperSha256='0'*64), 'POLICY_BACKEND_HELPER_STALE')
run('six-kernel-profiles-retained', lambda m: m['environmentPolicyBoot']['delivery']['bundles'].pop(), 'POLICY_BACKEND_PROFILE_MISSING')
run('generated-bundle-pinned', lambda m: m['environmentPolicyBoot']['delivery']['bundleManifest'].update(sha256='0'*64), 'POLICY_BACKEND_BUNDLE_MANIFEST_STALE')
if 'credentialSnapshotRepair' in manifest:
    run('snapshot-sdk-paired', lambda m: m['credentialSnapshotRepair'].update(deliveredArchiveSha256='0'*64),
        'CREDENTIAL_SNAPSHOT_SDK_STALE')
    run('snapshot-backend-paired', lambda m: m['credentialSnapshotRepair'].update(policyBackendSha256='0'*64),
        'CREDENTIAL_SNAPSHOT_BACKEND_STALE')
    run('snapshot-helper-paired', lambda m: m['credentialSnapshotRepair'].update(deliveredHelperSha256='0'*64),
        'CREDENTIAL_SNAPSHOT_HELPER_STALE')
    run('snapshot-source-edit-requires-rebuild', lambda m: m['credentialSnapshotRepair']['sources'].update(
        {'runtime/ultra/authorization/credential_snapshot.cpp': '0'*64}), 'CREDENTIAL_SNAPSHOT_SOURCE_STALE')
    run('snapshot-member-pinned', lambda m: m['credentialSnapshotRepair']['memberDiff']['changed'][0].update(
        candidateSha256='0'*64), 'CREDENTIAL_SNAPSHOT_MEMBER_STALE')
def old_contract(m):
    item = next(b for b in m['environmentPolicyBoot']['delivery']['bundles'] if b['kernelSeries'] == '6.12')
    contract = json.loads((ROOT / item['compatibility']['path']).read_text())
    contract['equivalentConfigs'] = []
    f = Path(temporary) / 'kernel-compatibility.json'
    f.write_text(json.dumps(contract))
    item['compatibility'] = dict(path=f.relative_to(ROOT).as_posix(), sha256=digest(f))
a.output.parent.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='policy-delivery-', dir=a.output.parent.resolve()) as temporary:
    run('plr110-previously-missed-proof-rejected', old_contract, 'POLICY_BACKEND_CONFIG_PROOF_MISSING')
record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=True, cases=len(results), results=results,
              manifestSha256=digest(a.manifest), deviceAccess=False)
a.output.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
