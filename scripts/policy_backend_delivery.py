"""Validate the compiled policy backend, its paired helper and required profiles."""
import hashlib
import io
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile
from policy_backend_identity import describe_backend
from ar_archive import parse_ar
from zero_module_quiet_delivery import verify_zero_module_quiet_repair

SOURCES = [
    'runtime/CMakeLists.txt',
    'scripts/build-ultra-policy-bundles.py',
    'scripts/build-ultra-policy-compatibility.py',
    'scripts/build-ultra-policy-config-equivalence.py',
    'scripts/policy_config_declarations.py',
    'scripts/build-ultra-policy-config-declarations.py',
    'scripts/rebind-ultra-policy-backend.py',
]
SOURCES += ['runtime/ultra/policy/' + name for name in (
    'environment_policy.cpp', 'environment_loader.c', 'environment_entry.S',
    'module_policy_config.cpp', 'module_policy_config.h', 'kernel_policy_gate.cpp', 'kernel_policy_gate.h',
    'kernel_payload.cpp', 'kernel_payload_loader.cpp', 'kernel_payload_loader.h', 'kernel_payload_metadata.cpp',
    'kernel_layout.cpp', 'kernel_layout.h', 'kernel_payload.h', 'policy_layout_slots.h',
    'kernel_payload_sdk.cpp', 'kernel_compatibility_profiles.json')]
SOURCES += sorted('runtime/ultra/policy/kernel/' + path.name for path in
                  (next(p for p in Path(__file__).resolve().parents if (p / 'runtime/CMakeLists.txt').is_file()) / 'runtime/ultra/policy/kernel').iterdir()
                  if path.suffix in ('.c', '.h', '.S') or path.name == 'Makefile')

KERNEL_READ_SOURCES = {
    'runtime/ultra/authorization/kernel_read.cpp', 'scripts/update-ultra-kernel-read.py',
    'runtime/ultra/authorization/kernel_read_metadata.h',
    *('runtime/maplesu-sdk/include/' + name for name in (
        'module_err_def.h', 'aarch64_asm_helper.h', 'module_base_kernel_mem.h', 'module_base_kernel_symbol_kaddr.h')),
}
HELPER_KERNEL_READ_SOURCES = {
    'runtime/ultra/authorization/helper_kernel_read.cpp', 'runtime/ultra/authorization/helper_kernel_read.S',
    'scripts/update-ultra-helper-kernel-read.py', 'runtime/ultra/authorization/kernel_read_metadata.h',
}
MEMORY_PROTECTION_SOURCES = {
    'scripts/update-ultra-memory-protection.py', 'scripts/update-ultra-helper-memory-protection.py',
    'scripts/package-ultra-memory-protection.py', 'runtime/ultra/boot/helper_memory_protection.S',
}
MEMORY_PROTECTION_VALIDATION = [
    'compile', 'baseline-contract', 'global-abi', 'archive-member-diff', 'helper-section-whitelist',
]
TASK_COMM_SCAN_SOURCES = {
    'runtime/ultra/authorization/task_comm_scan.cpp', 'runtime/ultra/authorization/task_comm_scan.h',
    'scripts/update-ultra-task-comm-scan.py',
    *('runtime/maplesu-sdk/include/' + name for name in (
        'module_err_def.h', 'aarch64_asm_helper.h', 'module_base_kernel_export_symbol.h',
        'module_base_kernel_export_symbol.inl', 'module_base_kernel_func_executor.h',
        'module_base_kernel_mem.h', 'kernel_offsets/task_struct.h')),
}
MODULE_CONTROL_SOURCE = 'runtime/ultra/modules/module_control.cpp'
MODULE_CONTROL_WAIT_SOURCES = {MODULE_CONTROL_SOURCE, 'runtime/tests/module_control_wait_test.cpp',
                               'scripts/tests/test-module-control-wait.py'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def historical_source_matches(manifest, root, name, expected):
    source = (root / name).resolve()
    if not source.is_relative_to(root) or not source.is_file():
        return False
    actual = digest(source)
    if actual == expected:
        return True
    repair = manifest.get('moduleControlWaitRepair', {})
    return name == MODULE_CONTROL_SOURCE and repair.get('baselineSourceSha256') == expected and \
        repair.get('sources', {}).get(name) == actual


def verify_module_control_wait_repair(manifest, root, members):
    repair = manifest.get('moduleControlWaitRepair')
    if repair is None:
        return
    for field, expected, error in (
        ('deliveredArchiveSha256', manifest['archive']['sha256'], 'SDK'),
        ('deliveredHelperSha256', manifest['helper']['sha256'], 'HELPER'),
        ('policyBackendSha256', manifest['environmentPolicyBoot']['backend']['sha256'], 'BACKEND')):
        assert repair.get(field) == expected, 'MODULE_CONTROL_WAIT_' + error + '_STALE'
    rebound = verify_zero_module_quiet_repair(manifest, root, members) if manifest.get('zeroModuleQuietRepair') else None
    sources = repair.get('sources', {})
    assert MODULE_CONTROL_WAIT_SOURCES <= sources.keys(), 'MODULE_CONTROL_WAIT_SOURCE_MISSING'
    for name, expected in sources.items():
        source = (root / name).resolve()
        historical_validator = rebound and name == 'scripts/policy_backend_delivery.py' and expected == rebound['baselineValidatorSha256'] and digest(source) == manifest['zeroModuleQuietRepair']['sources'][name]
        assert source.is_relative_to(root) and source.is_file() and (digest(source) == expected or historical_validator), \
            'MODULE_CONTROL_WAIT_SOURCE_STALE: ' + name
    delta = repair['memberDiff']
    changed = delta['changed']
    control = manifest['moduleControl']
    assert len(changed) == 1 and changed[0]['ord'] == 255 and changed[0]['name'] == 'maplesu_module_control.o' and \
        not delta.get('added') and not delta.get('removed') and not delta.get('orderErrors') and \
        delta.get('unchanged') == 257 and len(members) == 258 and members[255]['ord'] == 255 and \
        members[255]['name'] == changed[0]['name'] and \
        (rebound['baselineControlSha256'] if rebound else members[255]['sha256']) == changed[0]['candidateSha256'] and \
        members[255]['sha256'] == control.get('memberSha256') and \
        control.get('memberOrdinal') == 255 and control.get('memberName') == changed[0]['name'] and \
        sum(m['name'] == 'maplesu_module_control.o' for m in members) == 1, 'MODULE_CONTROL_WAIT_MEMBER_STALE'
    assert control.get('sourceSha256') == sources[MODULE_CONTROL_SOURCE] and \
        changed[0]['baselineSha256'] == repair.get('baselineMemberSha256') and \
        repair.get('baselineSourceSha256') == repair.get('baselineModuleControl', {}).get('sourceSha256') and \
        repair.get('baselineMemberSha256') == repair.get('baselineModuleControl', {}).get('memberSha256'), \
        'MODULE_CONTROL_WAIT_BASELINE_CHAIN_STALE'
    for name in ('requestContextRepair', 'memoryProtectionRepair', 'memoryProtectionRangeRepair'):
        previous = manifest.get(name, {}).get('sources', {}).get(MODULE_CONTROL_SOURCE)
        assert previous == repair.get('baselineSourceSha256'), 'MODULE_CONTROL_WAIT_HISTORY_STALE: ' + name
    assert repair.get('baselineExactReproduction') is True and repair.get('globalAbiPreserved') is True and \
        repair.get('helperUnchanged') is True and repair.get('waitTimeoutMilliseconds') == 10000 and \
        repair.get('baselineHelperSha256') == (rebound['baselineHelperSha256'] if rebound else manifest['helper']['sha256']), 'MODULE_CONTROL_WAIT_CONTRACT'


def verify_task_comm_scan_repair(manifest, root, members, compiled):
    repair = manifest.get('taskCommScanRepair')
    if repair is None:
        return
    assert repair.get('deliveredArchiveSha256') == manifest['archive']['sha256'], 'TASK_COMM_SCAN_SDK_STALE'
    assert repair.get('deliveredHelperSha256') == manifest['helper']['sha256'], 'TASK_COMM_SCAN_HELPER_STALE'
    assert repair.get('policyBackendSha256') == manifest['environmentPolicyBoot']['backend']['sha256'], \
        'TASK_COMM_SCAN_BACKEND_STALE'
    sources = repair.get('sources', {})
    assert TASK_COMM_SCAN_SOURCES <= sources.keys(), 'TASK_COMM_SCAN_SOURCE_MISSING'
    for name, expected in sources.items():
        source = (root / name).resolve()
        assert source.is_relative_to(root) and source.is_file() and digest(source) == expected, \
            'TASK_COMM_SCAN_SOURCE_STALE: ' + name
    snapshot = manifest.get('credentialSnapshotRepair')
    assert snapshot, 'TASK_COMM_SCAN_SNAPSHOT_REQUIRED'
    previous = snapshot['memberDiff']['changed']
    changed = repair['memberDiff']['changed']
    assert len(previous) == len(changed) == 1 and previous[0]['ord'] == changed[0]['ord'] == 1 and \
        previous[0]['name'] == changed[0]['name'] == 'task_struct.o' and \
        repair.get('baselineCredentialSnapshotMemberSha256') == previous[0]['candidateSha256'] == \
        changed[0]['baselineSha256'], 'TASK_COMM_SCAN_SNAPSHOT_CHAIN_STALE'
    assert not repair['memberDiff'].get('added') and not repair['memberDiff'].get('removed') and \
        not repair['memberDiff'].get('orderErrors') and len(members) > 1 and members[1]['ord'] == 1 and \
        members[1]['name'] == 'task_struct.o' and members[1]['sha256'] == changed[0]['candidateSha256'] and \
        sum(m['name'] == 'task_struct.o' for m in members) == 1, 'TASK_COMM_SCAN_MEMBER_STALE'
    for field in ('requestIsolationPreserved', 'originalM001TextPreserved',
                  'originalM001RelocationsPreserved', 'canonicalStrongDefinition',
                  'originalOtherGlobalDefinitionsPreserved'):
        assert repair.get(field) is True, 'TASK_COMM_SCAN_IMPLEMENTATION_CONTRACT: ' + field
    symbols = ELFFile(io.BytesIO(compiled)).get_section_by_name('.symtab')
    defined = {s.name for s in symbols.iter_symbols() if isinstance(s['st_shndx'], int) and
               s['st_shndx'] > 0 and s['st_info']['type'] == 'STT_FUNC'} if symbols else set()
    assert {'_ZN13kernel_module27get_task_struct_comm_offsetERj',
            'maplesu_find_real_cred_offset'} <= defined, 'TASK_COMM_SCAN_BACKEND_MISSING'


def verify_kernel_read_repair(manifest, root, members, compiled):
    repair = manifest.get('kernelReadRepair')
    if repair is None:
        return
    assert repair.get('deliveredArchiveSha256') == manifest['archive']['sha256'], 'KERNEL_READ_SDK_STALE'
    assert repair.get('deliveredHelperSha256') == manifest['helper']['sha256'], 'KERNEL_READ_HELPER_STALE'
    assert repair.get('policyBackendSha256') == manifest['environmentPolicyBoot']['backend']['sha256'], \
        'KERNEL_READ_BACKEND_STALE'
    sources = repair.get('sources', {})
    assert KERNEL_READ_SOURCES <= sources.keys(), 'KERNEL_READ_SOURCE_MISSING'
    for name, expected in sources.items():
        source = (root / name).resolve()
        assert source.is_relative_to(root) and digest(source) == expected, 'KERNEL_READ_SOURCE_STALE: ' + name
    changed = repair['memberDiff']['changed']
    assert len(changed) == 1 and changed[0]['ord'] == 23 and len(members) > 23 and \
        members[23]['ord'] == 23 and members[23]['name'] == changed[0]['name'] == 'module_base_kernel_request.o' and \
        members[23]['sha256'] == changed[0]['candidateSha256'] and \
        sum(m['name'] == 'module_base_kernel_request.o' for m in members) == 1, 'KERNEL_READ_MEMBER_STALE'
    elf = ELFFile(io.BytesIO(compiled))
    symbols = elf.get_section_by_name('.symtab')
    defined = {s.name for s in symbols.iter_symbols() if isinstance(s['st_shndx'], int) and
               0 < s['st_shndx'] < elf.num_sections() and
               s['st_info']['type'] == 'STT_FUNC'} if symbols else set()
    assert {'_ZN13kernel_module23request_kernel_read_memEmPvj', 'maplesu_prepare_kernel_request'} <= defined, \
        'KERNEL_READ_BACKEND_MISSING'
    assert '__wrap__ZN13kernel_module23request_kernel_read_memEmPvj' not in defined, 'KERNEL_READ_BACKEND_WRAPPED'
    assert b'copy_to_user_nofault\0' in compiled, 'KERNEL_READ_NOFAULT_MISSING'


def verify_helper_kernel_read_repair(manifest, root, helper):
    repair = manifest.get('helperKernelReadRepair')
    if repair is None:
        return
    assert repair.get('deliveredArchiveSha256') == manifest['archive']['sha256'], 'HELPER_KERNEL_READ_SDK_STALE'
    assert repair.get('policyBackendSha256') == manifest['environmentPolicyBoot']['backend']['sha256'], \
        'HELPER_KERNEL_READ_BACKEND_STALE'
    assert repair.get('deliveredHelperSha256') == manifest['helper']['sha256'] == hashlib.sha256(helper).hexdigest(), \
        'HELPER_KERNEL_READ_HELPER_STALE'
    sources = repair.get('sources', {})
    assert HELPER_KERNEL_READ_SOURCES <= sources.keys(), 'HELPER_KERNEL_READ_SOURCE_MISSING'
    for name, expected in sources.items():
        source = (root / name).resolve()
        assert source.is_relative_to(root) and digest(source) == expected, 'HELPER_KERNEL_READ_SOURCE_STALE: ' + name
    patch = repair['entryPatch']
    offset, replacement = patch['offset'], bytes.fromhex(patch['candidateHex'])
    assert offset >= 0 and len(bytes.fromhex(patch['baselineHex'])) == len(replacement) == 4 and \
        helper[offset:offset + 4] == replacement, 'HELPER_KERNEL_READ_ENTRY_STALE'
    extension = repair['extension']
    offset, size = extension['offset'], extension['bytes']
    assert offset >= 0 and size > 0 and offset + size <= len(helper) and \
        hashlib.sha256(helper[offset:offset + size]).hexdigest() == extension['sha256'], \
        'HELPER_KERNEL_READ_EXTENSION_STALE'
    elf = ELFFile(io.BytesIO(helper))
    assert any(s['p_type'] == 'PT_LOAD' and s['p_flags'] & 1 and s['p_offset'] <= offset and
               offset + size <= s['p_offset'] + s['p_filesz'] and
               extension['address'] == s['p_vaddr'] + offset - s['p_offset'] for s in elf.iter_segments()), \
        'HELPER_KERNEL_READ_EXTENSION_STALE'
    replay = repair['callbackReplay']
    replay_path = (root / replay['path']).resolve()
    assert replay_path.is_relative_to(root / 'work') and digest(replay_path) == replay['sha256'], \
        'HELPER_KERNEL_READ_REPLAY_STALE'
    report = json.loads(replay_path.read_text())
    assert report.get('passed') is True and report.get('helperSha256') == repair['helperSha256'] and \
        report.get('baselineHelperSha256') == repair['baselineHelperSha256'], 'HELPER_KERNEL_READ_REPLAY_UNPAIRED'


def verify_memory_protection_repair(manifest, root, members, helper):
    repair = manifest.get('memoryProtectionRepair')
    if repair is None:
        return
    assert repair.get('deliveredArchiveSha256') == manifest['archive']['sha256'], 'MEMORY_PROTECTION_SDK_STALE'
    assert repair.get('policyBackendSha256') == manifest['environmentPolicyBoot']['backend']['sha256'], \
        'MEMORY_PROTECTION_BACKEND_STALE'
    assert repair.get('deliveredHelperSha256') == manifest['helper']['sha256'] == hashlib.sha256(helper).hexdigest(), \
        'MEMORY_PROTECTION_HELPER_STALE'
    sources = repair.get('sources', {})
    assert MEMORY_PROTECTION_SOURCES <= sources.keys(), 'MEMORY_PROTECTION_SOURCE_MISSING'
    for name, expected in sources.items():
        source = (root / name).resolve()
        assert historical_source_matches(manifest, root, name, expected), \
            'MEMORY_PROTECTION_SOURCE_STALE: ' + name
    assert len(members) > 24 and members[24]['ord'] == 24 and \
        members[24]['name'] == 'module_base_kernel_mem.o' and \
        members[24]['sha256'] == repair.get('candidateObjectSha256') and \
        sum(m['name'] == 'module_base_kernel_mem.o' for m in members) == 1, 'MEMORY_PROTECTION_MEMBER_STALE'
    assert repair.get('validationScope') == MEMORY_PROTECTION_VALIDATION and \
        repair.get('deviceAcceptance') is False, 'MEMORY_PROTECTION_VALIDATION_SCOPE'
    patch = repair['helper']['entryPatch']
    offset, replacement = patch['offset'], bytes.fromhex(patch['candidateHex'])
    assert offset >= 0 and len(bytes.fromhex(patch['baselineHex'])) == len(replacement) == 4 and \
        helper[offset:offset + 4] == replacement, 'MEMORY_PROTECTION_ENTRY_STALE'
    extension = repair['helper']['extension']
    offset, size = extension['offset'], extension['bytes']
    assert offset >= 0 and size > 0 and offset + size <= len(helper) and \
        hashlib.sha256(helper[offset:offset + size]).hexdigest() == extension['sha256'], \
        'MEMORY_PROTECTION_EXTENSION_STALE'
    elf = ELFFile(io.BytesIO(helper))
    assert any(s['p_type'] == 'PT_LOAD' and s['p_flags'] == 5 and s['p_offset'] <= offset and
               offset + size <= s['p_offset'] + s['p_filesz'] and
               extension['address'] == s['p_vaddr'] + offset - s['p_offset'] for s in elf.iter_segments()), \
        'MEMORY_PROTECTION_EXTENSION_STALE'


def verify_delivery(manifest, root):
    policy = manifest['environmentPolicyBoot']
    delivery = policy.get('delivery', {})
    assert delivery.get('schemaVersion') == 2 and delivery.get('consentRequest') == 7, \
        'POLICY_BACKEND_STALE: consent-capable boot backend was not paired and imported'
    backend = policy['backend']
    assert not manifest.get('zeroModuleQuietRepair') or manifest.get('moduleControlWaitRepair'), 'QUIET_REBIND_WAIT_HISTORY_REQUIRED'
    if manifest.get('moduleControlWaitRepair'):
        archive = (root / manifest['archive']['path']).resolve()
        assert archive.is_relative_to(root) and digest(archive) == manifest['archive']['sha256']
        verify_module_control_wait_repair(manifest, root, parse_ar(str(archive))['members'])
    request_context = manifest.get('requestContextRepair')
    if request_context:
        assert request_context.get('deliveredArchiveSha256') == manifest['archive']['sha256'], \
            'REQUEST_CONTEXT_SDK_STALE'
        assert request_context.get('policyBackendSha256') == backend['sha256'], \
            'REQUEST_CONTEXT_BACKEND_STALE'
        assert request_context.get('deliveredHelperSha256') == manifest['helper']['sha256'], \
            'REQUEST_CONTEXT_HELPER_STALE'
        for name, expected in request_context['sources'].items():
            assert historical_source_matches(manifest, root, name, expected), 'REQUEST_CONTEXT_SOURCE_STALE: ' + name
    snapshot = manifest.get('credentialSnapshotRepair')
    if snapshot:
        assert snapshot.get('deliveredArchiveSha256') == manifest['archive']['sha256'], \
            'CREDENTIAL_SNAPSHOT_SDK_STALE'
        assert snapshot.get('policyBackendSha256') == backend['sha256'], \
            'CREDENTIAL_SNAPSHOT_BACKEND_STALE'
        assert snapshot.get('deliveredHelperSha256') == manifest['helper']['sha256'], \
            'CREDENTIAL_SNAPSHOT_HELPER_STALE'
        for name, expected in snapshot['sources'].items():
            assert digest(root / name) == expected, 'CREDENTIAL_SNAPSHOT_SOURCE_STALE: ' + name
    path = (root / backend['path']).resolve()
    assert path.is_relative_to(root)
    assert describe_backend(path) == {k:v for k,v in backend.items() if k != 'path'}, 'POLICY_BACKEND_IDENTITY_MISMATCH'
    for name in SOURCES:
        assert delivery.get('sourceSha256', {}).get(name) == digest(root / name), \
            'POLICY_BACKEND_SOURCE_STALE: ' + name
    bundle_manifest = delivery['bundleManifest']
    bundle_path = (root / bundle_manifest['path']).resolve()
    assert bundle_path.is_relative_to(root) and digest(bundle_path) == bundle_manifest['sha256'], \
        'POLICY_BACKEND_BUNDLE_MANIFEST_STALE'
    generated = json.loads(bundle_path.read_text())
    assert digest(bundle_path.with_suffix('.cpp')) == generated['generatedSourceSha256'], \
        'POLICY_BACKEND_BUNDLE_SOURCE_STALE'
    assert generated['generatorSha256'] == digest(root / 'scripts/build-ultra-policy-bundles.py') and \
        generated['profilePolicySha256'] == digest(root / 'runtime/ultra/policy/kernel_compatibility_profiles.json'), \
        'POLICY_BACKEND_BUNDLE_GENERATOR_STALE'
    bundles = delivery['bundles']
    assert {b['kernelSeries'] for b in bundles} == {'5.10', '5.15', '6.1', '6.6', '6.12', '6.18'}, \
        'POLICY_BACKEND_PROFILE_MISSING'
    required = json.loads((root / 'runtime/ultra/policy/kernel_compatibility_profiles.json').read_text())
    for bundle in bundles:
        contract_file = bundle.get('compatibility')
        if not contract_file:
            assert bundle['kernelSeries'] == '5.10' and bundle.get('exactImageOnly') is True
            continue
        contract_path = (root / contract_file['path']).resolve()
        assert contract_path.is_relative_to(root) and digest(contract_path) == contract_file['sha256'], \
            'POLICY_BACKEND_CONTRACT_STALE'
        contract = json.loads(contract_path.read_text())
        for override in required['profilesBySeries'].get(bundle['kernelSeries'], []):
            variant = {k:v for k,v in override.items() if k in contract['config'] and contract['config'][k] != v}
            assert not variant or variant in contract['equivalentConfigs'], 'POLICY_BACKEND_CONFIG_PROOF_MISSING'
        for name, expected in contract['inputSha256'].items():
            assert digest(contract_path.parent / name) == expected, 'POLICY_BACKEND_CONFIG_PROOF_STALE: ' + name
    archive = (root / manifest['archive']['path']).resolve()
    assert archive.is_relative_to(root) and digest(archive) == manifest['archive']['sha256']
    members = parse_ar(str(archive))['members']
    verify_kernel_read_repair(manifest, root, members, path.read_bytes())
    if snapshot:
        changed = snapshot['memberDiff']['changed']
        comm = manifest.get('taskCommScanRepair')
        expected = changed[0]['candidateSha256'] if changed else None
        if comm:
            comm_changed = comm['memberDiff']['changed']
            assert len(comm_changed) == 1 and comm_changed[0]['ord'] == 1 and \
                comm.get('baselineCredentialSnapshotMemberSha256') == expected == \
                comm_changed[0]['baselineSha256'], 'CREDENTIAL_SNAPSHOT_MEMBER_STALE'
            expected = comm_changed[0]['candidateSha256']
        assert len(changed) == 1 and changed[0]['ord'] == 1 and \
            members[1]['sha256'] == expected, 'CREDENTIAL_SNAPSHOT_MEMBER_STALE'
        symbols = ELFFile(io.BytesIO(path.read_bytes())).get_section_by_name('.symtab')
        assert symbols and any(s.name == 'maplesu_find_real_cred_offset' and s['st_shndx'] != 'SHN_UNDEF'
                               for s in symbols.iter_symbols()), 'CREDENTIAL_SNAPSHOT_BACKEND_MISSING'
    verify_task_comm_scan_repair(manifest, root, members, path.read_bytes())
    member = members[52]
    body = archive.read_bytes()[member['body_offset']:member['body_offset'] + member['size']]
    helper = ELFFile(io.BytesIO(body)).get_section_by_name('.data').data()
    assert hashlib.sha256(helper).hexdigest() == policy['entryHelperSha256'] == manifest['helper']['sha256'], \
        'POLICY_BACKEND_HELPER_STALE'
    verify_helper_kernel_read_repair(manifest, root, helper)
    verify_memory_protection_repair(manifest, root, members, helper)
    for value in (backend['fileName'].encode() + b'\0', bytes.fromhex(backend['noteHex'])):
        assert helper.count(value) == 1, 'POLICY_BACKEND_HELPER_UNPAIRED'
    compiled = path.read_bytes()
    for marker in (b'experimental-support\0', b'userConfirmedUnverified=', b'MODULE_POLICY_LOADER_CONFIG_MISMATCH:'):
        assert marker in compiled, 'POLICY_BACKEND_CONSENT_IMPLEMENTATION_MISSING'


# The historical gates above retain their exact R10 contracts. A separately
# validated new chain supplies immutable historical files, never rewritten pins.
_verify_r10_delivery = verify_delivery
_verify_r10_module_control_wait = verify_module_control_wait_repair

def _su_uid_historical_delivery(manifest, root):
    from su_uid_isolation_delivery import verify_su_uid_isolation_repair
    from private_dac_delivery import checked, verify_private_dac_repair
    verify_su_uid_isolation_repair(manifest, root)
    receipt = json.loads(checked(root, manifest['suUidIsolationRepair']['baselinePhysicalReceipt']).read_bytes())
    view = Path(receipt['physicalRoot']).resolve()
    baseline = json.loads((view / 'runtime/maplesu-sdk/SDK-RELEASE.json').read_bytes())
    return verify_private_dac_repair(baseline, view)


def verify_module_control_wait_repair(manifest, root, members):
    if manifest.get('suUidIsolationRepair'):
        baseline, view = _su_uid_historical_delivery(manifest, root)
        original = parse_ar(str(view / baseline['archive']['path']))['members']
        return _verify_r10_module_control_wait(baseline, view, original)
    if not manifest.get('privateDacRepair'):
        return _verify_r10_module_control_wait(manifest, root, members)
    from private_dac_delivery import verify_private_dac_repair
    baseline, view = verify_private_dac_repair(manifest, root)
    original = parse_ar(str(view / baseline['archive']['path']))['members']
    return _verify_r10_module_control_wait(baseline, view, original)

def verify_delivery(manifest, root):
    if manifest.get('suUidIsolationRepair'):
        baseline, view = _su_uid_historical_delivery(manifest, root)
        return _verify_r10_delivery(baseline, view)
    if not manifest.get('privateDacRepair'):
        return _verify_r10_delivery(manifest, root)
    from private_dac_delivery import verify_private_dac_repair, checked
    baseline, view = verify_private_dac_repair(manifest, root)
    archive = checked(root, manifest['archive'])
    members = parse_ar(str(archive))['members']
    row = members[52]
    raw = archive.read_bytes()
    helper = ELFFile(io.BytesIO(raw[row['body_offset']:row['body_offset'] + row['size']])).get_section_by_name('.data').data()
    # The two old runtime patches must still exist in the final helper bytes.
    verify_helper_kernel_read_repair(manifest, view, helper)
    verify_memory_protection_repair(manifest, view, members, helper)
    return _verify_r10_delivery(baseline, view)
