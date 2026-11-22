"""Validate one durable-retention member update while preserving the entire DAC chain."""
import copy
import io
import json

from ar_archive import parse_ar
from elftools.elf.elffile import ELFFile

BASELINE_ARCHIVE = '2c6bc470af5ac72054b9e1f0ea239ff84908619d8e2347e09104a9a243ac8489'
BASELINE_MANIFEST = 'd5b4d0fa11bc50096b2846a255ba63eb888916062d0e48f6a1aee60d192f0275'
HELPER = '02cf4ae01842dd34685c1300cc6316488a0304197faa1ff29e990cb50c611778'
SOURCES = {'runtime/ultra/authorization/su_retention_store.cpp', 'runtime/ultra/authorization/su_retention_store.h',
           'runtime/ultra/authorization/su_allowlist_writer.cpp', 'scripts/repair-ultra-su-authorization.py'}
STORE_SYMBOL = '_Z26maplesu_store_su_retentionPKvm'

def verify_su_retention_repair(manifest, root):
    from private_dac_delivery import checked, sha, body, public_definitions
    repair = manifest['suRetentionPersistenceRepair']
    assert repair.get('schemaVersion') == 1 and repair.get('deviceAcceptance') is False, 'SU_RETENTION_SCOPE'
    source_manifest = checked(root, repair['baselineManifest'])
    assert sha(source_manifest.read_bytes()) == BASELINE_MANIFEST, 'SU_RETENTION_MANIFEST_ANCHOR'
    baseline = json.loads(source_manifest.read_bytes())
    assert not baseline.get('suRetentionPersistenceRepair') and baseline.get('privateDacRepair'), 'SU_RETENTION_BASELINE_CHAIN'
    snapshot = checked(root, repair['baselineArchive'])
    assert sha(snapshot.read_bytes()) == baseline['archive']['sha256'] == BASELINE_ARCHIVE, 'SU_RETENTION_ARCHIVE_ANCHOR'
    archive = checked(root, manifest['archive'])
    assert repair['baselineArchiveSha256'] == BASELINE_ARCHIVE and repair['deliveredArchiveSha256'] == manifest['archive']['sha256'], 'SU_RETENTION_CURRENT_IDENTITY'
    assert repair['helperSha256'] == manifest['helper']['sha256'] == baseline['helper']['sha256'] == HELPER, 'SU_RETENTION_HELPER_CHANGED'
    assert manifest['helper'] == baseline['helper'] and manifest['bootstrap'] == baseline['bootstrap'], 'SU_RETENTION_HELPER_METADATA_CHANGED'
    checked(root, manifest['helper'])
    assert SOURCES == repair['sources'].keys(), 'SU_RETENTION_SOURCE_MISSING'
    for path, expected in repair['sources'].items():
        checked(root, dict(path=path, sha256=expected), 'SU_RETENTION_SOURCE_STALE')
    old_data, data = snapshot.read_bytes(), archive.read_bytes()
    assert len(old_data) == baseline['archive']['size'] and len(data) == manifest['archive']['size'], 'SU_RETENTION_ARCHIVE_SIZE'
    before, after = parse_ar(str(snapshot))['members'], parse_ar(str(archive))['members']
    assert len(before) == len(after) == 260, 'SU_RETENTION_MEMBER_COUNT'
    assert all(a['ord'] == b['ord'] == i and a['name'] == b['name'] for i, (a, b) in enumerate(zip(before, after))), 'SU_RETENTION_MEMBER_ORDER'
    assert {i for i, (a, b) in enumerate(zip(before, after)) if a['sha256'] != b['sha256']} == {81}, 'SU_RETENTION_MEMBER_DIFF'
    assert before[81]['name'] == after[81]['name'] == 'module_su_redirect.o', 'SU_RETENTION_MEMBER_IDENTITY'
    assert repair['baselineMemberSha256'] == before[81]['sha256'] and repair['candidateMemberSha256'] == after[81]['sha256'], 'SU_RETENTION_MEMBER_RECEIPT'
    original, current = public_definitions(body(old_data, before[81])), public_definitions(body(data, after[81]))
    added = {(STORE_SYMBOL, 'STB_GLOBAL', 'STT_FUNC', 'STV_HIDDEN')}
    assert original <= current and current - original == added, 'SU_RETENTION_GLOBAL_ABI'
    old_helper = ELFFile(io.BytesIO(body(old_data, before[52]))).get_section_by_name('.data').data()
    helper = ELFFile(io.BytesIO(body(data, after[52]))).get_section_by_name('.data').data()
    assert old_helper == helper and sha(helper) == HELPER, 'SU_RETENTION_EMBEDDED_HELPER_CHANGED'
    expected_control = copy.deepcopy(baseline['moduleControl'])
    expected_control['archiveSha256'] = manifest['archive']['sha256']
    assert manifest['moduleControl'] == expected_control, 'SU_RETENTION_CONTROL_REWRITTEN'
    assert manifest['environmentPolicyBoot'] == baseline['environmentPolicyBoot'], 'SU_RETENTION_POLICY_REWRITTEN'
    expected_repairs = copy.deepcopy(baseline['repairs'])
    for row in expected_repairs:
        if row.get('memberOrdinal') == 81:
            row['sha256'] = after[81]['sha256']
    assert manifest['repairs'] == expected_repairs, 'SU_RETENTION_REPAIR_MEMBERS_REWRITTEN'
    for name, value in baseline.items():
        if not name.endswith('Repair'):
            continue
        current_repair = copy.deepcopy(manifest.get(name))
        assert isinstance(current_repair, dict), 'SU_RETENTION_HISTORY_REMOVED: ' + name
        if 'deliveredArchiveSha256' in value and current_repair.get('deliveredArchiveSha256') != value['deliveredArchiveSha256']:
            assert current_repair.get('deliveredArchiveSha256') == manifest['archive']['sha256'], 'SU_RETENTION_HISTORY_ENDPOINT: ' + name
            current_repair['deliveredArchiveSha256'] = value['deliveredArchiveSha256']
        assert current_repair == value, 'SU_RETENTION_HISTORY_REWRITTEN: ' + name
    reports = {}
    for name in ('archiveBuild', 'durability'):
        path = checked(root, repair['evidence'][name], 'SU_RETENTION_EVIDENCE_STALE')
        reports[name] = json.loads(path.read_bytes())
        assert reports[name].get('passed') is True, 'SU_RETENTION_EVIDENCE_FAILED: ' + name
    build = reports['archiveBuild']
    assert build.get('baselineArchiveSha256') == BASELINE_ARCHIVE and build.get('archiveSha256') == manifest['archive']['sha256'], 'SU_RETENTION_BUILD_ARCHIVE'
    assert build.get('baselineMemberSha256') == before[81]['sha256'] and build.get('candidateMemberSha256') == after[81]['sha256'] and build.get('helperSha256') == HELPER, 'SU_RETENTION_BUILD_MEMBER'
    assert build.get('publicAbiPreserved') is True and build.get('onlyMember81Changed') is True, 'SU_RETENTION_BUILD_CONTRACT'
    assert build.get('sourceSha256') == repair['sources'] and {tuple(row) for row in build.get('addedDefinitions', [])} == added, 'SU_RETENTION_BUILD_SOURCES'
    durability = reports['durability']
    assert durability.get('sourceSha256') == repair['sources']['runtime/ultra/authorization/su_retention_store.cpp'], 'SU_RETENTION_DURABILITY_SOURCE'
    assert durability.get('actualHostFilesystem') is True and durability.get('faultInjection') is True and durability.get('budgetsPreserved') is True, 'SU_RETENTION_DURABILITY_CONTRACT'
    assert durability.get('storeCases') == 25 and durability.get('lifetimeCases') == 13, 'SU_RETENTION_DURABILITY_CASES'
    assert all(durability.get(key) is True for key in ('fileFsyncBeforeRename', 'full64ByteReadback', 'directoryFsyncBeforeSuccess', 'unknownDamageRejected', 'onlyNewBootResetsValidLedger', 'selinuxXattrFixture')), 'SU_RETENTION_DURABILITY_ORDER'
    assert durability.get('deviceAcceptance') is False and durability.get('powerLossSimulation') is False, 'SU_RETENTION_DURABILITY_SCOPE'
    inputs = durability.get('inputSha256', {})
    required_inputs = (SOURCES - {'scripts/repair-ultra-su-authorization.py'}) | {'runtime/tests/pro_su_retention_store_test.cpp', 'runtime/tests/pro_su_lifetime_test.cpp'}
    assert inputs.keys() == required_inputs, 'SU_RETENTION_DURABILITY_INPUTS'
    for name, expected in inputs.items():
        checked(root, dict(path=name, sha256=expected), 'SU_RETENTION_DURABILITY_INPUT_STALE')
        if name in repair['sources']:
            assert expected == repair['sources'][name], 'SU_RETENTION_DURABILITY_INPUT_SOURCE'
    expected_manifest = copy.deepcopy(baseline)
    expected_manifest['archive'] = dict(baseline['archive'], sha256=sha(data), size=len(data))
    expected_manifest['moduleControl'] = expected_control
    expected_manifest['repairs'] = expected_repairs
    for name, value in expected_manifest.items():
        if name.endswith('Repair') and 'deliveredArchiveSha256' in value:
            value['deliveredArchiveSha256'] = sha(data)
    current_manifest = copy.deepcopy(manifest)
    current_manifest.pop('suRetentionPersistenceRepair')
    assert current_manifest == expected_manifest, 'SU_RETENTION_MANIFEST_REWRITTEN'
    return baseline, snapshot
