"""Strict R10 -> batch -> private DAC delivery chain, with immutable historical gates."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from ar_archive import parse_ar
from elftools.elf.elffile import ELFFile

BASELINE_ARCHIVE = '84d6b5a35bfdf822768d6005bae478982eabc84158f3a6f85728455657c48843'
BASELINE_HELPER = 'a121b912bcc68efeafc3cba8c5077950f5768bef5e8dee2a22ada5e47ba9f7c0'
BASELINE_MANIFEST = '592918e6115bbb414a810f6921bc1bd65b6e297996f31ca92d25f24d1ad7e058'
BASELINE_FREEZE = 'fedbf177c654d19b14a705efa2918b3c7213184b970cff5fe3f458432fb87714'
BATCH_ARCHIVE = '330399d3ae5cb4afb9cd694c85a8ce4067712d07f9025dfb0019da08d036fd5b'
BATCH_CONTROL = '301b2bfd0e936cfed458671f77c3a7f0534e973865f998c92a3b395252ecc5db'
BATCH_SOURCE = '77eee7011fc86e21aa07f245bb3f9252911f24dae02b62b559576d5cd3f1ad28'
CHANGED = {35, 47, 48, 52, 81, 88, 255}
ADDED = ['maplesu_private_dac.o', 'maplesu_private_allowlist.o']
SOURCE_PATHS = {'runtime/ultra/identity/private_dac.c', 'runtime/ultra/identity/private_dac.h',
                'runtime/ultra/identity/private_dac.S', 'runtime/ultra/identity/private_allowlist.cpp',
                'runtime/ultra/authorization/su_exec_context.cpp'}
SOURCE_PATHS.update(('runtime/ultra/modules/module_control.cpp', 'runtime/maplesu-sdk/include/maplesu_module_control.h',
                     'runtime/ultra/bridge/native_lib_ultra.cpp'))
DAC = dict(ownerRoot=0o711, initRoot=0o700, privateChildren=0o700,
           suExecContext=0o711, allowlist=0o600, authorizationRecord=0o600)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def checked(root, row, error='PRIVATE_DAC_EVIDENCE_STALE'):
    assert isinstance(row, dict) and isinstance(row.get('path'), str), error
    path = (root / row['path']).resolve()
    assert path.is_relative_to(root) and path.is_file() and sha(path.read_bytes()) == row.get('sha256'), error + ': ' + row['path']
    return path

def body(data, member):
    return data[member['body_offset']:member['body_offset'] + member['size']]

def historical(root, repair):
    freeze_path = checked(root, repair['historicalFreeze'])
    assert sha(freeze_path.read_bytes()) == BASELINE_FREEZE, 'PRIVATE_DAC_FREEZE_ANCHOR'
    view = freeze_path.parent
    freeze = json.loads(freeze_path.read_bytes())
    assert freeze['archiveSha256'] == BASELINE_ARCHIVE and freeze['manifestSha256'] == BASELINE_MANIFEST, 'PRIVATE_DAC_BASELINE_ARCHIVE'
    for name, expected in freeze['files'].items():
        checked(view, dict(path=name, sha256=expected), 'PRIVATE_DAC_HISTORY_FILE_STALE')
    manifest_path = checked(view, dict(path='manifest.json', sha256=freeze['manifestSha256']))
    baseline = json.loads(manifest_path.read_bytes())
    assert baseline['archive']['sha256'] == BASELINE_ARCHIVE and baseline['helper']['sha256'] == BASELINE_HELPER, 'PRIVATE_DAC_BASELINE_IDENTITY'
    return baseline, view

def verify_helper_delta(old, new, delta):
    assert delta['baselineSha256'] == sha(old) == BASELINE_HELPER and delta['candidateSha256'] == sha(new), 'PRIVATE_DAC_HELPER_CHAIN'
    rebuilt = bytearray(old)
    seen = set()
    for patch in delta['patches']:
        offset = patch['offset']
        before, after = bytes.fromhex(patch['baselineHex']), bytes.fromhex(patch['candidateHex'])
        assert before and len(before) == len(after) and offset >= 0 and offset + len(before) <= len(old), 'PRIVATE_DAC_PATCH_RANGE'
        positions = set(range(offset, offset + len(before)))
        assert not seen & positions and old[offset:offset + len(before)] == before, 'PRIVATE_DAC_PATCH_BASELINE'
        seen.update(positions)
        rebuilt[offset:offset + len(before)] = after
    tail = delta['append']
    assert tail['offset'] == len(old) and tail['bytes'] == len(new) - len(old) >= 0 and sha(new[len(old):]) == tail['sha256'], 'PRIVATE_DAC_APPEND'
    rebuilt.extend(new[len(old):])
    assert bytes(rebuilt) == new, 'PRIVATE_DAC_UNDECLARED_HELPER_BYTES'

def public_definitions(data):
    if data[:4] in (b'BC\xc0\xde', b'\xde\xc0\x17\x0b'):
        root = next(p for p in Path(__file__).resolve().parents if (p / 'tools/native_toolchain.py').is_file())
        sys.path.insert(0, str(root / 'tools'))
        import native_toolchain
        tool = native_toolchain.ndk_bin(native_toolchain.ndk_home()) / ('llvm-nm.exe' if os.name == 'nt' else 'llvm-nm')
        with tempfile.TemporaryDirectory(prefix='maplesu-dac-abi-') as scratch:
            path = Path(scratch) / 'member.bc'
            path.write_bytes(data)
            result = subprocess.run([str(tool), '--defined-only', '--extern-only', '--format=posix', str(path)],
                                    capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, 'PRIVATE_DAC_BITCODE_SYMBOLS'
        rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
        assert rows and all(len(row) >= 2 and len(row[1]) == 1 for row in rows), 'PRIVATE_DAC_BITCODE_SYMBOLS'
        return {(row[0], row[1]) for row in rows}
    assert data[:4] == b'\x7fELF', 'PRIVATE_DAC_OBJECT_FORMAT'
    elf = ELFFile(io.BytesIO(data))
    symbols = elf.get_section_by_name('.symtab')
    assert symbols, 'PRIVATE_DAC_OBJECT_SYMBOLS'
    return {(s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'])
            for s in symbols.iter_symbols() if s['st_info']['bind'] != 'STB_LOCAL' and s['st_shndx'] != 'SHN_UNDEF'}

def verify_private_dac_repair(manifest, root, _archive_snapshot=None):
    root = root.resolve()
    if manifest.get('suRetentionPersistenceRepair'):
        assert _archive_snapshot is None, 'SU_RETENTION_RECURSIVE_CHAIN'
        from su_retention_delivery import verify_su_retention_repair
        previous, snapshot = verify_su_retention_repair(manifest, root)
        return verify_private_dac_repair(previous, root, snapshot)
    repair = manifest['privateDacRepair']
    assert repair.get('schemaVersion') == 1 and repair.get('deviceAcceptance') is False, 'PRIVATE_DAC_SCOPE'
    baseline, view = historical(root, repair)
    assert repair.get('baselineArchiveSha256') == BASELINE_ARCHIVE and repair.get('baselineHelperSha256') == BASELINE_HELPER, 'PRIVATE_DAC_BASELINE_IDENTITY'
    archive = _archive_snapshot or checked(root, manifest['archive'])
    if _archive_snapshot is not None:
        assert sha(archive.read_bytes()) == manifest['archive']['sha256'] == '2c6bc470af5ac72054b9e1f0ea239ff84908619d8e2347e09104a9a243ac8489', 'SU_RETENTION_DAC_SNAPSHOT'
    helper_path = checked(root, manifest['helper'])
    assert repair['deliveredArchiveSha256'] == manifest['archive']['sha256'] and repair['deliveredHelperSha256'] == manifest['helper']['sha256'], 'PRIVATE_DAC_CURRENT_IDENTITY'
    backend = baseline['environmentPolicyBoot']['backend']
    assert repair['policyBackendSha256'] == backend['sha256'] and manifest['environmentPolicyBoot']['backend'] == backend, 'PRIVATE_DAC_BACKEND_CHANGED'
    checked(root, backend)
    for name, expected in repair['sources'].items():
        checked(root, dict(path=name, sha256=expected), 'PRIVATE_DAC_SOURCE_STALE')
    assert SOURCE_PATHS <= repair['sources'].keys(), 'PRIVATE_DAC_SOURCE_MISSING'
    for row in repair.get('sourceRebindings', []):
        checked(root, dict(path=row['path'], sha256=row['candidateSha256']))
        before = checked(root, row['baselineSource'])
        assert sha(before.read_bytes()) == row['baselineSha256'], 'PRIVATE_DAC_SOURCE_BASELINE'
    assert repair['dacContract'] == DAC, 'PRIVATE_DAC_MODE_CONTRACT'
    before_path = checked(view, baseline['archive'])
    old_data, data = before_path.read_bytes(), archive.read_bytes()
    old, members = parse_ar(str(before_path))['members'], parse_ar(str(archive))['members']
    assert len(old) == 258 and len(members) == 260, 'PRIVATE_DAC_MEMBER_COUNT'
    assert all(a['ord'] == b['ord'] == i and a['name'] == b['name'] for i, (a, b) in enumerate(zip(old, members))), 'PRIVATE_DAC_MEMBER_ORDER'
    changed = {i for i, (a, b) in enumerate(zip(old, members)) if a['sha256'] != b['sha256']}
    assert changed == CHANGED and [m['name'] for m in members[258:]] == ADDED and [m['ord'] for m in members[258:]] == [258, 259], 'PRIVATE_DAC_MEMBER_DIFF'
    claimed = repair['memberDiff']
    assert not claimed.get('removed') and not claimed.get('orderErrors') and claimed['unchanged'] == 251, 'PRIVATE_DAC_MEMBER_DIFF'
    for kind, indices in [('changed', sorted(CHANGED)), ('added', [258, 259])]:
        rows = claimed[kind]
        assert [r['ord'] for r in rows] == indices, 'PRIVATE_DAC_MEMBER_RECEIPT'
        for row in rows:
            i = row['ord']
            assert row['name'] == members[i]['name'] and row['candidateSha256'] == members[i]['sha256'] and row['candidateSize'] == members[i]['size'], 'PRIVATE_DAC_MEMBER_RECEIPT'
            if kind == 'changed':
                assert row['baselineSha256'] == old[i]['sha256'] and row['baselineSize'] == old[i]['size'], 'PRIVATE_DAC_MEMBER_BASELINE'
    batch_path = checked(root, repair['batchArchive'])
    assert sha(batch_path.read_bytes()) == BATCH_ARCHIVE, 'PRIVATE_DAC_BATCH_ARCHIVE'
    batch = parse_ar(str(batch_path))['members']
    assert len(batch) == 258 and batch[255]['sha256'] == BATCH_CONTROL and all(a['name'] == b['name'] and (i == 255 or a['sha256'] == b['sha256']) for i, (a, b) in enumerate(zip(old, batch))), 'PRIVATE_DAC_BATCH_CHAIN'
    checked(root, dict(path='runtime/ultra/modules/module_control.cpp', sha256=BATCH_SOURCE), 'PRIVATE_DAC_BATCH_SOURCE')
    batch_control = body(batch_path.read_bytes(), batch[255])
    final_control = body(data, members[255])
    assert public_definitions(batch_control) <= public_definitions(final_control), 'PRIVATE_DAC_ABI_LOSS'
    for i in sorted(CHANGED - {255}):
        assert public_definitions(body(old_data, old[i])) <= public_definitions(body(data, members[i])), 'PRIVATE_DAC_ABI_LOSS: ' + str(i)
    old_helper = ELFFile(io.BytesIO(body(old_data, old[52]))).get_section_by_name('.data').data()
    helper = ELFFile(io.BytesIO(body(data, members[52]))).get_section_by_name('.data').data()
    assert helper == helper_path.read_bytes() and sha(helper) == manifest['environmentPolicyBoot']['entryHelperSha256'], 'PRIVATE_DAC_HELPER_PAIRING'
    verify_helper_delta(old_helper, helper, repair['helperDelta'])
    slot = manifest['helper']['keySlotOffset']
    assert slot == baseline['helper']['keySlotOffset'] == 182886 and helper[slot:slot + 4096] == old_helper[slot:slot + 4096], 'PRIVATE_DAC_KEY_SLOT'
    normalized = bytearray(helper)
    normalized[slot:slot + 4096] = bytes(4096)
    elf = ELFFile(io.BytesIO(helper))
    note = elf.get_section_by_name('.note.gnu.build-id')
    assert note and list(note.iter_notes())[0]['n_desc'] == manifest['helper']['buildId'] and sha(normalized) == manifest['helper']['normalizedSha256'] and len(helper) == manifest['helper']['size'], 'PRIVATE_DAC_HELPER_IDENTITY'
    control = manifest['moduleControl']
    expected_control = copy.deepcopy(baseline['moduleControl'])
    for field, expected in dict(archiveSha256=manifest['archive']['sha256'], helperSha256=sha(helper),
        helperNormalizedSha256=sha(normalized), helperBuildId=manifest['helper']['buildId'],
        helperBytes=len(helper), sourceSha256=BATCH_SOURCE, memberSha256=members[255]['sha256']).items():
        expected_control[field] = expected
    assert control == expected_control, 'PRIVATE_DAC_CONTROL_IDENTITY'
    for name, original in baseline.items():
        if not name.endswith('Repair'):
            continue
        current = copy.deepcopy(manifest.get(name))
        assert isinstance(current, dict), 'PRIVATE_DAC_HISTORY_REMOVED: ' + name
        for field, endpoint in [('deliveredArchiveSha256', manifest['archive']['sha256']), ('deliveredHelperSha256', sha(helper))]:
            if field in original and current.get(field) != original[field]:
                assert current.get(field) == endpoint, 'PRIVATE_DAC_HISTORY_ENDPOINT: ' + name
                current[field] = original[field]
        assert current == original, 'PRIVATE_DAC_HISTORY_REWRITTEN: ' + name
    policy = copy.deepcopy(manifest['environmentPolicyBoot'])
    policy['entryHelperSha256'] = baseline['environmentPolicyBoot']['entryHelperSha256']
    assert policy == baseline['environmentPolicyBoot'], 'PRIVATE_DAC_POLICY_REWRITTEN'
    for name in ('m255IdentityRebind', 'writerReplay', 'archiveBuild', 'oldHelperRepairs'):
        evidence_path = checked(root, repair['evidence'][name])
        evidence = json.loads(evidence_path.read_bytes())
        assert evidence.get('passed') is True, 'PRIVATE_DAC_EVIDENCE_FAILED: ' + name
        if name == 'm255IdentityRebind':
            assert evidence.get('baselineControlSha256') == BATCH_CONTROL and evidence.get('candidateControlSha256') == members[255]['sha256'] and evidence.get('helperSha256') == sha(helper), 'PRIVATE_DAC_GATE_EVIDENCE_IDENTITY'
            assert all(evidence.get(k) is True for k in ('baselineExactReproduction', 'originalGlobalDefinitionsPreserved', 'onlyHelperGateIdentityChanged')), 'PRIVATE_DAC_GATE_EVIDENCE_CONTRACT'
        elif name == 'writerReplay':
            assert evidence.get('dacContract') == DAC and evidence.get('upgradesExistingPermissions') is True and evidence.get('ordinaryUidCannotReadPrivateRecords') is True, 'PRIVATE_DAC_WRITER_EVIDENCE_CONTRACT'
        elif name == 'archiveBuild':
            assert evidence.get('archiveSha256') == manifest['archive']['sha256'] and evidence.get('memberDiff') == claimed and evidence.get('baselineExactReproduction') is True and evidence.get('globalAbiPreserved') is True, 'PRIVATE_DAC_BUILD_EVIDENCE_CONTRACT'
        else:
            assert evidence.get('helperSha256') == sha(helper) and evidence.get('quietBootPreserved') is True and evidence.get('oldRepairAnchorsPreserved') is True, 'PRIVATE_DAC_HELPER_EVIDENCE_CONTRACT'
    return baseline, view
