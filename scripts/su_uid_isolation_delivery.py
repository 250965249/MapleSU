"""Outer r25 delivery gate; older retention/DAC gates run on their intact physical view."""
from pathlib import Path
import io
import json
import sys

BASE_ARCHIVE = 'f015f15ceb91e81f09c0a3b70c4a1c09042c2926ad91380499692a3733c2b4c5'
BASE_HELPER = '02cf4ae01842dd34685c1300cc6316488a0304197faa1ff29e990cb50c611778'

def verify_su_uid_isolation_repair(manifest, root):
    root = Path(root).resolve()
    scripts = str(root / 'scripts')
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from ar_archive import parse_ar
    from elftools.elf.elffile import ELFFile
    from private_dac_delivery import checked, sha, body
    from su_retention_delivery import verify_su_retention_repair
    repair = manifest['suUidIsolationRepair']
    assert repair.get('schemaVersion') == 1 and repair.get('deviceAcceptance') is False, 'SU_UID_SCOPE'
    receipt_path = checked(root, repair['baselinePhysicalReceipt'])
    receipt = json.loads(receipt_path.read_bytes())
    assert receipt.get('schema') == 'maplesu-retention-physical-baseline-r25-v1' and receipt.get('passed') is True, 'SU_UID_PHYSICAL_BASELINE'
    view = Path(receipt['physicalRoot']).resolve()
    assert receipt['manifestSha256'] == '5f15c3d252cec74fd8683b9bed39422d37b8974209e89a6e5f296bf67768d2b9', 'SU_UID_BASELINE_MANIFEST'
    assert len(receipt['files']) == 601, 'SU_UID_BASELINE_FILE_COUNT'
    for name, item in receipt['files'].items():
        path = (view / name).resolve()
        assert path.is_relative_to(view) and path.is_file() and path.stat().st_size == item['bytes'] and sha(path.read_bytes()) == item['sha256'], 'SU_UID_BASELINE_STALE:' + name
    old_manifest = view / 'runtime/maplesu-sdk/SDK-RELEASE.json'
    assert sha(old_manifest.read_bytes()) == receipt['manifestSha256'], 'SU_UID_BASELINE_MANIFEST_STALE'
    baseline = json.loads(old_manifest.read_bytes())
    historical = verify_su_retention_repair(baseline, view)
    assert repair['baselineArchiveSha256'] == baseline['archive']['sha256'] == BASE_ARCHIVE, 'SU_UID_BASE_ARCHIVE'
    assert repair['baselineHelperSha256'] == baseline['helper']['sha256'] == BASE_HELPER, 'SU_UID_BASE_HELPER'
    archive = checked(root, manifest['archive'])
    helper = checked(root, manifest['helper'])
    backend = checked(root, manifest['environmentPolicyBoot']['backend'])
    final_archive, final_helper, final_backend = manifest['archive']['sha256'], manifest['helper']['sha256'], sha(backend.read_bytes())
    assert repair['deliveredArchiveSha256'] == final_archive, 'SU_UID_CURRENT_ARCHIVE'
    assert repair['deliveredHelperSha256'] == final_helper, 'SU_UID_CURRENT_HELPER'
    assert repair['policyBackendSha256'] == final_backend, 'SU_UID_CURRENT_BACKEND'
    for name, expected in repair['sources'].items():
        checked(root, dict(path=name, sha256=expected), 'SU_UID_SOURCE_STALE')
    before_path = view / baseline['archive']['path']
    before_bytes, after_bytes = before_path.read_bytes(), archive.read_bytes()
    before, after = parse_ar(str(before_path))['members'], parse_ar(str(archive))['members']
    assert len(before) == len(after) == 260, 'SU_UID_MEMBER_COUNT'
    changes = []
    for i, (old, new) in enumerate(zip(before, after)):
        assert old['ord'] == new['ord'] == i and old['name'] == new['name'], 'SU_UID_MEMBER_ORDER'
        if old['sha256'] != new['sha256']:
            changes.append(dict(ord=i, name=old['name'], baselineSha256=old['sha256'],
                candidateSha256=new['sha256'], baselineSize=old['size'], candidateSize=new['size']))
    ordinals = {row['ord'] for row in changes}
    assert {48, 52, 81, 83, 255} <= ordinals <= {48, 52, 53, 81, 83, 84, 85, 86, 87, 255}, 'SU_UID_MEMBER_SCOPE'
    assert repair['memberDiff'] == dict(changed=changes, added=[], removed=[], orderErrors=[], unchanged=260-len(changes)), 'SU_UID_MEMBER_DIFF_RECEIPT'
    embedded = ELFFile(io.BytesIO(body(after_bytes, after[52]))).get_section_by_name('.data').data()
    assert embedded == helper.read_bytes() and sha(embedded) == repair['m52EmbeddedHelperSha256'] == final_helper, 'SU_UID_EMBEDDED_HELPER'
    old_helper_bytes = (view / baseline['helper']['path']).read_bytes()
    old_elf, current_elf = ELFFile(io.BytesIO(old_helper_bytes)), ELFFile(io.BytesIO(embedded))
    for name in ('.dynamic', '.rela.dyn', '.rela.plt', '.dynsym', '.eh_frame', '.eh_frame_hdr', '.gcc_except_table'):
        assert old_elf.get_section_by_name(name).data() == current_elf.get_section_by_name(name).data(), 'SU_UID_HELPER_INHERITANCE:' + name
    slot = baseline['helper']['keySlotOffset']
    assert embedded[slot:slot + 4096] == old_helper_bytes[slot:slot + 4096], 'SU_UID_KEY_SLOT_DRIFT'
    loads = [(i, segment) for i, segment in enumerate(old_elf.iter_segments()) if segment['p_type'] == 'PT_LOAD']
    # This window belongs to the exact BASE_HELPER above, not a mutable entry ELF.
    entry_offset, entry_bytes = 1215808, 988
    rx_index, rx = max(loads, key=lambda row: row[1]['p_vaddr'])
    assert rx['p_flags'] == 5 and len(old_helper_bytes) < len(embedded) <= len(old_helper_bytes) + 4096, 'SU_UID_HELPER_APPEND_SCOPE'
    phdr = old_elf['e_phoff'] + rx_index * old_elf['e_phentsize']
    note = old_elf.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    allowed = [(entry_offset, entry_offset + entry_bytes), (0xf5130, 0xf5134),
        (0xfaa34, 0xfaa38), (phdr + 32, phdr + 48), (note, note + 20)]
    assert all(a == b or any(lo <= i < hi for lo, hi in allowed)
        for i, (a, b) in enumerate(zip(old_helper_bytes, embedded))), 'SU_UID_HELPER_INHERITED_BYTES_DRIFT'
    for address in (0xf5130, 0xfaa34):
        instruction = int.from_bytes(embedded[address:address + 4], 'little')
        assert instruction >> 26 == 5, 'SU_UID_HELPER_ENTRY_NOT_BRANCH'
        immediate = instruction & ((1 << 26) - 1)
        if immediate & (1 << 25):
            immediate -= 1 << 26
        target = address + immediate * 4
        assert rx['p_vaddr'] + len(old_helper_bytes) - rx['p_offset'] <= target < rx['p_vaddr'] + len(embedded) - rx['p_offset'], 'SU_UID_HELPER_ENTRY_TARGET'
    for name, value in baseline.items():
        if name.endswith('Repair'):
            assert manifest.get(name) == value, 'SU_UID_HISTORY_REWRITTEN:' + name
    host = json.loads(checked(root, repair['hostExecution']).read_bytes())
    assert host.get('schema') == 'maplesu-su-isolation-host-v1' and host.get('passed') is True and host.get('executed') is True and host.get('deviceAcceptance') is False, 'SU_UID_HOST_EXECUTION'
    assert host['cases'] and all(row.get('passed') is True and row.get('executed') is True for row in host['cases']), 'SU_UID_HOST_CASES'
    return dict(passed=True, currentArchiveSha256=final_archive, currentHelperSha256=final_helper,
        currentBackendSha256=final_backend, changedOrdinals=sorted(ordinals),
        physicalHistoricalGatePassed=True, historical=historical, deviceAcceptance=False)
