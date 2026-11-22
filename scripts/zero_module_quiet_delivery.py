"""Validate the exact quiet-boot helper and its historical m255 gate rebinding."""
import hashlib
import io
import json
from pathlib import Path

from ar_archive import parse_ar
from elftools.elf.elffile import ELFFile

BASELINE_HELPER = '4ba5868f757ef7afa7697605378c9001f5faf51dd3f42db2a470aa92065d0520'
DELIVERED_HELPER = 'a121b912bcc68efeafc3cba8c5077950f5768bef5e8dee2a22ada5e47ba9f7c0'
BASELINE_ARCHIVE = 'e1c4265b8a84e6fb21f047a8b9199a8106a8cf50654df3d9d22af7ec98a576cf'
DELIVERED_ARCHIVE = '84d6b5a35bfdf822768d6005bae478982eabc84158f3a6f85728455657c48843'
BACKEND = '740f53cf0cb00cfab9e0ced982b2a3aa8ba93ef1baf56e3dd165221444c91657'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked(root, row):
    path = (root / row['path']).resolve()
    assert path.is_relative_to(root) and path.is_file() and sha(path.read_bytes()) == row['sha256'], \
        'QUIET_REBIND_EVIDENCE_STALE: ' + row['path']
    return path


def object_contract(data):
    elf = ELFFile(io.BytesIO(data))
    alloc = {s.name: (s['sh_flags'], s['sh_type'], s.data()) for s in elf.iter_sections() if s['sh_flags'] & 2}
    symbols = elf.get_section_by_name('.symtab')
    public = sorted((s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'],
                     s['st_shndx'] == 'SHN_UNDEF') for s in symbols.iter_symbols()
                    if s['st_info']['bind'] != 'STB_LOCAL')
    relocations = []
    for section in elf.iter_sections():
        if section['sh_type'] == 'SHT_RELA':
            for relocation in section.iter_relocations():
                symbol = symbols.get_symbol(relocation['r_info_sym'])
                name = symbol.name or elf.get_section(symbol['st_shndx']).name
                relocations.append((section.name, relocation['r_offset'], relocation['r_info_type'], name,
                                    relocation['r_addend']))
    return alloc, public, sorted(relocations)


def highest_load_header(data):
    elf = ELFFile(io.BytesIO(data))
    index, segment = max(((i, s) for i, s in enumerate(elf.iter_segments()) if s['p_type'] == 'PT_LOAD'),
                         key=lambda row: row[1]['p_vaddr'])
    assert segment['p_flags'] == 5 and elf['e_phentsize'] == 56, 'QUIET_REBIND_RX_HEADER'
    offset = elf['e_phoff'] + index * 56
    return offset, data[offset:offset + 56]


def verify_zero_module_quiet_repair(manifest, root, members):
    repair = manifest['zeroModuleQuietRepair']
    assert repair.get('schemaVersion') == 1 and repair.get('deviceAcceptance') is False and \
        repair.get('complete') is False, 'QUIET_REBIND_SCOPE'
    assert repair.get('baselineHelperSha256') == BASELINE_HELPER and \
        repair.get('deliveredHelperSha256') == manifest['helper']['sha256'] == DELIVERED_HELPER and \
        repair.get('baselineArchiveSha256') == BASELINE_ARCHIVE and \
        repair.get('deliveredArchiveSha256') == manifest['archive']['sha256'] == DELIVERED_ARCHIVE and \
        repair.get('policyBackendSha256') == manifest['environmentPolicyBoot']['backend']['sha256'] == BACKEND, \
        'QUIET_REBIND_CURRENT_IDENTITY'
    sources = repair.get('sources', {})
    assert {'scripts/policy_backend_delivery.py', 'scripts/zero_module_quiet_delivery.py',
            'scripts/tests/test-zero-module-quiet-delivery.py'} <= sources.keys(), 'QUIET_REBIND_SOURCE_MISSING'
    for name, expected in sources.items():
        checked(root, dict(path=name, sha256=expected))
    receipt = json.loads(checked(root, repair['gateRebindReceipt']).read_bytes())
    assert receipt.get('passed') is True and receipt.get('backendUnchanged') is True and \
        receipt.get('R10Closed') is False, 'QUIET_REBIND_RECEIPT'
    for name in ('baselineArchiveSha256', 'deliveredArchiveSha256', 'baselineHelperSha256',
                 'deliveredHelperSha256'):
        assert receipt[name] == repair[name], 'QUIET_REBIND_RECEIPT_IDENTITY'
    before_path = checked(root, repair['baselineArchive'])
    assert repair['baselineArchive']['sha256'] == BASELINE_ARCHIVE, 'QUIET_REBIND_BASELINE_ARCHIVE'
    after_path = (root / manifest['archive']['path']).resolve()
    assert after_path.is_relative_to(root) and sha(after_path.read_bytes()) == DELIVERED_ARCHIVE, \
        'QUIET_REBIND_ARCHIVE'
    before = parse_ar(str(before_path))['members']
    before_data, after_data = before_path.read_bytes(), after_path.read_bytes()
    assert len(before) == len(members) == 258, 'QUIET_REBIND_MEMBER_COUNT'
    changed = [i for i, (old, new) in enumerate(zip(before, members)) if old['sha256'] != new['sha256']]
    assert changed == [52, 255] and all(old['name'] == new['name'] and old['ord'] == new['ord']
        for old, new in zip(before, members)), 'QUIET_REBIND_MEMBER_DIFF'

    def body(blob, member):
        return blob[member['body_offset']:member['body_offset'] + member['size']]

    old_helper = ELFFile(io.BytesIO(body(before_data, before[52]))).get_section_by_name('.data').data()
    helper = ELFFile(io.BytesIO(body(after_data, members[52]))).get_section_by_name('.data').data()
    assert sha(old_helper) == BASELINE_HELPER and sha(helper) == DELIVERED_HELPER, 'QUIET_REBIND_HELPER'
    helper_path = (root / manifest['helper']['path']).resolve()
    assert helper_path.is_relative_to(root) and helper_path.read_bytes() == helper, 'QUIET_REBIND_HELPER_FILE'
    normalized = bytearray(helper)
    slot = manifest['helper']['keySlotOffset']
    assert slot == 182886 and helper[slot:slot + 4096] == old_helper[slot:slot + 4096], 'QUIET_REBIND_KEY_SLOT'
    normalized[slot:slot + 4096] = bytes(4096)
    image = ELFFile(io.BytesIO(helper))
    note = image.get_section_by_name('.note.gnu.build-id')
    assert note is not None and list(note.iter_notes())[0]['n_desc'] == manifest['helper']['buildId'] and \
        sha(normalized) == manifest['helper']['normalizedSha256'] and \
        len(helper) == manifest['helper']['size'], 'QUIET_REBIND_HELPER_IDENTITY'
    for field in ('helperSha256', 'helperNormalizedSha256', 'helperBuildId', 'helperBytes'):
        assert manifest['moduleControl'][field] == {'helperSha256': sha(helper),
            'helperNormalizedSha256': sha(normalized), 'helperBuildId': manifest['helper']['buildId'],
            'helperBytes': len(helper)}[field], 'QUIET_REBIND_CONTROL_IDENTITY'
    old_at, old_header = highest_load_header(old_helper)
    new_at, new_header = highest_load_header(helper)
    assert old_at == new_at == receipt['gatePhdrOffset'] and old_header.hex() == receipt['baselineGatePhdrHex'] and \
        new_header.hex() == receipt['deliveredGatePhdrHex'], 'QUIET_REBIND_HEADER_RECEIPT'
    old_control, control = body(before_data, before[255]), body(after_data, members[255])
    assert sha(old_control) == receipt['baselineControlSha256'] and \
        sha(control) == receipt['deliveredControlSha256'] == manifest['moduleControl']['memberSha256'], \
        'QUIET_REBIND_CONTROL_CHAIN'
    old_contract, contract = object_contract(old_control), object_contract(control)
    assert old_contract[1:] == contract[1:] and old_contract[0].keys() == contract[0].keys(), 'QUIET_REBIND_ABI'
    replacements = 0
    for name, (flags, kind, old_data) in old_contract[0].items():
        new_flags, new_kind, data = contract[0][name]
        replacements += data.count(new_header)
        assert (flags, kind) == (new_flags, new_kind) and data.replace(new_header, old_header) == old_data, \
            'QUIET_REBIND_ALLOC: ' + name
    assert replacements == 1, 'QUIET_REBIND_HEADER_COUNT'
    backend = checked(root, dict(path=manifest['environmentPolicyBoot']['backend']['path'], sha256=BACKEND)).read_bytes()
    assert old_header not in backend and new_header not in backend, 'QUIET_REBIND_BACKEND_HEADER'
    symbol_table = ELFFile(io.BytesIO(backend)).get_section_by_name('.symtab')
    defined = {s.name for s in symbol_table.iter_symbols() if s['st_shndx'] != 'SHN_UNDEF'}
    public = {row[0] for row in contract[1] if row[1] == 'STB_GLOBAL' and not row[-1]}
    assert not public & defined, 'QUIET_REBIND_BACKEND_CONTROL_SYMBOLS'
    return receipt


_verify_r10_zero_module_quiet = verify_zero_module_quiet_repair

def verify_zero_module_quiet_repair(manifest, root, members):
    if not manifest.get('privateDacRepair'):
        return _verify_r10_zero_module_quiet(manifest, root, members)
    from private_dac_delivery import verify_private_dac_repair
    baseline, view = verify_private_dac_repair(manifest, root)
    original = parse_ar(str(view / baseline['archive']['path']))['members']
    return _verify_r10_zero_module_quiet(baseline, view, original)
