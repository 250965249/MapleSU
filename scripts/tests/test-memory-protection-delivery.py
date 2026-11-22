"""Validate real candidate permission metadata; no machine code is executed."""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from elftools.elf.elffile import ELFFile
from ar_archive import parse_ar
from policy_backend_delivery import MEMORY_PROTECTION_SOURCES, digest, verify_delivery, verify_memory_protection_repair

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    assert 'memoryProtectionRepair' in manifest, 'Real candidate repair metadata required'
    verify_delivery(manifest, ROOT)
    archive = ROOT / manifest['archive']['path']
    members = parse_ar(str(archive))['members']
    member = members[52]
    with archive.open('rb') as handle:
        handle.seek(member['body_offset'])
        helper = ELFFile(io.BytesIO(handle.read(member['size']))).get_section_by_name('.data').data()
    fixture = dict(manifest=manifest, members=members, helper=bytearray(helper))
    results = [dict(name='full-candidate-delivery', passed=True)]

    def check(name, mutate=lambda c: None, expected=None):
        candidate = copy.deepcopy(fixture)
        mutate(candidate)
        try:
            verify_memory_protection_repair(candidate['manifest'], ROOT, candidate['members'], candidate['helper'])
        except AssertionError as error:
            assert expected is not None and expected in str(error), name + ': ' + str(error)
        else:
            assert expected is None, 'Expected failure: ' + name
        results.append(dict(name=name, passed=True))

    def repair(candidate):
        return candidate['manifest']['memoryProtectionRepair']

    check('paired-permission-repair')
    check('optional-repair', lambda c: c['manifest'].pop('memoryProtectionRepair'))
    for field, label in [('deliveredArchiveSha256', 'SDK'), ('deliveredHelperSha256', 'HELPER'),
                         ('policyBackendSha256', 'BACKEND')]:
        check('current-' + label.lower(), lambda c, field=field: repair(c).update({field: '0' * 64}),
              'MEMORY_PROTECTION_' + label + '_STALE')
    check('actual-helper', lambda c: c['helper'].__setitem__(0, 0), 'MEMORY_PROTECTION_HELPER_STALE')
    for source in sorted(MEMORY_PROTECTION_SOURCES):
        check('required-source-' + Path(source).name,
              lambda c, source=source: repair(c)['sources'].pop(source), 'MEMORY_PROTECTION_SOURCE_MISSING')
    source = next(iter(sorted(MEMORY_PROTECTION_SOURCES)))
    check('source-stale', lambda c: repair(c)['sources'].update({source: '0' * 64}), 'MEMORY_PROTECTION_SOURCE_STALE')
    check('source-outside-project', lambda c: repair(c)['sources'].update({'../outside': '0' * 64}),
          'MEMORY_PROTECTION_SOURCE_STALE')
    for field, value in [('ord', 23), ('name', 'other.o'), ('sha256', '0' * 64)]:
        check('member-' + field, lambda c, field=field, value=value: c['members'][24].update({field: value}),
              'MEMORY_PROTECTION_MEMBER_STALE')
    check('duplicate-member', lambda c: c['members'].append(copy.deepcopy(c['members'][24])), 'MEMORY_PROTECTION_MEMBER_STALE')
    check('candidate-object-stale', lambda c: repair(c).update(candidateObjectSha256='0' * 64), 'MEMORY_PROTECTION_MEMBER_STALE')
    check('runtime-claim', lambda c: repair(c).update(deviceAcceptance=True), 'MEMORY_PROTECTION_VALIDATION_SCOPE')
    check('validation-scope', lambda c: repair(c).update(validationScope=['runtime']), 'MEMORY_PROTECTION_VALIDATION_SCOPE')
    for field, value in [('offset', -1), ('candidateHex', '00' * 4), ('baselineHex', '00')]:
        check('entry-' + field, lambda c, field=field, value=value: repair(c)['helper']['entryPatch'].update({field: value}),
              'MEMORY_PROTECTION_ENTRY_STALE')
    for field, value in [('offset', -1), ('bytes', 0), ('address', 0), ('sha256', '0' * 64)]:
        check('extension-' + field, lambda c, field=field, value=value: repair(c)['helper']['extension'].update({field: value}),
              'MEMORY_PROTECTION_EXTENSION_STALE')

    def remove_execute_permission(candidate):
        image = ELFFile(io.BytesIO(candidate['helper']))
        offset = repair(candidate)['helper']['extension']['offset']
        index = next(i for i, s in enumerate(image.iter_segments()) if s['p_type'] == 'PT_LOAD' and
                     s['p_offset'] <= offset < s['p_offset'] + s['p_filesz'])
        struct.pack_into('<I', candidate['helper'], image['e_phoff'] + index * image['e_phentsize'] + 4, 4)
        changed = hashlib.sha256(candidate['helper']).hexdigest()
        candidate['manifest']['helper']['sha256'] = changed
        repair(candidate)['deliveredHelperSha256'] = changed

    check('extension-not-executable', remove_execute_permission, 'MEMORY_PROTECTION_EXTENSION_STALE')
    report = dict(passed=True, cases=len(results), results=results, manifestSha256=digest(args.manifest),
                  deviceAccess=False, machineCodeExecuted=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=True, cases=len(results), machineCodeExecuted=False)))


if __name__ == '__main__':
    main()
