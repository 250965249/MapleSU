"""Stamp a paired SDK/helper version without changing the legacy module ABI."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
sha = lambda data: hashlib.sha256(data).hexdigest()


def symbols(data):
    table = ELFFile(io.BytesIO(data)).get_section_by_name('.symtab')
    return sorted((s.name, s['st_info']['bind'], s['st_info']['type'],
                   s['st_other']['visibility'], s['st_shndx'] == 'SHN_UNDEF')
                  for s in table.iter_symbols() if s['st_info']['bind'] != 'STB_LOCAL')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', required=True, type=Path)
    parser.add_argument('--sdk-version', required=True)
    parser.add_argument('--app-version', required=True)
    parser.add_argument('--version-code', required=True, type=int)
    parser.add_argument('--build-id', required=True)
    args = parser.parse_args()
    source, out = args.source.resolve(), args.out.resolve()
    assert source != out and source.is_relative_to(ROOT) and out.is_relative_to(ROOT / 'work')
    assert all(re.fullmatch(r'[0-9]+[.][0-9]+[.][0-9]+', v) for v in (args.sdk_version, args.app_version))
    assert re.fullmatch(r'[A-Za-z0-9._-]+', args.build_id)
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((source / 'SDK-RELEASE.json').read_text())
    archive = source / 'lib/arm64-v8a/libkernel_module_kit_static.a'
    base = archive.read_bytes()
    assert sha(base) == manifest['archive']['sha256']
    before = parse_ar(str(archive))
    original_helper = (source / 'embedded-bootstrap.elf').read_bytes()
    assert sha(original_helper) == manifest['helper']['sha256']
    old_version, new_version = (manifest['sdkVersion'] + '\0').encode(), (args.sdk_version + '\0').encode()
    assert len(old_version) == len(new_version) and old_version != new_version
    assert original_helper.count(old_version) == 1
    helper = bytearray(original_helper.replace(old_version, new_version))
    elf = ELFFile(io.BytesIO(helper))
    note = elf.get_section_by_name('.note.gnu.build-id')
    assert note['sh_size'] == 36
    at = note['sh_offset'] + 16
    helper[at:at + 20] = bytes(20)
    slot = manifest['helper']['keySlotOffset']
    normalized = bytearray(helper)
    normalized[slot:slot + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[at:at + 20] = normalized[at:at + 20] = build_id
    assert helper[slot:slot + 4096] == original_helper[slot:slot + 4096]
    # The gate pins the load header, branch and gate code; version stamping must
    # leave those bytes unchanged, so its existing object remains valid.
    gate = manifest['moduleControl']
    index, tail = max(((i, p) for i, p in enumerate(elf.iter_segments()) if p['p_type'] == 'PT_LOAD'),
                      key=lambda pair: pair[1]['p_vaddr'])
    ph = elf['e_phoff'] + index * elf['e_phentsize']
    for start, size in ((gate['gateFileOffset'], gate['gateBytes']), (0xa6d68, 4), (ph, 56)):
        assert helper[start:start + size] == original_helper[start:start + size]
    changes = []
    for ordinal in (52, 53):
        row = before['members'][ordinal]
        original = base[row['body_offset']:row['body_offset'] + row['size']]
        assert original.startswith(b'\x7fELF')
        if ordinal == 52:
            data = ELFFile(io.BytesIO(original)).get_section_by_name('.data')
            assert data.data() == original_helper and len(helper) == data['sh_size']
            patched = original[:data['sh_offset']] + helper + original[data['sh_offset'] + data['sh_size']:]
        else:
            assert original.count(old_version) == 1
            patched = original.replace(old_version, new_version)
        assert symbols(original) == symbols(patched)
        target = out / row['name']
        target.write_bytes(patched)
        changes.append(target)
    candidate = out / 'lib/arm64-v8a' / archive.name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(base)
    ar = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-ar.exe'
    for command in ([ar, 'rD', candidate, *changes], [ar, 'sD', candidate]):
        subprocess.run(list(map(str, command)), check=True, capture_output=True, timeout=60)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [m['ord'] for m in diff['changed']] == [52, 53]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    (out / 'embedded-bootstrap.elf').write_bytes(helper)
    baseline = parse_ar(str(ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
    count = baseline['member_count']
    full = compare_members(baseline, dict(after, members=after['members'][:count], member_count=count))
    full['added'] = [dict(ord=m['ord'], name=m['name'], candidateSha256=m['sha256']) for m in after['members'][count:]]
    diff_file = out / 'SU-AUTH-MEMBER-DIFF.json'
    diff_file.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=baseline['file_sha256'],
        archiveSha256=after['file_sha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
    manifest.update(sdkVersion=args.sdk_version, sdkBuildId=args.build_id,
                    appVersion=args.app_version, versionCode=args.version_code,
                    generatedUtc=datetime.now(timezone.utc).isoformat())
    manifest['archive'].update(path=candidate.relative_to(ROOT).as_posix(), sha256=after['file_sha256'], size=candidate.stat().st_size)
    for key in ('helper', 'bootstrap'):
        manifest[key].update(sha256=sha(helper), buildId=build_id.hex(), size=len(helper))
    manifest['helper']['normalizedSha256'] = sha(normalized)
    manifest['moduleControl'].update(helperSha256=sha(helper), helperNormalizedSha256=sha(normalized),
        helperBuildId=build_id.hex(), helperBytes=len(helper), archiveSha256=after['file_sha256'])
    for row in diff['changed']:
        for repair in manifest['repairs']:
            if row['ord'] == repair['memberOrdinal']: repair['sha256'] = row['candidateSha256']
    manifest['memberDiff'].update(path=diff_file.relative_to(ROOT).as_posix(), sha256=sha(diff_file.read_bytes()),
        changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
    policy = manifest['environmentPolicyBoot']
    backend = policy['backend']
    backend_bytes = (ROOT / backend['path']).read_bytes()
    assert sha(backend_bytes) == backend['sha256']
    backend_copy = out / 'backend' / backend['fileName']
    backend_copy.parent.mkdir(exist_ok=True)
    backend_copy.write_bytes(backend_bytes)
    backend['path'] = backend_copy.relative_to(ROOT).as_posix()
    policy['entryHelperSha256'] = sha(helper)
    manifest['versionStamp'] = dict(previousSdkVersion=old_version[:-1].decode(), sourceArchiveSha256=sha(base),
        gateBytesUnchanged=True, abiPreserved=True, keySlotPreserved=True,
        memberChanges=[r['ord'] for r in diff['changed']])
    (out / 'SDK-RELEASE.json').write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run([sys.executable, str(ROOT / 'scripts/sync-ultra-sdk-identity.py'),
        '--manifest', str(out / 'SDK-RELEASE.json'), '--output', str(out / 'SDK-IDENTITY.cmake')], check=True)
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=True, sdkVersion=args.sdk_version,
        appVersion=args.app_version, archiveSha256=after['file_sha256'], helperNormalizedSha256=sha(normalized),
        memberDiff=diff, abiPreserved=True, gateUnchanged=True, deviceAccess=False)
    (out / 'version-verification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k:v for k,v in record.items() if k != 'memberDiff'}))


if __name__ == '__main__':
    main()
