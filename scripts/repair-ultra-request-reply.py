"""Repair executor replies and invalid exec requests on the pinned r13 SDK."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from verify_sdk_member_diff import parse_ar, compare_members

ROOT = Path(__file__).resolve().parents[1]
BASE = 'cde6eb6f9889d8b57a40e1227fbe648312951f2021ce855d1afbf17e92e04661'
sha = lambda data: hashlib.sha256(data).hexdigest()


def abi(blob):
    table = ELFFile(io.BytesIO(blob)).get_section_by_name('.symtab')
    return sorted((s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'],
                   s['st_shndx'] == 'SHN_UNDEF') for s in table.iter_symbols() if s['st_info']['bind'] != 'STB_LOCAL')


def once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new, 1)


def patch_request(ir):
    # Keep the original signed error, plus the complete reply after INVALID_GID
    # is converted to Android's default overflowgid. Do not match low bits alone.
    ir = once(ir, '  %maplesu.failed = icmp eq i64 %60, -19999\n',
        '  %maplesu.legacy_failed = icmp eq i64 %60, -19999\n'
        '  %maplesu.mapped_failed = icmp eq i64 %60, 281470681723361\n'
        '  %maplesu.failed = or i1 %maplesu.legacy_failed, %maplesu.mapped_failed\n')
    symbol = '_ZN13kernel_module30unsafe_request_kernel_exec_memEmjRm'
    match = re.search(r'^define[^\n]*@' + symbol + r'\([^\n]*\{\n.*?\n}', ir, re.M | re.S)
    assert match
    body = re.sub(r'%(\d+)\b', r'%sdk\1', match[0])
    body = once(body, '  %sdk13 = tail call',
        '  %maplesu.address_ok = icmp ne i64 %sdk0, 0\n'
        '  %maplesu.size_ok = icmp ne i32 %sdk11, 0\n'
        '  %maplesu.pages_ok = icmp ne i32 %sdk12, 0\n'
        '  %maplesu.range_ok = and i1 %maplesu.size_ok, %maplesu.pages_ok\n'
        '  %maplesu.valid = and i1 %maplesu.address_ok, %maplesu.range_ok\n'
        '  br i1 %maplesu.valid, label %maplesu.send, label %maplesu.invalid\n\n'
        'maplesu.send:\n  %sdk13 = tail call')
    body = once(body, '\n}', '\n\nmaplesu.invalid:\n  ret i64 -19999\n}')
    return ir[:match.start()] + body + ir[match.end():]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--install', action='store_true')
    a = parser.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sdk = ROOT / 'runtime/maplesu-sdk'
    if a.install:
        assert a.archive.resolve() == (sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a').resolve(), \
            '--install requires the current SDK archive path'
    data = a.archive.read_bytes()
    assert sha(data) == BASE, 'Use the frozen r13 archive; preserve concurrent SDK edits'
    before = parse_ar(str(a.archive))
    tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *args):
        r = subprocess.run([str(tool / (name + '.exe')), *map(str, args)], capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(r.stdout + r.stderr)

    def member(ordinal):
        m = before['members'][ordinal]
        return m, data[m['body_offset']:m['body_offset'] + m['size']]

    m, original = member(23)
    source = ROOT / 'runtime/ultra/panic/sdk-m023-r13.bc'
    assert sha(source.read_bytes()) == 'd2bff48076d915a97fd34dd9ea1bc00bea1532818ca00c4faa8c190fe24cb0e2'
    baseline = out / 'm023.baseline.o'
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', source, '-o', baseline)
    assert baseline.read_bytes() == original, 'Recovered IR must reproduce the shipped member exactly'
    ir = out / 'm023.baseline.ll'
    run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', source, '-o', ir)
    patched = out / 'm023.patched.ll'
    patched.write_text(patch_request(ir.read_text()))
    request = out / m['name']
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', patched, '-o', request)
    assert abi(request.read_bytes()) == abi(original)

    m, original = member(52)
    elf = ELFFile(io.BytesIO(original))
    old_helper = elf.get_section_by_name('.data').data()
    assert sha(old_helper) == '9956d245a875a112315d05978e4f8cfdc4ba07497e7e537080e89472d48e424c'
    helper = bytearray(old_helper)
    obj, linked, binary = [out / ('bootstrap-request.' + suffix) for suffix in ('o', 'elf', 'bin')]
    run('clang', '--target=aarch64-linux-android21', '-c', ROOT / 'runtime/ultra/authorization/bootstrap_request.S', '-o', obj)
    run('ld.lld', '-Ttext=0xc4598', '--defsym=ROOT_KEY=0x11fa88', '--defsym=SYSCALL=0x112fc0',
        '--defsym=GET_SUID=0xc4560', '--defsym=GET_SGID=0xc457c', '--defsym=EXECUTOR_RETURN=0xc5e60',
        '--entry=maplesu_bootstrap_request', obj, '-o', linked)
    run('llvm-objcopy', '-O', 'binary', '--only-section=.text', linked, binary)
    replacement = binary.read_bytes()
    assert len(replacement) == 336
    # Keep the staging-failure thunk and all subsequent helper functions in place.
    assert replacement[304:] == old_helper[0xc46c8:0xc46e8]
    helper[0xc4598:0xc46c8] = replacement[:304]
    he = ELFFile(io.BytesIO(old_helper))
    # The original FDE already describes X29+48 and the saved-register order.
    # Only its first SP-relative row still describes the old 128-byte frame.
    request_fde = next(e for e in he.get_dwarf_info().EH_CFI_entries()
                       if isinstance(e, FDE) and e['initial_location'] == 0xc4598)
    assert request_fde['address_range'] == 0x15c
    fde_at = he.get_section_by_name('.eh_frame')['sh_offset'] + request_fde.offset
    fde_bytes = old_helper[fde_at:fde_at + request_fde['length'] + 4]
    old_cfa = bytes.fromhex('44 0e 80 01 50 0c 1d 30')
    assert fde_bytes.count(old_cfa) == 1
    unwind_at = fde_at + fde_bytes.index(old_cfa) + 2
    helper[unwind_at] = 0xb0  # DW_CFA_def_cfa_offset: 176, same ULEB size.
    note = he.get_section_by_name('.note.gnu.build-id')['sh_offset'] + 16
    helper[note:note + 20] = bytes(20)
    normalized = bytearray(helper)
    normalized[182886:182886 + 4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[note:note + 20] = normalized[note:note + 20] = build_id
    assert len(helper) == len(old_helper)
    assert helper[:note] == old_helper[:note]
    assert helper[note + 20:unwind_at] == old_helper[note + 20:unwind_at]
    assert helper[unwind_at + 1:0xc4598] == old_helper[unwind_at + 1:0xc4598]
    assert helper[0xc46c8:] == old_helper[0xc46c8:]
    helper_file = out / 'embedded-bootstrap.elf'
    helper_file.write_bytes(helper)
    original_obj = out / 'm052.baseline.o'
    original_obj.write_bytes(original)
    installer = out / m['name']
    run('llvm-objcopy', '--update-section', f'.data={helper_file}', original_obj, installer)
    updated = ELFFile(io.BytesIO(installer.read_bytes()))
    assert abi(installer.read_bytes()) == abi(original)
    assert elf.num_sections() == updated.num_sections()
    for s, t in zip(elf.iter_sections(), updated.iter_sections()):
        assert s.name == t.name
        if s.name != '.data':
            assert s.data() == t.data(), s.name
    candidate = out / a.archive.name
    assert candidate.resolve() != a.archive.resolve()
    candidate.write_bytes(data)
    run('llvm-ar', 'rD', candidate, request, installer)
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [m['ord'] for m in diff['changed']] == [23, 52]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    report = dict(baselineArchiveSha256=BASE, archiveSha256=sha(candidate.read_bytes()), memberDiff=diff,
        helperSha256=sha(helper), helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(),
        helperBytes=len(helper), abiPreserved=True, helperProgramHeadersUnchanged=True,
        installerCodeUnchanged=True, sourceReproducesR13Exactly=True, deviceVerification=False,
        requestUnwindRepair=dict(frameBytes=176, savedRegisters=[19, 20, 21, 22, 29, 30],
            fdeFileOffset=fde_at, cfaByteFileOffset=unwind_at, originalFdeRangePreserved=True),
        replyScope='Legacy signed error and Android overflowgid=65534; nondefault overflowgid is not decoded',
        evidence='work/xiaomi-panic-20261107/sdk-r14',
        sources={str(p.relative_to(ROOT)).replace('\\', '/'): sha(p.read_bytes()) for p in [
            source, ROOT / 'runtime/ultra/authorization/bootstrap_request.S', Path(__file__).resolve()]})
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    if a.install:
        manifest_path = sdk / 'SDK-RELEASE.json'
        manifest = json.loads(manifest_path.read_text())
        assert manifest['archive']['sha256'] == sha(a.archive.read_bytes()) == BASE
        backup = out / 'before'
        backup.mkdir(exist_ok=True)
        for p in [a.archive, manifest_path, sdk / 'SDK-IDENTITY.cmake', sdk / 'SU-AUTH-MEMBER-DIFF.json']:
            shutil.copy2(p, backup / p.name)
        baseline = parse_ar(str(ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
        n = baseline['member_count']
        full = compare_members(baseline, dict(after, members=after['members'][:n], member_count=n))
        full['added'] = [dict(ord=m['ord'], name=m['name'], candidateSha256=m['sha256']) for m in after['members'][n:]]
        diff_path = sdk / 'SU-AUTH-MEMBER-DIFF.json'
        diff_path.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=baseline['file_sha256'],
            archiveSha256=report['archiveSha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
        manifest['sdkBuildId'] = 'maplesu-ultra-5.1.0-request-validation-r14-20261107'
        manifest['generatedUtc'] = datetime.now(timezone.utc).isoformat()
        manifest['archive'].update(sha256=report['archiveSha256'], size=candidate.stat().st_size)
        for key in ['helper', 'bootstrap']:
            manifest[key].update(sha256=report['helperSha256'], buildId=report['helperBuildId'], size=len(helper), changed=True)
        manifest['helper']['normalizedSha256'] = report['helperNormalizedSha256']
        manifest['moduleControl'].update(helperSha256=report['helperSha256'], helperNormalizedSha256=report['helperNormalizedSha256'],
            helperBuildId=report['helperBuildId'], helperBytes=len(helper), archiveSha256=report['archiveSha256'])
        manifest['requestValidationRepair'] = report
        manifest['statement'] = 'SDK r14: propagate INVALID_GID-converted executor errors, reject zero/overflow execution requests, and align helper saved registers/CFA with the request unwind table. r13 atomic installers, Identity, authorization, module ABI and prior Panic repairs preserved. Device Panic acceptance pending.'
        for row in diff['changed']:
            for repair in manifest['repairs']:
                if repair['memberOrdinal'] == row['ord']:
                    repair['sha256'] = row['candidateSha256']
        manifest['memberDiff'].update(sha256=sha(diff_path.read_bytes()), changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
        shutil.copy2(candidate, a.archive)
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
        subprocess.run([sys.executable, str(ROOT / 'scripts/sync-ultra-sdk-identity.py')], check=True)
    print(json.dumps({k: v for k, v in report.items() if k not in ['sources', 'memberDiff']}, indent=2))


if __name__ == '__main__':
    main()
