"""Repair Fault classification and query replies on top of the frozen r15 SDK."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar, compare_members

ROOT = Path(__file__).resolve().parents[1]
BASE = 'e82179f4bc7ed5474a7d4e46169ae28cbb1a089a094a67f14abd49dec0efe4e4'
INPUT = '6928675234ac47e00471c193226be99c3601bd9b3da30f0d6bbde55c4d37683e'
PUBLIC = '_ZN7maplesu3sdk29get_maplesu_environment_stateEPKc'
UNSAFE = '_ZN7maplesu3sdkL36unsafe_get_maplesu_environment_stateEv'
sha = lambda b: hashlib.sha256(b).hexdigest()
spec = importlib.util.spec_from_file_location('upgrade', ROOT / 'scripts/repair-ultra-environment-upgrade.py')
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def patch(ir):
    match, body = upgrade.function_body(ir, PUBLIC)
    old = 'store i32 0, ptr %sdk3, align 4'
    assert body.count(old) == 1
    body = body.replace(old, 'store i32 3, ptr %sdk3, align 4')
    old = '@waitpid(i32 noundef %sdk21, ptr noundef nonnull %sdk4, i32 noundef 0)'
    assert body.count(old) == 1
    body = body.replace(old, '@maplesu_wait_environment_child(i32 %sdk21, ptr %sdk4)')
    old = '\nsdk31:\n'
    assert body.count(old) == 1
    body = body.replace(old, old + '''  %wait.ok = icmp eq i32 %sdk22, %sdk21
  %child.valid = icmp sgt i32 %sdk21, 0
  %child.status = load i32, ptr %sdk4, align 4
  %child.ok = icmp eq i32 %child.status, 0
  %reply.range = icmp ult i32 %sdk19, 4
  %reply.read = and i1 %sdk17, %wait.ok
  %reply.exit = and i1 %child.valid, %child.ok
  %reply.transport = and i1 %reply.read, %reply.exit
  %reply.ok = and i1 %reply.transport, %reply.range
  %verified.state = select i1 %reply.ok, i32 %sdk19, i32 3
''')
    assert body.count('ret i32 %sdk19') == 1
    body = body.replace('ret i32 %sdk19', 'ret i32 %verified.state')
    ir = ir[:match.start()] + body + ir[match.end():]
    match, _ = upgrade.function_body(ir, UNSAFE)
    ir = ir[:match.start()] + f'''define internal fastcc noundef i32 @{UNSAFE}() unnamed_addr #1 {{
  %state = tail call i32 @maplesu_environment_state()
  ret i32 %state
}}''' + ir[match.end():]
    assert ir.count(', !range !88') == 2 and ir.count('!88 = !{i32 0, i32 3}') == 1
    ir = ir.replace('!88 = !{i32 0, i32 3}', '!88 = !{i32 0, i32 4}')
    return ir + '''
declare i32 @maplesu_environment_state()
declare i32 @maplesu_wait_environment_child(i32, ptr)
define hidden void @maplesu_environment_paths(ptr %helper, ptr %version) {
  call fastcc void @_ZN7maplesu3sdkL26get_autorun_bootstrap_pathEv(ptr sret(%"class.std::__ndk1::basic_string") align 8 %helper)
  call fastcc void @_ZN7maplesu3sdkL23get_maplesu_sdk_ver_pathEv(ptr sret(%"class.std::__ndk1::basic_string") align 8 %version)
  ret void
}
'''


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--ndk', type=Path, required=True)
    p.add_argument('--install', action='store_true')
    a = p.parse_args()
    sdk, out = ROOT / 'runtime/maplesu-sdk', a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = a.archive.read_bytes()
    assert sha(data) == BASE, 'Use the frozen r15 archive; retain the boot lifecycle repair'
    tool = a.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *argv):
        r = subprocess.run([str(tool / (name + '.exe')), *map(str, argv)], capture_output=True, text=True)
        if r.returncode: raise RuntimeError(r.stdout + r.stderr)

    before = parse_ar(str(a.archive))
    m = before['members'][53]
    original = data[m['body_offset']:m['body_offset'] + m['size']]
    source = ROOT / 'runtime/ultra/boot/sdk-m053.bc'
    assert sha(source.read_bytes()) == INPUT
    baseline = out / 'm053.baseline.ll'
    run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', source, '-o', baseline)
    baseline_obj = out / 'm053.baseline.o'
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', baseline, '-o', baseline_obj)
    reproduced = baseline_obj.read_bytes().replace(b'5.0.5\0', b'5.1.0\0')
    assert reproduced == original, 'Recovered installer input must reproduce r15 byte-for-byte'
    patched = out / 'm053.patched.ll'
    patched.write_text(patch(baseline.read_text()))
    member = out / m['name']
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', patched, '-o', member)
    member.write_bytes(member.read_bytes().replace(b'5.0.5\0', b'5.1.0\0'))

    def exports(blob):
        e = ELFFile(io.BytesIO(blob))
        return {s.name for s in e.get_section_by_name('.symtab').iter_symbols()
                if s['st_info']['bind'] == 'STB_GLOBAL' and s['st_shndx'] != 'SHN_UNDEF'}
    assert exports(original) <= exports(member.read_bytes()), 'Keep every existing SDK export'
    classifier = ROOT / 'runtime/ultra/boot/environment_state.cpp'
    obj = out / 'maplesu_environment_state.o'
    run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions',
        '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections', '-Wall', '-Wextra', '-Werror',
        '-I', sdk / 'include', '-c', classifier, '-o', obj)
    candidate = out / a.archive.name
    assert candidate.resolve() != a.archive.resolve()
    candidate.write_bytes(data)
    run('llvm-ar', 'rD', candidate, member, obj)
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    n = before['member_count']
    diff = compare_members(before, dict(after, members=after['members'][:n], member_count=n))
    diff['added'] = [dict(ord=s['ord'], name=s['name'], candidateSha256=s['sha256']) for s in after['members'][n:]]
    assert [row['ord'] for row in diff['changed']] == [53]
    assert len(diff['added']) == 1 and diff['added'][0]['name'] == obj.name
    assert not diff['removed'] and not diff['orderErrors']
    report = dict(baselineArchiveSha256=BASE, archiveSha256=sha(candidate.read_bytes()), memberDiff=diff,
        baselineReproducedExactly=True, existingSdkExportsPreserved=True, helperUnchanged=True,
        faultCondition='Current-boot duplicate receipt, safe_flag=3, enabled protection flag',
        runningCondition='safe_flag=2 and a valid work receipt matching the current boot UUID',
        unknownCondition='Startup/incomplete/read/root/IPC errors; no persistence mutation or capability grant',
        enumValues=dict(NotInstalled=0, Running=1, Fault=2, Unknown=3), deviceVerification=False,
        sources={str(s.relative_to(ROOT)).replace('\\', '/'): sha(s.read_bytes()) for s in
                 [source, classifier, Path(__file__).resolve(), sdk / 'include/maplesu_sdk/maplesu_installer.h']})
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    if a.install:
        assert a.archive.resolve() == (sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a').resolve()
        backup = out / 'before'
        assert not backup.exists(), 'Preserve the original r15 backup'
        backup.mkdir()
        manifest_path = sdk / 'SDK-RELEASE.json'
        for path in [a.archive, manifest_path, sdk / 'SDK-IDENTITY.cmake', sdk / 'SU-AUTH-MEMBER-DIFF.json']:
            shutil.copy2(path, backup / path.name)
        manifest = json.loads(manifest_path.read_text())
        assert manifest['archive']['sha256'] == BASE
        baseline_sdk = parse_ar(str(ROOT / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'))
        n = baseline_sdk['member_count']
        full = compare_members(baseline_sdk, dict(after, members=after['members'][:n], member_count=n))
        full['added'] = [dict(ord=s['ord'], name=s['name'], candidateSha256=s['sha256']) for s in after['members'][n:]]
        diff_path = sdk / 'SU-AUTH-MEMBER-DIFF.json'
        diff_path.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=baseline_sdk['file_sha256'],
            archiveSha256=report['archiveSha256'], totalMembers=after['member_count'], **full), indent=2) + '\n')
        manifest.update(sdkBuildId='maplesu-ultra-5.1.0-environment-state-r16-20261108',
                        generatedUtc=datetime.now(timezone.utc).isoformat(), environmentStateRepair=report)
        manifest['archive'].update(sha256=report['archiveSha256'], size=candidate.stat().st_size)
        manifest['moduleControl']['archiveSha256'] = report['archiveSha256']
        manifest['repairs'] = [repair for repair in manifest['repairs'] if repair['memberOrdinal'] != 53]
        manifest['repairs'].append(dict(id='m053', memberOrdinal=53, memberName=m['name'], sha256=sha(member.read_bytes())))
        manifest['memberDiff'].update(sha256=sha(diff_path.read_bytes()), changed=len(full['changed']), added=len(full['added']), removed=len(full['removed']))
        manifest['statement'] = 'SDK r16: Fault requires current-boot protection evidence; uncertain startup, read, root and IPC results are Unknown. Running requires the completed current boot. r15 synchronous completion and all earlier repairs retained. Device acceptance pending.'
        shutil.copy2(candidate, a.archive)
        manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
        subprocess.run([sys.executable, str(ROOT / 'scripts/sync-ultra-sdk-identity.py')], check=True)
    print(json.dumps(report, indent=2))


if __name__ == '__main__': main()
