"""Repair the retained SDK real_cred probe without disabling request isolation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
MEMBER_SHA = '9c18e06cbe5f21ed5a9302f16b377eafd30cc12059a4c70d21f4709e2b2fce95'


def patch_snapshot(ir):
    match = re.search(r'^define [^\n]*@_ZN13kernel_module32get_task_struct_real_cred_offsetERj\([^\n]*\{\n.*?^}', ir, re.M | re.S)
    assert match, 'Pinned real_cred probe missing'
    # Replace only this public probe. Other task_struct probes and their cache
    # logic are retained. Its old three byte-wise reads observe different creds.
    body = '''define hidden i64 @_ZN13kernel_module32get_task_struct_real_cred_offsetERj(ptr %0) {
  %result = call i64 @maplesu_find_real_cred_offset(ptr %0)
  ret i64 %result
}'''
    return (ir[:match.start()] + body + ir[match.end():] +
            '\ndeclare hidden i64 @maplesu_find_real_cred_offset(ptr)\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'work') and out != ROOT / 'work'
    out.mkdir(parents=True, exist_ok=True)
    before = parse_ar(str(args.archive))
    member = before['members'][1]
    assert member['name'] == 'task_struct.o' and member['sha256'] == MEMBER_SHA
    data = args.archive.read_bytes()
    original = out / 'task_struct.original.bc'
    original.write_bytes(data[member['body_offset']:member['body_offset'] + member['size']])
    tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *arguments):
        result = subprocess.run([str(tool / (name + '.exe')), *map(str, arguments)],
                                capture_output=True, encoding='utf-8', errors='replace', timeout=120)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    target = '--target=aarch64-linux-android21'
    original_ir, patched_ir = out / 'task_struct.original.ll', out / 'task_struct.patched.ll'
    run('clang', target, '-S', '-emit-llvm', '-x', 'ir', original, '-o', original_ir)
    patched_ir.write_text(patch_snapshot(original_ir.read_text(encoding='utf-8')), encoding='utf-8')
    run('clang', target, '-Oz', '-fPIC', '-c', patched_ir, '-o', out / 'task_struct.ir.o')
    source = ROOT / 'runtime/ultra/authorization/credential_snapshot.cpp'
    run('clang++', target, '-std=c++17', '-Oz', '-fPIC', '-fno-stack-protector',
        '-fexceptions', '-fno-rtti', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
        '-Wno-packed-non-pod',
        '-isystem', ROOT / 'runtime/maplesu-sdk/include', '-c', source, '-o', out / 'snapshot.o')
    run('ld.lld', '-r', out / 'task_struct.ir.o', out / 'snapshot.o', '-o', out / 'task_struct.o')
    candidate = out / args.archive.name
    assert candidate != args.archive.resolve()
    candidate.write_bytes(data)
    run('llvm-ar', 'rD', candidate, out / 'task_struct.o')
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [m['ord'] for m in diff['changed']] == [1]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    report = dict(baselineArchiveSha256=before['file_sha256'], archiveSha256=after['file_sha256'],
                  memberDiff=diff, requestIsolationPreserved=True,
                  sources={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in (source, Path(__file__).resolve())})
    (out / 'credential-snapshot-repair.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS only SDK member 1 changed; request isolation retained')


if __name__ == '__main__':
    main()
