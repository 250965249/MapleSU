"""Rebuild only SDK member 81; retain archive order and duplicate member names."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_sdk_member_diff import parse_ar

parser = argparse.ArgumentParser()
parser.add_argument('--archive', type=Path, required=True)
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--ndk', type=Path, required=True)
parser.add_argument('--expect-member-sha256', default='3ddfcc783f4854d8c43a253938229c2cbe7b159b0d2a6ffb66bd4be5805b8a78')
parser.add_argument('--maplesu-display', action='store_true', help='Retain the 5.1.0 member display spelling')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
source = repo / 'runtime/ultra/authorization'
bc = source / 'sdk-module-su-redirect.bc'
assert hashlib.sha256(bc.read_bytes()).hexdigest() == '3ddfcc783f4854d8c43a253938229c2cbe7b159b0d2a6ffb66bd4be5805b8a78'
args.out.mkdir(parents=True, exist_ok=True)
tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

def run(name, *argv):
    subprocess.run([str(tool / (name + '.exe')), *map(str, argv)], check=True)

original = args.out / 'm081.original.ll'
run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', bc, '-o', original)
ir = original.read_text()
if args.maplesu_display:
    assert ir.count('ERR_MAPLESU_ENV_NOT_INSTALL') == 1
    ir = ir.replace('ERR_MAPLESU_ENV_NOT_INSTALL', 'ERR_MAPLESU_ENV_UNPREPARED')
# The old writer was the mapper's sole IR caller. It is now called from the
# replacement C++ TU, so retain its definition instead of dropping linkonce_odr.
mapper = re.search(r'define linkonce_odr hidden void @([^ (]*read_pkg_uids_from_packages_list[^ (]*)', ir)[1]
ir = ir.replace('define linkonce_odr hidden void @' + mapper + '(', 'define hidden void @' + mapper + '(')
writer = re.search(r'define internal fastcc noundef i64 @([^ (]*write_allowlist[^ (]*)', ir)[1]
start = ir.index('define internal fastcc noundef i64 @' + writer)
end = ir.index('\n}\n', start) + 3
ir = ir[:start] + f'''declare i64 @maplesu_write_su_allowlist(ptr, ptr, i1)
define internal fastcc i64 @{writer}(ptr %packages) {{
  %result = call i64 @maplesu_write_su_allowlist(ptr %packages, ptr null, i1 false)
  ret i64 %result
}}
''' + ir[end:]
add = re.search(r'define hidden noundef i64 @[^ (]*16add_su_allowlistEPKc\(.*?\n}', ir, re.S)
body, count = re.subn(
    r'invoke fastcc noundef i64 @' + re.escape(writer) + r'\(ptr noundef nonnull align 8 dereferenceable\(24\) %2\)',
    'invoke i64 @maplesu_write_su_allowlist(ptr %2, ptr %0, i1 false)', add[0])
assert count == 1
ir = ir[:add.start()] + body + ir[add.end():]
# These four SDK entrypoints are called after its root fork. C++ wrappers hold
# one file lock across the original load/update/persist body in both consumers.
for public, private in (
    ('get_su_allowlist', 'maplesu_sdk_get_su_allowlist'),
    ('add_su_allowlist', 'maplesu_sdk_add_su_allowlist'),
    ('remove_su_allowlist', 'maplesu_sdk_remove_su_allowlist'),
    ('clear_su_allowlist', 'maplesu_sdk_clear_su_allowlist'),
):
    symbol = re.search(r'define hidden noundef i64 @([^ (]*\d' + public + r'[^ (]*)\(', ir)[1]
    assert ir.count('@' + symbol + '(') == 1
    ir = ir.replace('@' + symbol + '(', '@' + private + '(')
patched = args.out / 'm081.patched.ll'
patched.write_text(ir)
ir_obj, cpp_obj = args.out / 'm081.ir.o', args.out / 'writer.o'
member = args.out / 'module_su_redirect.o'
run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', patched, '-o', ir_obj)
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
    '-fexceptions', '-Wall', '-Wextra', '-Werror', '-I', repo / 'runtime/maplesu-sdk/include',
    '-c', source / 'su_allowlist_writer.cpp', '-o', cpp_obj)
lock_obj = args.out / 'transaction.o'
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
    '-fexceptions', '-Wall', '-Wextra', '-Werror', '-I', repo / 'runtime/maplesu-sdk/include',
    '-c', source / 'su_auth_transaction.cpp', '-o', lock_obj)
context_obj = args.out / 'context.o'
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
    '-fexceptions', '-Wall', '-Wextra', '-Werror', '-I', repo / 'runtime/maplesu-sdk/include',
    '-c', source / 'su_exec_context.cpp', '-o', context_obj)
retention_obj = args.out / 'retention.o'
run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
    '-fexceptions', '-Wall', '-Wextra', '-Werror', '-I', repo / 'runtime/maplesu-sdk/include',
    '-c', source / 'su_retention_store.cpp', '-o', retention_obj)
run('ld.lld', '-r', ir_obj, cpp_obj, lock_obj, context_obj, retention_obj, '-o', member)

before = parse_ar(str(args.archive))
# Later SDKs append module-control and compatibility objects. Preserve those
# members too; the exact ordinal/name/hash and full post-build diff stay pinned.
assert len(before['members']) >= 255
assert before['members'][81]['name'] == member.name
assert before['members'][81]['sha256'] == args.expect_member_sha256
archive = args.out / 'libkernel_module_kit_static.a'
assert archive.resolve() != args.archive.resolve()
archive.write_bytes(args.archive.read_bytes())
run('llvm-ar', 'rD', archive, member)
run('llvm-ar', 'sD', archive)
after = parse_ar(str(archive))
assert len(after['members']) == len(before['members'])
changes = []
for old, new in zip(before['members'], after['members']):
    assert old['name'] == new['name']
    if old['sha256'] != new['sha256']:
        changes.append({'ordinal': old['ord'], 'name': old['name'], 'before': old['sha256'], 'after': new['sha256']})
assert [item['ordinal'] for item in changes] == [81]
metadata = {
    'archiveSha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
    'baselineArchiveSha256': hashlib.sha256(args.archive.read_bytes()).hexdigest(),
    'sourceSha256': hashlib.sha256((source / 'su_allowlist_writer.cpp').read_bytes()).hexdigest(),
    'transactionSha256': hashlib.sha256((source / 'su_auth_transaction.cpp').read_bytes()).hexdigest(),
    'executionSourceSha256': hashlib.sha256((source / 'su_exec_context.cpp').read_bytes()).hexdigest(),
    'retentionSourceSha256': hashlib.sha256((source / 'su_retention_store.cpp').read_bytes()).hexdigest(),
    'memberChanges': changes,
    'bootstrapMemberUnchanged': before['members'][52]['sha256'] == after['members'][52]['sha256'],
    'maplesuDisplay': args.maplesu_display,
}
(args.out / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
print(json.dumps(metadata, indent=2))
