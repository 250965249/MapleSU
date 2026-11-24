import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path('D:/Maple_Workflow/MapleSU')
HERE = Path(__file__).resolve().parent
OUT = HERE / 'candidate'
SOURCE = HERE / 'source'
OUT.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_sdk_member_diff import parse_ar
from elftools.elf.elffile import ELFFile
TOOLS = Path('D:/Maple_Env/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/windows-x86_64/bin')

def run(tool, *args):
    subprocess.run([str(TOOLS / (tool + '.exe')), *map(str, args)], check=True)

def sha(data): return hashlib.sha256(data).hexdigest()

archive = ROOT / 'runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a'
original = archive.read_bytes()
assert sha(original) == 'f015f15ceb91e81f09c0a3b70c4a1c09042c2926ad91380499692a3733c2b4c5'
before = parse_ar(str(archive))
flags = ['--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
         '-fexceptions', '-fno-rtti', '-Wall', '-Wextra', '-Werror',
         '-I', ROOT / 'runtime/maplesu-sdk/include', '-I', SOURCE]
objects = []
for name in ('su_allowlist_writer', 'su_auth_transaction', 'su_exec_context', 'su_retention_store', 'su_uid_copies'):
    output = OUT / (name + '.o')
    run('clang++', *flags, '-c', SOURCE / (name + '.cpp'), '-o', output)
    objects.append(output)
member81 = OUT / before['members'][81]['name']
run('ld.lld', '-r', HERE / 'baseline-rebuild/m081.ir.o', *objects, '-o', member81)
member83 = OUT / before['members'][83]['name']
run('clang++', *flags, '-w', '-emit-llvm', '-c', SOURCE / 'patch_do_execve.cpp', '-o', member83)
row = before['members'][48]
member48 = bytearray(original[row['body_offset']:row['body_offset'] + row['size']])
elf = ELFFile(io.BytesIO(member48))
text_offset = elf.get_section_by_name('.text')['sh_offset']
for relative in (0x4d0, 0x9b8):
    offset = text_offset + relative
    assert member48[offset:offset + 4] == struct.pack('<I', 0x52800001 | (0o711 << 5))
    member48[offset:offset + 4] = struct.pack('<I', 0x52800001 | (0o700 << 5))
member48_path = OUT / row['name']
member48_path.write_bytes(member48)
candidate = OUT / archive.name
candidate.write_bytes(original)
run('llvm-ar', 'rD', candidate, member48_path, member81, member83)
run('llvm-ar', 'sD', candidate)
after = parse_ar(str(candidate))
assert len(before['members']) == len(after['members'])
changed = []
for old, new in zip(before['members'], after['members']):
    assert old['name'] == new['name'] and old['ord'] == new['ord']
    if old['sha256'] != new['sha256']:
        changed.append({'ordinal': old['ord'], 'name': old['name'], 'baselineSha256': old['sha256'],
                        'candidateSha256': new['sha256']})
assert [r['ordinal'] for r in changed] == [48, 81, 83]
report = {'baselineArchiveSha256': sha(original), 'archiveSha256': sha(candidate.read_bytes()),
          'memberChanges': changed, 'sources': {p.name: sha(p.read_bytes()) for p in SOURCE.iterdir() if p.is_file()},
          'generatorSha256': sha(Path(__file__).read_bytes()),
          'moduleErrHeaderSha256': sha((ROOT / 'runtime/maplesu-sdk/include/module_err_def.h').read_bytes()),
          'deviceAcceptance': False, 'candidateOnly': True,
          'contract': {'canonicalSu': 'u-00000000/su root:root 0700',
                       'canonicalDirectory': 'root:root 0700', 'ownerRoot': 'root:root 0711',
                       'uidDirectory': 'root:uid 0710', 'uidSu': 'uid:uid 0700',
                       'duringGrantMutation': 'root:uid 0700', 'newCredentialHooks': False}}
(OUT / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))

