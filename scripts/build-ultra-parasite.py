"""Append the source-built parasite extension without changing any existing SDK member."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from verify_sdk_member_diff import parse_ar


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

    def run(name, *options):
        subprocess.run([str(tool / (name + '.exe')), *map(str, options)], check=True)

    common = ['--target=aarch64-linux-android21', '-Oz', '-fPIC', '-Wall', '-Wextra', '-Werror']
    harden = ['-Wl,--no-undefined', '-Wl,-z,relro,-z,now', '-Wl,-z,max-page-size=16384']
    app = out / 'libmaplesu_parasite.so'
    su = out / 'libmaplesu_su_env.so'
    run('clang++', *common, '-std=c++20', '-shared', '-static-libstdc++',
        root / 'runtime/src/parasite/parasite_loader.cpp', '-llog',
        '-Wl,-soname,libmaplesu_parasite.so', *harden, '-o', app)
    run('clang', *common, '-shared', root / 'runtime/ultra/parasite/su_env_loader.c',
        '-Wl,-soname,libmaplesu_su_env.so', *harden, '-o', su)
    text = '#pragma once\n'
    for name, path in [('app', app), ('su', su)]:
        data = path.read_bytes()
        text += f'static const unsigned char maplesu_{name}_payload[] = {{\n'
        text += '\n'.join(','.join(str(b) for b in data[i:i + 32]) + ',' for i in range(0, len(data), 32))
        text += '\n};\n'
    (out / 'parasite_payloads.h').write_text(text)
    obj = out / 'maplesu_parasite_sdk.o'
    run('clang++', *common, '-std=c++17', '-fexceptions', '-ffunction-sections', '-fdata-sections',
        '-I', root / 'runtime/maplesu-sdk/include', '-I', out, '-c',
        root / 'runtime/ultra/parasite/parasite_sdk.cpp', '-o', obj)
    original = parse_ar(str(args.archive))
    assert 'maplesu_parasite_sdk.o' not in {m['name'] for m in original['members']}, 'Extension already present'
    archive = out / 'libkernel_module_kit_static.a'
    assert archive != args.archive.resolve()
    shutil.copy2(args.archive, archive)
    run('llvm-ar', 'rD', archive, obj)
    run('llvm-ar', 'sD', archive)
    current = parse_ar(str(archive))
    assert [(m['name'], m['sha256']) for m in current['members'][:-1]] == [
        (m['name'], m['sha256']) for m in original['members']]
    assert current['members'][-1]['name'] == obj.name
    sources = ['runtime/ultra/parasite/parasite_sdk.cpp', 'runtime/ultra/parasite/su_env_loader.c',
               'runtime/src/parasite/parasite_loader.cpp', 'runtime/maplesu-sdk/include/maplesu_parasite.h']
    meta = {
        'sdkVersion': '5.1.0', 'baselineArchiveSha256': sha(args.archive),
        'archiveSha256': sha(archive), 'existingMembersUnchanged': len(original['members']),
        'addedMember': obj.name, 'addedMemberSha256': sha(obj),
        'appPayloadSha256': sha(app), 'suPayloadSha256': sha(su),
        'sources': {p: sha(root / p) for p in sources}, 'deviceVerification': False,
    }
    (out / 'build.json').write_text(json.dumps(meta, indent=2) + '\n')
    print(json.dumps(meta, indent=2))


if __name__ == '__main__':
    main()
