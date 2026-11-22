#!/usr/bin/env python3
"""Real helper module worker/metadata/state and original ABI host fixtures."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import struct
import hashlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
SDK = ROOT / 'runtime/maplesu-sdk/sdk'
META_SOURCE = SDK / json.loads((SDK / 'manifest/0054_maplesu_module_elf_meta.o.json').read_text(encoding='utf-8-sig'))['sources'][0]
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    commands = []

    def run(name, argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True, encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(done.stdout + done.stderr, encoding='utf-8')
        commands.append({'name': name, 'argv': [str(a) for a in argv], 'exit': done.returncode})
        if done.returncode:
            raise RuntimeError(name + ': ' + (done.stderr or done.stdout)[-5000:])
        return done

    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,exec,size=64m', '--tmpfs', '/data:rw,exec,size=32m',
              '--mount', f'type=bind,source={ROOT},target=/repo,readonly',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work',
              '--entrypoint', '/bin/sh', IMAGE]
    def docker_run(name, argv):
        return run(name, [*docker, '-c', 'exec "$@"', 'sh', *argv])
    prefix = '/repo/runtime/maplesu-sdk/'
    base = ['g++', '-std=c++20', '-O1', '-g', '-ffunction-sections', '-fdata-sections',
            '-I' + prefix + 'sdk/tools/tests/module_state/include', '-I' + prefix + 'include',
            '-I' + prefix + 'sdk/include', '-I' + prefix + 'sdk/src/maplesu/module',
            '-I' + prefix + 'sdk/src/helper', '-I/work']
    meta_source = (ROOT / 'runtime/maplesu-sdk/include/maplesu/compat/native_module_abi.h').read_text(encoding='utf-8')
    def tag(stem, end=False):
        name = {'___MOD_NAME_TAG': 'NAME', '___MOD_ID32_TAG': 'ID',
                '___MOD_VERSION_TAG': 'VERSION', '____MAPLESU_MODULE_MIN_SUPPORT_SDK_VERSION_TAG': 'MINIMUM_SDK'}[stem]
        macro = 'MAPLESU_MODULE_' + name + '_TAG_' + ('END' if end else 'BEGIN')
        return re.search(r'#define ' + macro + r' "([^"]+)"', meta_source).group(1)
    module_code = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include "maplesu/compat/native_module_abi.h"
__attribute__((destructor)) static void unloaded() { FILE* f = fopen("/tmp/helper-events", "a"); if(f){fputs("unload\n",f);fclose(f);} }
#ifndef OMIT_ENTRY
extern "C" int MAPLESU_MODULE_ENTRY_NAME(const char*, const char*) MAPLESU_MODULE_ENTRY_ASM;
extern "C" int MAPLESU_MODULE_ENTRY_NAME(const char* key, const char* dir) {
    FILE* f = fopen("/tmp/helper-events", "a"); if(f){fprintf(f,"entry:%s:%s\n",key,dir);fclose(f);}
    const char* action = getenv("FIXTURE_ACTION");
    if(action && !strcmp(action,"exit")) _exit(7);
    if(action && !strcmp(action,"signal")) raise(SIGTERM);
    if(action && !strcmp(action,"partial")) {
        int partial = 0;
        for(int fd=3;fd<64;++fd) if((fcntl(fd,F_GETFL)&O_ACCMODE)==O_WRONLY) write(fd,&partial,4);
        _exit(0);
    }
    return ENTRY_RESULT;
}
#endif
'''
    ids = ['0123456789abcdefghijklmnopqrstuv', '1123456789abcdefghijklmnopqrstuv',
           '2123456789abcdefghijklmnopqrstuv']
    for number, module_id in enumerate(ids):
        metadata = ''.join(tag(stem) + value + tag(stem, True) for stem, value in
            [('___MOD_NAME_TAG', 'fixture'), ('___MOD_ID32_TAG', module_id),
             ('___MOD_VERSION_TAG', '1'), ('____MAPLESU_MODULE_MIN_SUPPORT_SDK_VERSION_TAG', '5.2.0')])
        source = out / (module_id + '.cpp')
        source.write_text('__attribute__((used)) static const char metadata[] = ' + json.dumps(metadata) + ';\n' + module_code,
                          encoding='utf-8')
        docker_run('module-' + str(number), ['g++', '-shared', '-fPIC', '-O1', '-I' + prefix + 'include',
                   '-DENTRY_RESULT=' + ('42' if number == 1 else '0'), *(['-DOMIT_ENTRY'] if number == 2 else []),
                   source.name, '-o', module_id + '.so'])
    (out / '3123456789abcdefghijklmnopqrstuv.so').write_bytes(b'not an ELF')
    test_dir = prefix + 'sdk/tools/tests/helper_native/'
    docker_run('runtime-compile', [*base, test_dir + 'test_runtime.cpp',
        prefix + 'sdk/src/maplesu/module/runtime.cpp', prefix + 'sdk/src/maplesu/module/state.cpp',
        '/repo/' + META_SOURCE.relative_to(ROOT).as_posix(), '-Wl,--wrap=setxattr,--gc-sections', '-ldl', '-o', 'runtime-test'])
    runtime = docker_run('runtime-test', ['./runtime-test'])
    docker_run('abi-compile', [*base, test_dir + 'test_abi.cpp',
        '/repo/runtime/ultra/boot/su-isolation/helper_su_backend.cpp', '-Wl,--gc-sections', '-o', 'abi-test'])
    abi = docker_run('abi-test', ['./abi-test'])
    (out / 'helper_sdk_version.h').write_text('#pragma once\n#define MAPLESU_HELPER_SDK_VERSION maplesu::sdk::MapleSUSdkVersion{5,2,0}\n', encoding='utf-8')
    docker_run('bootstrap-compile', [*base, test_dir + 'test_bootstrap.cpp',
        prefix + 'sdk/src/helper/bootstrap_runtime.cpp', prefix + 'sdk/src/helper/helper_text.cpp', '-include', 'cstdint',
        '-Wl,--gc-sections', '-o', 'bootstrap-test'])
    bootstrap = docker_run('bootstrap-test', ['./bootstrap-test'])
    docker_run('session-writer-compile', ['gcc', '-std=c11', '-D_GNU_SOURCE',
        '/repo/runtime/ultra/boot/bootstrap_finish.c', '-c', '-o', 'session-writer.o'])
    docker_run('session-compile', [*base, test_dir + 'test_session.cpp',
        prefix + 'sdk/src/helper/helper_session.cpp', prefix + 'sdk/src/helper/helper_text.cpp',
        'session-writer.o', '-Wl,--gc-sections', '-o', 'session-test'])
    session = docker_run('session-test', ['./session-test'])
    (out / 'loader-backend.c').write_text('''#include <stdio.h>
__attribute__((constructor)) static void constructed(void){FILE*f=fopen("/tmp/loader-constructor","w");if(f)fclose(f);}
int maplesu_environment_policy_start(const char*key){FILE*f=fopen("/tmp/loader-entry","w");if(f)fclose(f);return !key;}
''', encoding='utf-8')
    docker_run('loader-backend-compile', ['gcc', '-shared', '-fPIC', '-Wl,--build-id=sha1', 'loader-backend.c', '-o', 'loader-backend.so'])
    backend = (out / 'loader-backend.so').read_bytes()
    phoff, = struct.unpack_from('<Q', backend, 32)
    phentsize, phnum = struct.unpack_from('<HH', backend, 54)
    note_offset = next(struct.unpack_from('<Q', backend, phoff + i * phentsize + 8)[0]
                       for i in range(phnum) if struct.unpack_from('<I', backend, phoff + i * phentsize)[0] == 4)
    namesz, descsz, _ = struct.unpack_from('<III', backend, note_offset)
    note_size = 12 + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
    note = backend[note_offset:note_offset + note_size]
    pairing = out / 'pairing'
    pairing.mkdir(exist_ok=True)
    (pairing / 'environment_backend_identity.h').write_text('#pragma once\n#define MAPLESU_POLICY_BACKEND_FILE "fixture.' + hashlib.sha256(backend).hexdigest() + '.so"\n'
        + f'#define MAPLESU_POLICY_BACKEND_SIZE {len(backend)}\n#define MAPLESU_POLICY_BACKEND_NOTE_OFFSET {note_offset}\n'
        + 'static const unsigned char maplesu_policy_backend_note[] = {' + ','.join(map(str, note)) + '};\n', encoding='utf-8')
    docker_run('loader-compile', ['gcc', '-O1', '-I/work/pairing', '-DMAPLESU_POLICY_DIRECTORY="/tmp/helper-policy"',
        test_dir + 'test_loader.c', '/repo/runtime/ultra/policy/environment_loader.c', '-ldl', '-o', 'loader-test'])
    loader = [docker_run('loader-' + mode, ['./loader-test', mode]).stdout for mode in ['missing', 'size', 'note', 'valid']]
    result = {'commands': commands, 'runtime': runtime.stdout, 'abi': abi.stdout, 'bootstrap': bootstrap.stdout,
              'session': session.stdout, 'loader': loader,
              'boundaries': ['root acquisition/enumeration are fixture boundaries',
                             'module disable gate is injected; real gate source compiled in Android helper',
                             'SELinux setxattr is injected; state bytes/path/metadata/DSO/fork/pipe/wait are real',
                             'ABI PatchDoExecve method is instrumented; full SDK layout compiled by NDK helper'],
              'device': False}
    (out / 'RESULT.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(runtime.stdout + abi.stdout + bootstrap.stdout + session.stdout + ''.join(loader))


if __name__ == '__main__':
    main()
