#!/usr/bin/env python3
"""Exercise real description writer/list TUs; emit logs and a manifest-built m055.

The explicit output directory holds all compiled objects. No SDK archive,
manifest, official artifact or device is written by this runner.
"""
import argparse
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SDK = HERE.parents[2]
sys.path.insert(0, str(SDK / 'tools'))
import sdk_common as S

IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
CASES = [('plain', n) for n in [0, 1, 64, 4095, 4096, 4097, 8192, 65536]]
CASES += [('nul-file', 4097), ('nul-file', 8192), ('null', 0)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'ndk').mkdir(exist_ok=True)
    commands = []

    def run(name, argv):
        done = subprocess.run([str(a) for a in argv], capture_output=True, text=True,
                              encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(done.stdout + done.stderr, encoding='utf-8')
        commands.append({'name': name, 'argv': [str(a) for a in argv], 'exit': done.returncode})
        return done

    docker = ['docker.exe', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=128m', '--tmpfs', '/data:rw,size=32m,mode=0777',
              '--mount', f'type=bind,source={SDK},target=/sdk,readonly',
              '--mount', f'type=bind,source={SDK.parent / "include"},target=/upstream-include,readonly',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work',
              '--entrypoint', '/bin/sh', IMAGE]
    cpp = ['/sdk/tools/tests/module_desc_bounds/fixture.cpp', '/sdk/tools/tests/module_state/boundaries.cpp',
           '/sdk/src/maplesu/module/list.cpp', '/sdk/src/maplesu/module/state.cpp',
           '/sdk/src/module_base/module_base_change_status.cpp']
    host_flags = ['-std=c++20', '-O1', '-g', '-fno-omit-frame-pointer', '-ffunction-sections',
                  '-fdata-sections', '-Wno-packed', '-DFOLDER_HEAD_ROOT_KEY_LEN=16',
                  '-I/sdk/tools/tests/module_state/include', '-I/sdk/tools/tests/module_state',
                  '-I/sdk/src/maplesu/module', '-I/upstream-include', '-I/sdk/include']
    results = []
    for variant, flags in [('fortify', ['-D_FORTIFY_SOURCE=2']),
                           ('asan', ['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=0', '-fsanitize=address'])]:
        compiled = run(variant + '-compile', [*docker, '-c', 'exec "$@"', 'sh', 'g++', *host_flags,
                       *flags, *cpp, '-Wl,--gc-sections,--wrap=chmod,--wrap=setxattr', '-o', variant + '-test'])
        if compiled.returncode:
            raise RuntimeError(compiled.stderr[-3000:])
        # Each case is a separate process: one intentional old failure must not hide later boundaries.
        script = '\n'.join(f'ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 ./{variant}-test {mode} {length}'
                           f' > {variant}-{mode}-{length}.log 2>&1\nprintf "%s\\n" "$?" > {variant}-{mode}-{length}.exit'
                           for mode, length in CASES)
        launched = run(variant + '-cases', [*docker, '-c', script])
        if launched.returncode:
            raise RuntimeError(launched.stderr[-3000:])
        for mode, length in CASES:
            name = f'{variant}-{mode}-{length}'
            log = (out / (name + '.log')).read_text(encoding='utf-8')
            rows = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
            results.append({'variant': variant, 'mode': mode, 'length': length,
                            'exit': int((out / (name + '.exit')).read_text()), 'rows': rows,
                            'fortifyOverflow': 'buffer overflow detected' in log,
                            'asanOverflow': 'AddressSanitizer: stack-buffer-overflow' in log,
                            'asanDiagnostic': 'ERROR: AddressSanitizer:' in log})

    entry = json.loads((SDK / 'manifest/0055_maplesu_module_list.o.json').read_text(encoding='utf-8-sig'))
    assert entry['sources'] == ['src/maplesu/module/list.cpp', 'src/maplesu/module/state.cpp']
    assert int(entry.get('recipe', {}).get('stages', 1)) == 1
    bin_dir = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR
    run('ndk/version', [bin_dir / 'clang++.exe', '--version'])
    flags = S.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
    flags += ['-Wall', '-Wextra', '-I', str(SDK.parent / 'include'), '-I', str(SDK / 'include')]

    def compile_one(source):
        target = out / 'ndk' / (Path(source).stem + '.o')
        done = run('ndk/' + Path(source).stem, [bin_dir / 'clang++.exe', *flags, '-c', SDK / source, '-o', target])
        if done.returncode:
            raise RuntimeError(done.stderr[-3000:])
        return target

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        objects = list(pool.map(compile_one, entry['sources']))
    composed = out / 'ndk/maplesu_module_list.composed.o'
    linked = run('ndk/compose', [bin_dir / 'ld.lld.exe', '-r', '-o', composed, *objects])
    if linked.returncode:
        raise RuntimeError(linked.stderr[-3000:])
    run('ndk/nm', [bin_dir / 'llvm-nm.exe', '-P', composed])
    inputs = [SDK / source for source in entry['sources']]
    inputs += [SDK / 'src/module_base/module_base_change_status.cpp', SDK.parent / 'include/maplesu_sdk/maplesu_module.h',
               SDK / 'tools/tests/module_state/boundaries.cpp', SDK / 'tools/tests/module_state/fixture_config.h',
               SDK / 'tools/tests/module_state/include/kernel_module_kit_umbrella.h', SDK / 'tools/sdk_common.py',
               SDK / 'src/maplesu/module/operations.h', SDK / 'src/maplesu/module/types.h',
               SDK / 'src/maplesu/module/state.h', SDK / 'src/maplesu/compat/module_list_legacy_abi.h',
               SDK / 'src/maplesu/compat/module_carrier_conversion.h',
               SDK / 'manifest/0055_maplesu_module_list.o.json', HERE / 'fixture.cpp', HERE / 'run.py']
    passed = all(row['exit'] == 0 for row in results)
    receipt = {'passed': passed, 'deviceAccess': False, 'productionOutputsWritten': False,
               'source': 'actual production list/state/description writer TUs; external boundaries in README.md',
               'image': IMAGE, 'results': results, 'manifestEntry': entry,
               'ndkObjects': [{'path': str(path), 'bytes': path.stat().st_size, 'sha256': S.sha256_file(path)}
                              for path in [*objects, composed]],
               'inputs': [{'path': str(path), 'sha256': S.sha256_file(path)} for path in inputs], 'commands': commands}
    (out / 'RESULTS.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': passed, 'cases': len(results), 'failures': sum(row['exit'] != 0 for row in results),
                      'out': str(out)}))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
