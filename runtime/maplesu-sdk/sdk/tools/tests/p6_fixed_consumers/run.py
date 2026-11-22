#!/usr/bin/env python3
"""Run the actual fixed-business consumers with explicit kernel/process boundaries."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
SDK = ROOT / 'runtime/maplesu-sdk/sdk'
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'
RELS = ['src/bypass/module_bypass_mtk_mkp.cpp', 'src/bypass/module_bypass_oplus_secure_guard.cpp',
        'src/bypass/module_bypass_oplus_inte.cpp', 'src/module/idx070/module_root.cpp',
        'src/module/module_selinux.cpp']

def function(source, signature):
    matches = list(re.finditer('^' + re.escape(signature) + r' \{.*?^\}', source, re.M | re.S))
    if len(matches) != 1:
        raise ValueError((signature, len(matches)))
    return matches[0].group(0) + '\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source_root = args.source_root.resolve()
    sources = [(source_root / 'runtime/maplesu-sdk/sdk' / rel).read_text(encoding='utf-8') for rel in RELS]
    inputs = [source_root / 'runtime/maplesu-sdk/sdk' / rel for rel in RELS]
    inputs += [HERE / 'fixture.h', HERE / 'cases.cpp', Path(__file__).resolve(),
               SDK / 'include/maplesu_early_fixed_private.h', SDK / 'include/private_module_selinux.h',
               SDK / 'include/maplesu_request_private.h', SDK.parent / 'include/module_err_def.h',
               ROOT / 'runtime/ultra/authorization/request_protocol.h']
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    header = (HERE / 'fixture.h').read_text(encoding='utf-8')
    private = (SDK / 'include/maplesu_early_fixed_private.h').read_text(encoding='utf-8')
    adapter = function(private, 'inline KModErr maplesu_request_helper_fixed_business(uint32_t operation, uint32_t mode,\n    uint32_t exploit, uint64_t value, RequestEarlyFixedResult& output)')
    private_selinux = (SDK / 'include/private_module_selinux.h').read_text(encoding='utf-8')
    selinux_adapter = function(private_selinux, 'inline KModErr maplesu_request_helper_selinux(EarlySelinuxOperation operation, uint32_t mode,\n    uint32_t exploit, uint64_t value, RequestEarlySelinuxResult& result)')
    generated = header.replace('// BUSINESS_ADAPTER', adapter).replace('// SELINUX_ADAPTER', selinux_adapter)
    for source, namespace in zip(sources[:3], ['mtk', 'guard', 'inte']):
        generated += '\nnamespace ' + namespace + ' {\n'
        generated += function(source, 'KModErr init()') + '}\n'
    generated += '\nnamespace root_consumer {\n'
    generated += function(sources[3], 'KModErr init_anti_detect_root_env(const std::vector<std::string>& hide_names, bool only_print)')
    generated += '}\n'
    generated += '\nnamespace selinux_consumer {\n'
    # Run the complete init with real C++ filesystem/stream operations on private
    # fixture paths; process, policy and native publication APIs are explicit mocks.
    generated += function(sources[4], 'KModErr read_selinux_kernel_status(selinux_kernel_status& out_status)')
    generated += function(sources[4], 'KModErr write_selinux_kernel_status_sequence(uint32_t sequence)')
    generated += function(sources[4], 'KModErr enable_selinux_status_hooks(const SelinuxHookSwitch& switch_info)')
    generated += function(sources[4], 'KModErr init(maplesu::sdk::InstallMode install_mode, maplesu::sdk::ExploitMethod exploit_method)')
    generated += '}\n' + (HERE / 'cases.cpp').read_text(encoding='utf-8')
    (out / 'consumers.cpp').write_text(generated, encoding='utf-8')
    commands = []
    passed = False
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,exec,size=32m',
              '--mount', f'type=bind,source={ROOT},target=/repo,readonly',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work',
              '--entrypoint', '/bin/sh', IMAGE]
    try:
        for name, argv in [('compile', ['g++', '-std=c++20', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                                      '-Wno-unused-function', '-fsanitize=address,undefined',
                                      '-fno-omit-frame-pointer', '-no-pie',
                                      '-I/repo/runtime/maplesu-sdk/include', '/work/consumers.cpp', '-o', '/work/consumers']),
                           ('cases', ['/work/consumers'])]:
            result = subprocess.run([*docker, '-c', 'exec "$@"', 'sh', *argv], cwd=ROOT,
                                    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=90)
            (out / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
            commands.append({'name': name, 'argv': argv, 'exitCode': result.returncode})
            print(name, result.returncode, (result.stdout + result.stderr)[-9000:], flush=True)
            if result.returncode:
                raise RuntimeError(name)
        passed = True
    finally:
        stable = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == digest for p, digest in before.items())
        (out / 'RESULT.json').write_text(json.dumps(dict(passed=passed and stable,
            sourceInputsStable=stable, commands=commands, inputs=before,
            scope='Actual complete OEM/root/SELinux consumer functions; ASan/UBSan Linux execution; '
                  'kernel service transport, native publications, policy, process and Android APIs are explicit fixture boundaries. '
                  'No formal SDK link or device claim.'), indent=2), encoding='utf-8')

if __name__ == '__main__':
    main()
