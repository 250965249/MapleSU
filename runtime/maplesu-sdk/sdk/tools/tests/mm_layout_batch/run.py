"""One batch for real complete mm getters; kernel/BTF/VM edges are explicit seams."""
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
NAMES = ['resolve_mm_btf_offset', 'get_mm_struct_mm_mt_offset', 'get_mm_struct_mmap_offset',
         'get_mm_struct_pgd_offset', 'get_mm_struct_map_count_offset', 'get_mm_struct_total_vm_offset',
         'probe_rss_stat_window', 'resolve_mm_btf_pair', 'get_mm_struct_arg_offset', 'get_mm_struct_env_offset']
FILE_NAMES = ['resolve_file_btf_offset', 'get_file_f_path_offset', 'get_file_f_inode_offset',
              'get_file_f_op_offset', 'get_file_f_flags_offset', 'get_file_f_mode_offset',
              'get_file_f_pos_offset', 'get_file_f_cred_offset', 'get_file_private_data_offset',
              'get_file_f_mapping_offset']
TASK_NAMES = ['resolve_task_btf_offset', 'get_task_struct_stack_offset', 'get_task_struct_mm_offset',
              'get_task_struct_pid_offset', 'get_task_struct_tgid_offset']


def identity(path):
    data = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', action='store_true')
    parser.add_argument('--subject', choices=['mm', 'file', 'task'], default='mm')
    args = parser.parse_args()
    out = args.out.resolve(); out.mkdir(parents=True, exist_ok=False)
    source_name, fixture_name, manifest_name, names = {
        'mm': ('mm_struct.cpp', 'fixture.cpp', '0002_mm_struct.o.json', NAMES),
        'file': ('file.cpp', 'file_fixture.cpp', '0007_file.o.json', FILE_NAMES),
        'task': ('task_struct.cpp', 'task_fixture.cpp', '0001_task_struct.o.json', TASK_NAMES),
    }[args.subject]
    source = SDK / 'src/kernel_offsets' / source_name
    fixture = HERE / fixture_name
    paths = [source, fixture, Path(__file__).resolve(),
             SDK / 'include/maplesu_kernel_layout_private.h', SDK.parent / 'include/module_err_def.h']
    before = [identity(path) for path in paths]
    for path in paths: (out / path.name).write_bytes(path.read_bytes())
    text = source.read_text(encoding='utf-8-sig')
    parts = []
    for name in names:
        matches = list(re.finditer(r'^(?:static )?KModErr ' + name + r'\([^;]*?\)\s*\{.*?^\}', text, re.M | re.S))
        if len(matches) != 1: raise RuntimeError(f'{name}: expected one complete production body, got {len(matches)}')
        match = matches[0]
        line = text.count('\n', 0, match.start()) + 1
        parts.append(f'#line {line} "{source.as_posix()}"\n' + match.group(0) + '\n')
    (out / 'extracted.cpp').write_text('namespace kernel_module {\n' + '\n'.join(parts) + '}\n', encoding='utf-8')
    docker = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=32m', '--mount', f'type=bind,source={out},target=/work', '-w', '/work', IMAGE]
    commands = [('compile', [*docker, 'g++', '-std=c++20', '-O1', '-g', '-pthread', '-I/work',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-no-pie',
                            fixture.name, '-o', 'mm-layout-test']),
                ('test', [*docker, './mm-layout-test'])]
    manifest = compiler = None
    if args.ndk:
        sys.dont_write_bytecode = True; sys.path.insert(0, str(SDK / 'tools'))
        import sdk_common as common
        manifest_path = SDK / 'manifest' / manifest_name
        entry = json.loads(manifest_path.read_text(encoding='utf-8-sig'))
        manifest = identity(manifest_path)
        compiler_path = common.DEFAULT_NDK / common.TOOLCHAIN_SUBDIR / 'clang++.exe'
        compiler = identity(compiler_path)
        paths += [manifest_path, SDK / 'tools/sdk_common.py']
        before += [identity(path) for path in paths[-2:]]
        flags = common.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
        commands.append(('ndk', list(map(str, [compiler_path, *flags, '-I', SDK.parent / 'include',
            '-I', SDK / 'include', '-MD', '-MF', out / 'ndk.d', '-MT', 'mm-object',
            '-c', source, '-o', out / 'mm-struct.o']))))
    rows = []
    for name, argv in commands:
        done = subprocess.run(argv, cwd=SDK, capture_output=True, text=True, encoding='utf-8', errors='replace')
        output = done.stdout + done.stderr
        (out / (name + '.log')).write_text(output, encoding='utf-8')
        rows.append({'name': name, 'argv': argv, 'exit': done.returncode,
                     'sanitizerDiagnostic': 'runtime error:' in output or 'ERROR: AddressSanitizer:' in output})
        print(output, end='')
        if done.returncode: break
    dependencies = []
    if (out / 'ndk.d').exists():
        text = (out / 'ndk.d').read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1]
        for token in re.findall(r'(?:\\.|[^\s])+', text):
            path = Path(token.replace('\\ ', ' ').replace('\\:', ':').replace('\\#', '#'))
            dependencies.append(identity(path if path.is_absolute() else SDK / path))
    stable = before == [identity(path) for path in paths]
    passed = stable and len(rows) == len(commands) and all(row['exit'] == 0 and not row['sanitizerDiagnostic'] for row in rows)
    receipt = {'passed': passed, 'sourcesUnchanged': stable, 'sources': before, 'commands': rows,
               'manifest': manifest, 'compiler': compiler, 'dependencies': dependencies, 'completeBodies': names,
               'subject': args.subject,
               'scope': 'Complete current getter bodies; BTF API, kernel I/O/assembler, VM maps or file descriptors are explicit seams; actual full Android TU compiled separately. No real kernel, shared parser test, SDK link or device proof.',
               'deviceOperations': False, 'formalArtifactsChanged': False}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
