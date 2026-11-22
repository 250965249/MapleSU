"""Probe consumed native layouts using the BTF in the supplied raw ARM64 Image."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/specgen'))
from specgen.kallsyms import decode


def record(path):
    data = path.read_bytes()
    return dict(path=path.resolve().relative_to(ROOT).as_posix(), size=len(data),
                sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--compiler-image', default='ghcr.io/ylarod/ddk-min:android15-6.6-20260828')
    args = parser.parse_args()
    image_path = args.image.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    image_record = record(image_path)
    if image_record['sha256'] != args.image_sha256:
        raise ValueError('Image SHA256 mismatch')
    source_paths = [Path(__file__).resolve(), ROOT / 'scripts/probe-kernel-layout-description.cpp',
                    ROOT / 'runtime/ultra/policy/kernel_layout.cpp', ROOT / 'runtime/ultra/policy/kernel_layout.h',
                    ROOT / 'tools/specgen/specgen/kallsyms.py']
    sources = [record(path) for path in source_paths]
    image = image_path.read_bytes()
    symbols = decode(image)

    def unique(name):
        offsets = set(symbols.all_offsets(name))
        if len(offsets) != 1:
            raise ValueError('Missing/ambiguous Image symbol: ' + name)
        return offsets.pop()

    start, stop = unique('__start_BTF'), unique('__stop_BTF')
    if not 0 <= start < stop <= len(image):
        raise ValueError('Invalid Image BTF symbol span')
    btf = image[start:stop]
    magic, version, flags, header, type_offset, type_size, string_offset, string_size = struct.unpack_from('<HBBIIIII', btf)
    end = max(header + type_offset + type_size, header + string_offset + string_size)
    if (magic, version, flags) != (0xeb9f, 1, 0) or header < 24 or end > len(btf):
        raise ValueError('Invalid extracted BTF header/span')
    btf_path = output / 'vmlinux.btf'
    btf_path.write_bytes(btf)
    inspection = subprocess.run(['docker', 'image', 'inspect', args.compiler_image],
                                capture_output=True, text=True, encoding='utf-8', timeout=30, check=True)
    compiler = json.loads(inspection.stdout)[0]
    commands = []

    def run(name, command):
        cid = output / (name + '.cid')
        if cid.exists():
            cid.unlink()
        argv = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--cidfile', str(cid),
                '--mount', f'type=bind,source={ROOT},target=/source,readonly',
                '--mount', f'type=bind,source={output},target=/output', compiler['Id']] + command
        result = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', timeout=90)
        stdout, stderr = output / (name + '.stdout.txt'), output / (name + '.stderr.txt')
        stdout.write_text(result.stdout, encoding='utf-8')
        stderr.write_text(result.stderr, encoding='utf-8')
        commands.append(dict(argv=argv, exitCode=result.returncode, containerId=cid.read_text().strip(),
                             stdout=record(stdout), stderr=record(stderr)))
        if result.returncode:
            raise RuntimeError(f'{name} failed ({result.returncode}): {result.stderr}')
        return result.stdout

    compiler_version = run('compiler-version', ['c++', '--version'])
    run('compile', ['c++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
        '-I/source/runtime/ultra/policy', '/source/runtime/ultra/policy/kernel_layout.cpp',
        '/source/scripts/probe-kernel-layout-description.cpp', '-o', '/output/probe'])
    description = json.loads(run('probe', ['/output/probe', '/output/vmlinux.btf']))
    if len(description['fields']) != 6:
        raise ValueError('Probe field count mismatch')
    if sources != [record(path) for path in source_paths] or image_record != record(image_path):
        raise ValueError('Probe source/Image changed')
    evidence = dict(schema='maplesu-native-layout-probe/1', recordedAt=datetime.now(timezone.utc).isoformat(),
        image=image_record, btf=record(btf_path), btfExtraction=dict(
            source='Image kallsyms __start_BTF/__stop_BTF; offsets relative to _text',
            startSymbol='__start_BTF', stopSymbol='__stop_BTF', startOffset=start, stopOffset=stop,
            textBase=hex(symbols.text_base), headerPayloadBytes=end, trailingBytes=len(btf) - end,
            kallsymsLayout=symbols.layout),
        compiler=dict(requestedImage=args.compiler_image, imageId=compiler['Id'],
            repoDigests=compiler.get('RepoDigests', []), version=compiler_version),
        commands=commands, inputs=sources, executable=record(output / 'probe'),
        description=description, sourcesUnchanged=True, imageUnchanged=True,
        scope='Offline native KernelLayoutDescription result for the supplied Image; no device execution')
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(image=image_record, btf=record(btf_path), fields=description['fields']), indent=2))


if __name__ == '__main__':
    main()
