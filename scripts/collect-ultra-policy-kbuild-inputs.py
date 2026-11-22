"""Record retained Kbuild dependencies in the matching offline compiler images."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def file_record(path: Path) -> dict:
    data = path.read_bytes()
    resolved = path.resolve()
    try:
        recorded = resolved.relative_to(ROOT).as_posix()
    except ValueError:
        recorded = resolved.as_posix()
    return dict(path=recorded, size=len(data),
                sha256=hashlib.sha256(data).hexdigest())


def inside(kernel: str) -> dict:
    directory = Path('/output') / kernel
    cwd = directory if kernel == 'android17-6.18' else Path('/opt/ddk/kdir') / kernel
    paths, wildcards, commands = set(), set(), []
    for command in sorted(directory.rglob('.*.cmd')):
        text = command.read_text()
        paths.add(command)
        commands.append(str(command))
        wildcards.update(re.findall(r'\$\(wildcard (include/config/[^)]+)\)', text))
        for line in text.splitlines():
            entry = line.strip().removesuffix('\\').strip()
            if entry.startswith('source_') and ':=' in entry:
                entry = entry.split(':=', 1)[1].strip()
            if not entry or any(char in entry for char in (' ', ':', '$', '=')):
                continue
            path = Path(entry)
            paths.add(path if path.is_absolute() else cwd / path)
    for pattern in ('*.c', '*.h', '*.S', '*.mod'):
        paths.update(directory.glob(pattern))
    paths.add(directory / 'Makefile')
    values = {}
    for line in (directory / 'target.config').read_text().splitlines():
        if line.startswith('CONFIG_'):
            key, value = line.split('=', 1)
            values[key] = value
    inputs, missing = [], []
    for path in sorted(paths):
        if not path.is_file():
            missing.append(str(path))
            continue
        data = path.read_bytes()
        item = dict(path=str(path), resolvedPath=str(path.resolve()), size=len(data),
                    sha256=hashlib.sha256(data).hexdigest())
        try:
            item['normalizedTextSha256'] = hashlib.sha256(path.read_text().encode()).hexdigest()
        except UnicodeDecodeError:
            pass
        inputs.append(item)
    configs = []
    for name in sorted(wildcards):
        path = cwd / name
        suffix = name.removeprefix('include/config/').removesuffix('.h').replace('/', '_').upper()
        symbol = suffix if suffix.startswith('CONFIG_') else 'CONFIG_' + suffix
        item = dict(expression='$(wildcard ' + name + ')', path=str(path), exists=path.is_file(),
                    symbol=symbol, capturedValue=values.get(symbol, 'n'))
        if path.is_file():
            data = path.read_bytes()
            item.update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
        configs.append(item)
    compiler = []
    if kernel == 'android17-6.18':
        for path in sorted(Path('/compiler').rglob('*')):
            if path.is_file():
                data = path.read_bytes()
                compiler.append(dict(path=str(path), resolvedPath=str(path.resolve()), size=len(data),
                                     sha256=hashlib.sha256(data).hexdigest()))
    return dict(schema='maplesu-kbuild-dependency-snapshot/1', kernel=kernel,
                workingDirectory=str(cwd), commands=commands, inputs=inputs,
                configurationWildcards=configs, compilerFiles=compiler, missingRequiredInputs=missing,
                scope='Retained actual Kbuild .cmd source/header dependencies; config wildcard existence and captured values recorded separately')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directories', nargs='+', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source-618', type=Path)
    parser.add_argument('--objtree-618', type=Path)
    parser.add_argument('--toolchain-618', type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    local = {file_record(Path(__file__))['path']: file_record(Path(__file__))}
    prepared = []

    def remember(path: Path, expected: dict | None = None) -> dict:
        item = file_record(path)
        if expected and any(item[key] != expected[key] for key in ('size', 'sha256')):
            raise ValueError('Input changed while collecting: ' + str(path))
        local[item['path']] = item
        return item

    for directory in (args.source_618, args.objtree_618, args.toolchain_618):
        if directory is None:
            continue
        index = directory / 'preparation-inputs.json'
        if not index.is_file():
            continue
        data = json.loads(index.read_text())
        prepared.append(remember(index))
        for item in data['inputs']:
            remember(ROOT / item['path'], item)
    containers, invocations = [], []
    for directory in args.directories:
        directory = directory.resolve()
        kernel = directory.name
        if not re.fullmatch(r'android\d+-\d+\.\d+', kernel):
            raise ValueError('Unknown kernel directory: ' + str(directory))
        image = 'ghcr.io/ylarod/ddk-min:' + ('android16-6.12' if kernel == 'android17-6.18' else kernel) + '-20260828'
        metadata = json.loads(subprocess.check_output(['docker', 'image', 'inspect', image], text=True))[0]
        mounts = [(ROOT, '/source'), (directory.parent, '/output')]
        if kernel == 'android17-6.18':
            for path, target in ((args.source_618, '/kernel'), (args.objtree_618, '/kernel-build'),
                                 (args.toolchain_618, '/compiler')):
                if path is None or not path.is_dir():
                    raise ValueError('6.18 collection needs prepared source, object tree and compiler directories')
                mounts.append((path.resolve(), target))
        command = ['docker', 'create', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges']
        for path, target in mounts:
            command.extend(['--mount', f'type=bind,source={path},target={target},readonly'])
        command.extend([image, 'python3', '/source/scripts/' + Path(__file__).name, '--inside', kernel])
        container = subprocess.check_output(command, text=True).strip()
        try:
            result = subprocess.run(['docker', 'start', '--attach', container], capture_output=True,
                                    text=True, encoding='utf-8', errors='replace', timeout=180)
            exit_code = int(subprocess.check_output(['docker', 'inspect', '--format', '{{.State.ExitCode}}', container], text=True))
        finally:
            subprocess.run(['docker', 'rm', '-f', container], check=True, capture_output=True)
        if result.returncode or exit_code:
            raise RuntimeError('Dependency collection failed: ' + (result.stderr or result.stdout))
        snapshot = json.loads(result.stdout)
        snapshot.update(containerId=container, image=image, imageId=metadata['Id'], repoDigests=metadata.get('RepoDigests', []))
        path = args.output.with_name(args.output.stem + '.' + kernel + '.json')
        path.write_text(json.dumps(snapshot, indent=2) + '\n')
        item = remember(path)
        containers.append(dict(kernel=kernel, receipt=item, containerId=container,
                               imageId=metadata['Id'], repoDigests=metadata.get('RepoDigests', [])))
        invocations.append(dict(argv=command, containerId=container, exitCode=exit_code))
        if snapshot['missingRequiredInputs']:
            raise ValueError('Missing retained Kbuild dependencies: ' + ', '.join(snapshot['missingRequiredInputs']))
        # Container-internal DDK files remain bound to their immutable image;
        # bind-mounted inputs are also checked as repository file records.
        for row in snapshot['inputs'] + snapshot['compilerFiles']:
            for host, target in sorted(mounts, key=lambda item: len(item[1]), reverse=True):
                if row['path'].startswith(target + '/'):
                    remember(host / row['path'][len(target) + 1:], row)
                    break
        print(kernel, len(snapshot['inputs']), 'dependencies;', len(snapshot['configurationWildcards']), 'config wildcards', flush=True)
    report = dict(schema='maplesu-kernel-kbuild-inputs/1', recordedAt=datetime.now(timezone.utc).isoformat(),
                  inputs=[local[key] for key in sorted(local)], preparationReceipts=prepared,
                  containers=containers, commands=invocations,
                  scope='Actual .cmd dependency closure from the same retained build; immutable DDK files and bind-mounted source/compiler inputs recorded')
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    if sys.argv[1:2] == ['--inside']:
        print(json.dumps(inside(sys.argv[2]), indent=2))
    else:
        main()
