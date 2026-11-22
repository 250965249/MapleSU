#!/usr/bin/env python3
"""Run two sequential full SDK builds in new directories and compare real products."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True


def identity(path):
    with Path(path).open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'size': Path(path).stat().st_size, 'sha256': digest}


def selection_files(root, selection):
    data = json.loads(selection.read_text(encoding='utf-8-sig'))
    if data.get('schema') != 'maplesu-sdk-source-selection/1' or not data.get('files'):
        raise ValueError('a nonempty current source selection is required')
    seen = set()
    for row in data['files']:
        path = (root / row['path']).resolve()
        if (not path.is_relative_to(root) or row['path'] != path.relative_to(root).as_posix()
                or path in seen or type(row.get('size')) is not int
                or identity(path) != {key: row[key] for key in ('size', 'sha256')}):
            raise ValueError('source selection mismatch: ' + row['path'])
        seen.add(path)
    return {'selection': identity(selection), 'files': data['files']}


def products(directory):
    """Include extensionless ELF helpers, nested kernel outputs and all object containers."""
    binaries, other = {}, {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink() or path.is_junction():
            raise ValueError('linked output is not a clean build product: ' + str(path))
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        with path.open('rb') as stream:
            magic = stream.read(8)
        compiled = magic.startswith((b'\x7fELF', b'BC\xc0\xde', b'\xde\xc0\x17\x0b', b'!<arch>\n'))
        selected = relative.startswith(('obj/', 'out/')) and path.suffix not in ('.json', '.d')
        (binaries if compiled or selected else other)[relative] = identity(path)
    return binaries, other


def differences(first, second):
    return [{'path': name, 'first': first.get(name), 'second': second.get(name)}
            for name in sorted(first.keys() | second.keys()) if first.get(name) != second.get(name)]


def validate_build(root, directory):
    root, directory = root.resolve(), directory.resolve()
    sys.path.insert(0, str(root / 'scripts'))
    from ar_archive import parse_ar
    from source_sdk_delivery import verify_build_provenance, verify_member_source_chain, verify_source_bootstrap

    report = json.loads((directory / 'report/build-report.json').read_text(encoding='utf-8'))
    required = {'check', 'manifest', 'payloads', 'compile', 'compose', 'pack', 'assets', 'gate', 'report'}
    gate = report.get('gate')
    if (report.get('failure') or not required.issubset(report.get('stages_run', []))
            or report.get('continuation') or not report.get('source_kernel')
            or report['pack']['members'] != 260
            or not isinstance(gate, dict) or gate.get('exit_code') != 0):
        raise ValueError('not a full clean SDK/kernel build: ' + str(directory))
    compiled = report.get('compile')
    if (not isinstance(compiled, dict) or compiled.get('failures') != []
            or not isinstance(compiled.get('rows'), list) or not compiled['rows']
            or any(not isinstance(row, dict) or row.get('status') != 'ok' for row in compiled['rows'])):
        raise ValueError('incomplete compile receipt: ' + str(directory))
    proof = report.get('provenance')
    if (not isinstance(proof, dict) or proof.get('schema') != 'maplesu-sdk-source-provenance/2'
            or proof.get('closure_complete') is not True or proof.get('incomplete_reasons') != []
            or not isinstance(proof.get('translation_units'), list) or not proof['translation_units']):
        raise ValueError('incomplete provenance receipt: ' + str(directory))
    if not report['source_selection']['files']:
        raise ValueError('build did not consume its source selection')
    programs = report['payloads']['programs']
    if ({row['asset'] for row in programs} != {'autorun_bootstrap.bin', 'su.bin', 'resetprop_file.bin', 'webui_loader.bin'}
            or len(programs) != 4 or any(row['status'] != 'built' for row in programs)
            or not report['source_backend'] or not report['source_helper']
            or not report['final_archive_stability']['passed']):
        raise ValueError('incomplete source helper/backend/payload pairing')

    def bound(path, size=None, digest=None, exact=None):
        path = (root / path).resolve()
        if not path.is_relative_to(directory) or (exact is not None and path != exact.resolve()):
            raise ValueError('product is outside this clean build: ' + str(path))
        actual = identity(path)
        if size is not None and actual != {'size': size, 'sha256': digest}:
            raise ValueError('clean product identity mismatch: ' + str(path))
        return path

    def recorded(row):
        return bound(row['path'], row['size'], row['sha256'])

    archive = bound(report['pack']['archive'], report['pack']['bytes'], report['pack']['sha256'],
                    directory / 'out/libkernel_module_kit_static.a')
    bound(report['bootstrap']['pack']['archive'])
    helper = report['source_helper']
    source_helper = bound(helper['out'], helper['surface']['bytes'], helper['surface']['sha256'])
    runtime_helper = report['assets']['helper']
    helper_file = bound(runtime_helper['out'], runtime_helper['bytes'], runtime_helper['sha256'],
                        directory / 'out/helper/autorun_bootstrap')
    if identity(source_helper) != identity(helper_file):
        raise ValueError('source/runtime helper mismatch')
    backend_file = recorded(report['source_backend']['file'])
    for row in programs:
        payload = bound(directory / 'out/assets' / row['asset'], row['bytes'], row['sha256'])
        if row['asset'] == 'autorun_bootstrap.bin' and identity(payload) != identity(source_helper):
            raise ValueError('source/payload helper mismatch')
    for unit in report['provenance']['translation_units']:
        for step in (unit, *unit.get('compile_steps', [])):
            bound(step['object'], step['bytes'], step['sha256'])
    for row in report['compose']['rows']:
        bound(row['object'], row['bytes'], row['sha256'])
    stability = report['final_archive_stability']
    recorded(stability['archive'])
    for name in ('helper', 'backend'):
        recorded(stability[name]['file'])
        recorded(stability[name]['trace'])
    kernel = report['source_kernel']
    bound(kernel['bundle'])
    kernel_build = json.loads(recorded(kernel['kernelBuildReceipt']).read_text(encoding='utf-8'))
    recorded(kernel['kernelContractReceipt'])
    families = {'android12-5.10', 'android13-5.15', 'android14-6.1', 'android15-6.6', 'android16-6.12', 'android17-6.18'}
    if ({row['kernel'] for row in kernel_build['results']} != families
            or len(kernel_build['results']) != len(families) or not kernel_build['sourcesUnchanged']
            or any(row['exitCode'] for row in kernel_build['results'])):
        raise ValueError('incomplete six-family kernel build')
    for family in families:
        for name in ('maplesu_policy_view.payload.o', 'policy-view.so'):
            bound(directory / 'kernel' / family / name)
    inputs = verify_build_provenance(report, root, directory)
    entries = [json.loads(line) for line in (directory / 'manifest.jsonl').read_text(encoding='utf-8').splitlines()
               if line.strip() and not line.lstrip().startswith('#')]
    verify_member_source_chain(entries, report, parse_ar(str(archive))['members'], root, directory)
    verify_source_bootstrap(report, archive, helper_file, backend_file, root, directory)
    # Compare outside-build inputs, including toolchain/headers, rather than path-normalizing their hashes.
    outside = {str((root / row['path']).resolve()): {key: row[key] for key in ('size', 'sha256')}
               for row in inputs if not (root / row['path']).resolve().is_relative_to(directory)}
    return report, outside


def run(args):
    root, work, selection = args.root.resolve(), args.work_dir.resolve(), args.source_selection.resolve()
    if not selection.is_relative_to(root):
        raise ValueError('source selection must be inside the selected source tree')
    selected = selection_files(root, selection)
    # Creation is exclusive: never reuse, clean, or delete an earlier build or failed attempt.
    work.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'maplesu-sdk-clean-reproducibility/1', 'sourceSelection': selected,
              'runs': [], 'passed': False, 'runtimeAcceptance': False,
              'fullMaintainableSourceAcceptance': False,
              'freeBytesAtStart': shutil.disk_usage(work).free,
              'scope': 'two complete SDK/kernel/helper/backend/payload builds; APK/device acceptance is separate'}
    try:
        if result['freeBytesAtStart'] < args.minimum_free_bytes:
            raise ValueError('insufficient space for the declared two-build peak')
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(args.source_date_epoch))
        products_by_run, inputs_by_run, other_by_run = [], [], []
        for number in (1, 2):
            if selection_files(root, selection) != selected:
                raise ValueError('source selection changed before clean build ' + str(number))
            directory = work / ('clean-' + str(number))
            directory.mkdir(exist_ok=False)
            argv = [sys.executable, str(root / 'runtime/maplesu-sdk/sdk/build.py'), '--all',
                    '--build-dir', str(directory), '--source-selection', str(selection),
                    '--jobs', str(args.jobs)]
            for key in ('kernel_source_618', 'kernel_objtree_618', 'kernel_toolchain_618', 'ndk', 'cmake', 'gate_allow'):
                value = getattr(args, key)
                if value is not None:
                    argv += ['--' + key.replace('_', '-'), str(value.resolve())]
            row = {'directory': str(directory), 'emptyBeforeStart': not any(directory.iterdir()), 'argv': argv}
            result['runs'].append(row)
            with (work / ('clean-' + str(number) + '.log')).open('w', encoding='utf-8') as log:
                completed = subprocess.run(argv, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            row['exitCode'] = completed.returncode
            if completed.returncode:
                raise ValueError('clean build failed: ' + str(number))
            if selection_files(root, selection) != selected:
                raise ValueError('source selection changed during clean build ' + str(number))
            report, outside = validate_build(root, directory)
            if report['source_selection']['files'] != selected['files']:
                raise ValueError('build consumed a different source selection')
            row['report'] = identity(directory / 'report/build-report.json')
            binaries, other = products(directory)
            row['products'] = binaries
            row['outsideBuildInputs'] = outside
            products_by_run.append(binaries)
            inputs_by_run.append(outside)
            other_by_run.append(other)
            row['transitionInputs'] = [{'idx': item['idx'], 'sources': item['sources']}
                                      for item in report['compile']['rows']
                                      if any(Path(path).suffix.lower() in ('.bc', '.ll', '.o', '.a') for path in item['sources'])]
        result['productDifferences'] = differences(*products_by_run)
        result['inputDifferences'] = differences(*inputs_by_run)
        result['metadataDifferencesRequiringExplanation'] = differences(*other_by_run)
        # Metadata differences remain visible and require review; no binary difference is waived.
        result['binaryProductsIdentical'] = not result['productDifferences']
        result['inputsIdentical'] = not result['inputDifferences']
        result['passed'] = (bool(products_by_run[0]) and result['binaryProductsIdentical']
                            and result['inputsIdentical'] and not result['metadataDifferencesRequiringExplanation'])
    except Exception as exc:
        result['failure'] = str(exc)
        raise
    finally:
        (work / 'REPRODUCIBILITY.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--work-dir', required=True, type=Path)
    parser.add_argument('--source-selection', required=True, type=Path)
    for name in ('kernel-source-618', 'kernel-objtree-618', 'kernel-toolchain-618'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('ndk', 'cmake', 'gate-allow'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--source-date-epoch', type=int, default=1700000000)
    parser.add_argument('--minimum-free-bytes', required=True, type=int,
                        help='measured peak for both retained builds plus headroom')
    args = parser.parse_args(argv)
    if args.minimum_free_bytes <= 0 or args.jobs <= 0:
        parser.error('minimum-free-bytes and jobs must be positive')
    try:
        result = run(args)
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print('PASS' if result['passed'] else 'REVIEW_REQUIRED')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
