"""Replay the one real non-BTF case over the tested saved-ID walker overlay."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence'


def identity(path):
    path = Path(path)
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--overlay-receipt', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tested = json.loads(args.overlay_receipt.read_bytes())
    assert tested['exitCode'] == 0 and tested['sourcesUnchanged'] and tested['frozenInputsUnchanged']
    image_receipt = BASE / 'owned-recovery-union-r1/green/OVERLAY.json'
    image = json.loads(image_receipt.read_bytes())
    previous_receipt = BASE / 'static-scs-entry-r1/case04-final/receipt.json'
    previous = json.loads(previous_receipt.read_bytes())
    effective_receipt = BASE / 'embedded-real-lifecycle-r2/effective-runtime.json'
    effective = json.loads(effective_receipt.read_bytes())
    input_path = ROOT / 'Boot_Research/boot.img'
    source_inputs = tested['sources']
    dependencies = [tested['overlay'], tested['recipeJar'], previous['harness'], *tested['frozenInputs']]
    for row in dependencies + source_inputs:
        assert identity(row['path']) == row, 'Replay input changed: ' + row['path']
    image_classes = image['imageClasses']
    for row in image_classes:
        assert identity(row['path']) == row, 'Frozen image class changed: ' + row['path']
    java = effective['runtime']['java']['path']
    scratch = out / 'scratch'
    classpath = os.pathsep.join([tested['overlay']['path'], tested['recipeJar']['path'],
        image['imageClassesDirectory'], previous['harness']['path'], effective['runtime']['jar']['path'],
        effective['runtime']['classpath']])
    argv = [java, '-Xmx768m', '-cp', classpath,
        'dev.maplesu.manager.ultrakernel.BootResearchLifecycleMainKt', str(input_path), str(scratch),
        str(out), str(ROOT / 'manager/src/main/assets')]
    receipt = dict(schema='maplesu-saved-id-frame-case04/1', input=identity(input_path),
        overlayReceipt=identity(args.overlay_receipt), imageReceipt=identity(image_receipt),
        effectiveReceipt=identity(effective_receipt), previousReceipt=identity(previous_receipt),
        dependencies=dependencies, imageClasses=image_classes, sources=source_inputs,
        argv=argv, runner=identity(__file__), deviceOperations=False, partitionWrites=False, SDKOrAPKBuild=False)
    result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True)
    for stream in ['stdout', 'stderr']:
        (out / ('replay.' + stream + '.log')).write_bytes(getattr(result, stream))
    receipt.update(exitCode=result.returncode, inputAfter=identity(input_path),
        sourcesUnchanged=all(identity(r['path']) == r for r in source_inputs),
        dependenciesUnchanged=all(identity(r['path']) == r for r in dependencies + image_classes))
    receipt['inputUnchanged'] = receipt['input'] == receipt['inputAfter']
    result_path = out / 'result.json'
    if result_path.is_file():
        receipt['result'] = json.loads(result_path.read_bytes())
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({key: receipt[key] for key in ['exitCode', 'inputUnchanged', 'sourcesUnchanged',
        'dependenciesUnchanged', 'result'] if key in receipt}, indent=2))
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
