"""Exercise generated recovery probes with small boot containers and captured production source."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'docs/dual-mode/impl/_work/2026-11-16/evidence'


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--image-classes', type=Path)
    args = parser.parse_args()
    args.out = args.out.resolve()
    if args.image_classes:
        args.image_classes = args.image_classes.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    def check(record):
        actual = identity(record['path'])
        if actual != record:
            raise ValueError('Frozen input changed: ' + record['path'])
        return actual

    manifest_path = EVIDENCE / 'owned-removal-current-core-r1/green-final/runtime-manifest.json'
    manifest = json.loads(manifest_path.read_bytes())
    walker = json.loads((EVIDENCE / 'saved-id-frame-r1/final/receipt.json').read_bytes())
    # The old manifest also lists historical source identities. Those source files
    # may now be edited by another owner; the retained runtime classes remain fixed.
    runtime_rows = [row for row in manifest['inputs']
                    if Path(row['path']).suffix.lower() in {'.class', '.jar', '.exe', '.zip'}]
    frozen_inputs = {row['path']: check(row) for row in runtime_rows}
    if args.image_classes:
        image_receipt = json.loads((args.image_classes.parent / 'receipt.json').read_bytes())
        for row in image_receipt['classes']:
            check(row)
        for row in image_receipt['sources']:
            check(row)
    compile_argv = next(row['argv'] for row in walker['commands'] if 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler' in row['argv'])
    run = manifest['runs'][0]['argv']
    old_cp = run[run.index('-cp') + 1]
    classes = args.out / 'classes'
    classes.mkdir()
    layers = [str(classes.resolve())]
    if args.image_classes:
        layers.append(str(args.image_classes.resolve()))
    classpath = os.pathsep.join([*layers, old_cp])
    source_paths = [ROOT / 'manager/src/main/java/dev/maplesu/manager/ultrakernel/UltraKernelOriginalRecovery.kt',
                    ROOT / 'manager/src/main/java/dev/maplesu/manager/ultrakernel/UltraKernelBuilder.kt',
                    ROOT / 'manager/src/test/java/dev/maplesu/manager/ultrakernel/UltraKernelRecoveryInvalidAvbTest.kt']
    sources, copies = [], []
    for path in source_paths:
        copy = args.out / 'source' / path.relative_to(ROOT)
        copy.parent.mkdir(parents=True, exist_ok=True)
        copy.write_bytes(path.read_bytes())
        sources.append(identity(path))
        copies.append(copy)
    frozen_runner = args.out / 'source/scripts/tests' / Path(__file__).name
    frozen_runner.parent.mkdir(parents=True, exist_ok=True)
    frozen_runner.write_bytes(Path(__file__).read_bytes())
    image_inputs = [] if not args.image_classes else [identity(p) for p in sorted(args.image_classes.rglob('*.class'))]
    receipt = dict(schema='maplesu-recovery-invalid-avb/1', sources=sources, runner=identity(__file__),
                   runtimeManifest=identity(manifest_path), frozenInputs=list(frozen_inputs.values()),
                   imageClasses=image_inputs, commands=[],
                   SDKOrAPKBuild=False, deviceOperations=False)

    def execute(name, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, cwd=ROOT / 'manager', capture_output=True)
        for stream in ['stdout', 'stderr']:
            (args.out / (name + '.' + stream + '.log')).write_bytes(getattr(result, stream))
        receipt['commands'].append(dict(name=name, argv=argv, exitCode=result.returncode))
        print(result.stdout.decode('utf-8', 'replace'), end='')
        print(result.stderr.decode('utf-8', 'replace'), end='')
        return result.returncode

    runtime_jar = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence/embedded-real-lifecycle-r2/tested-product-overlay.jar'
    code = execute('compile', [compile_argv[0], '-Xmx512m', '-cp', compile_argv[compile_argv.index('-cp') + 1],
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '17',
        '-Xfriend-paths=' + str(runtime_jar), '-classpath', classpath, '-d', classes, *copies])
    if not code:
        code = execute('tests', [run[0], '-Xmx256m', '-cp', classpath, 'org.junit.runner.JUnitCore',
            'dev.maplesu.manager.ultrakernel.UltraKernelRecoveryInvalidAvbTest'])
    receipt.update(exitCode=code, frozenInputsUnchanged=all(identity(row['path']) == row for row in frozen_inputs.values()),
                   sourcesUnchanged=all(identity(row['path']) == row for row in sources),
                   classes=[identity(p) for p in sorted(classes.rglob('*.class'))],
                   imageInputsUnchanged=all(identity(row['path']) == row for row in image_inputs))
    overlay = args.out / 'tested-recovery-overlay.jar'
    with zipfile.ZipFile(overlay, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(classes.rglob('*.class')):
            archive.write(path, path.relative_to(classes).as_posix())
    receipt['overlay'] = identity(overlay)
    (args.out / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
