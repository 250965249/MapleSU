"""Replay the real boot lifecycle with the tested recovery overlay, without recompiling it."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--overlay-receipt', type=Path, required=True)
    parser.add_argument('--image-receipt', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('boot_lifecycle',
        ROOT / 'scripts/tests/test-ultra-boot-research-lifecycle.py')
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    overlay = json.loads(args.overlay_receipt.read_text(encoding='utf-8-sig'))
    assert overlay['exitCode'] == 0 and overlay['sourcesUnchanged'] and overlay['runtimeUnchanged']
    image = None
    if args.image_receipt:
        image = json.loads(args.image_receipt.read_text(encoding='utf-8-sig'))
        assert image['exitCode'] == 0 and image['sourcesUnchanged']
    replacements = {record['path']: record for record in image['sources']} if image else {}
    base_receipt = Path(overlay['runtimeReceipt']['path'])
    assert lifecycle.identity(base_receipt) == overlay['runtimeReceipt']
    base = json.loads(base_receipt.read_text(encoding='utf-8-sig'))
    runtime = base['runtime']
    assert runtime == overlay['runtime']
    for record in overlay['sources']:
        record = replacements.get(record['path'], record)
        assert lifecycle.identity(Path(record['path'])) == record, 'source changed: ' + record['path']
    for record in replacements.values():
        assert lifecycle.identity(Path(record['path'])) == record
    for record in [runtime['java'], runtime['jar'], *runtime['dependencies'], *runtime['buildDependencies']]:
        assert lifecycle.identity(Path(record['path'])) == record
    test_jar = Path(overlay['testJar']['path'])
    assert lifecycle.identity(test_jar) == overlay['testJar']
    class_receipt = image or overlay
    classes = Path(class_receipt['imageClassesDirectory'])
    if not image:
        javac = next(command for command in overlay['commands'] if command['label'] == 'javac')
        assert str(classes) == javac['argv'][javac['argv'].index('-d') + 1]
    args.out.mkdir(parents=True, exist_ok=False)
    drivers = []
    for runner in (Path(__file__).resolve(), Path(lifecycle.__file__).resolve()):
        target = args.out / 'source' / runner.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(runner.read_bytes())
        drivers.append(lifecycle.identity(runner))
    product = args.out / 'tested-product-overlay.jar'
    with zipfile.ZipFile(runtime['jar']['path']) as original:
        entries = {name: original.read(name) for name in original.namelist() if not name.endswith('/')}
    with zipfile.ZipFile(test_jar) as current:
        for name in current.namelist():
            if name.endswith('/') or name == 'META-INF/MANIFEST.MF':
                continue
            target = 'META-INF/maplesu_recovery_overlay.kotlin_module' if name.endswith('.kotlin_module') else name
            entries[target] = current.read(name)
    java_classes = []
    for path in sorted(classes.rglob('*.class')):
        entries[path.relative_to(classes).as_posix()] = path.read_bytes()
        java_classes.append(lifecycle.identity(path))
    assert java_classes and java_classes == class_receipt['imageClasses'], 'tested Java classes changed'
    consumer_rerun = None
    if image:
        for record in overlay['testDependencies']:
            assert lifecycle.identity(Path(record['path'])) == record
        command = next(item['argv'][:] for item in overlay['commands'] if item['label'] == 'tests')
        position = command.index('-cp') + 1
        paths = command[position].split(os.pathsep)
        assert paths.count(overlay['imageClassesDirectory']) == 1
        paths[paths.index(overlay['imageClassesDirectory'])] = str(classes)
        command[position] = os.pathsep.join(paths)
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        (args.out / 'consumer.stdout.log').write_bytes(result.stdout)
        (args.out / 'consumer.stderr.log').write_bytes(result.stderr)
        consumer_rerun = {'argv': command, 'exitCode': result.returncode}
        (args.out / 'CONSUMER-RERUN.json').write_text(json.dumps(consumer_rerun, indent=2) + '\n', encoding='utf-8')
        assert result.returncode == 0, 'consumers failed against the replacement image classes'
    with zipfile.ZipFile(product, 'w', zipfile.ZIP_DEFLATED) as merged:
        for name, data in sorted(entries.items()):
            merged.writestr(name, data)
    overrides = {record['path']: record for record in overlay['sources']}
    overrides.update(replacements)
    sources = [overrides.pop(record['path'], record) for record in base['sources']]
    sources.extend(overrides.values())
    runtime = dict(runtime, jar=lifecycle.identity(product))
    effective = args.out / 'effective-runtime.json'
    effective.write_text(json.dumps({'sources': sources, 'runtime': runtime,
        'baseRuntimeReceipt': lifecycle.identity(base_receipt),
        'overlayReceipt': lifecycle.identity(args.overlay_receipt),
        'imageReceipt': lifecycle.identity(args.image_receipt) if args.image_receipt else None,
        'consumerRerun': consumer_rerun,
        'javaClasses': java_classes, 'drivers': drivers,
        'runner': lifecycle.identity(Path(__file__))}, indent=2) + '\n', encoding='utf-8')
    # The original driver still owns its cases, readback assertions and bounded cleanup.
    sys.argv = ['test-ultra-boot-research-lifecycle.py', '--runtime-receipt', str(effective),
        '--out', str(args.out / 'lifecycle'), '--scratch', str(args.scratch)]
    return lifecycle.main()


if __name__ == '__main__':
    raise SystemExit(main())
