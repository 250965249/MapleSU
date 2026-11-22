"""Compile only the saved-ID walker and tests over the frozen P2 product runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence'


def identity(path):
    path = Path(path)
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--regression', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    effective_path = BASE / 'embedded-real-lifecycle-r2/effective-runtime.json'
    recipe_path = BASE / 'static-scs-entry-r1/final/receipt.json'
    effective = json.loads(effective_path.read_bytes())
    recipe = json.loads(recipe_path.read_bytes())
    runtime = effective['runtime']
    image_path = BASE / 'owned-recovery-union-r1/green/OVERLAY.json'
    image = json.loads(image_path.read_bytes())
    recipe_jar = BASE / 'static-scs-entry-r1/final/tests.jar'
    assert identity(recipe_jar)['sha256'] == recipe['testJar']['sha256']
    replacements = [row for row in runtime['dependencies'] if not Path(row['path']).is_file() and
        'MapleSU-specgen-product' in row['path'] and Path(row['path']).name.startswith('image-core-')]
    frozen = [runtime['jar'], *[row for row in runtime['dependencies'] if row not in replacements], *runtime['buildDependencies'],
              *recipe['testDependencies'], recipe['runtime']['java']]
    frozen += image['imageClasses']
    for row in frozen:
        assert identity(row['path']) == row, 'Frozen input changed: ' + row['path']
    classes = out / 'classes'
    classes.mkdir()
    runtime_jar = runtime['jar']['path']
    runtime_cp = [image['imageClassesDirectory'] if entry in {row['path'] for row in replacements} else entry
        for entry in runtime['classpath'].split(os.pathsep)]
    classpath = os.pathsep.join([str(classes), str(recipe_jar), image['imageClassesDirectory'], runtime_jar,
        *runtime_cp, *[row['path'] for row in recipe['testDependencies']]])
    source = ROOT / 'manager/src/main/java/dev/maplesu/manager/ultrakernel/UltraKernelShellcode.kt'
    suites = ['UltraKernelSavedIdFrameTest']
    if args.regression:
        suites += ['UltraKernelSavedIdDataflowTest', 'UltraKernelStructDataflowTest', 'UltraKernelShellcodeTest']
    sources = [source, *[ROOT / 'manager/src/test/java/dev/maplesu/manager/ultrakernel' / (name + '.kt')
        for name in suites]]
    source_records, copies = [], []
    for path in sources:
        target = out / 'source' / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
        source_records.append(identity(path))
        copies.append(target)
    fixture_records = []
    for name in ['case04-saved-id-frame', 'android12-5.10-saved-id']:
        for path in sorted((ROOT / 'manager/src/test/resources/ultrakernel' / name).glob('*')):
            target = out / 'source' / path.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            fixture_records.append(identity(path))
    compiler = next(row['path'] for row in runtime['buildDependencies'] if 'kotlin-compiler-embeddable' in row['path'])
    coroutines = next(row['path'] for row in runtime['buildDependencies'] if 'kotlinx-coroutines-core-jvm' in row['path'])
    compiler_cp = os.pathsep.join([compiler, *runtime['classpath'].split(os.pathsep)[:2], coroutines])
    java = recipe['runtime']['java']['path']
    receipt = dict(schema='maplesu-saved-id-frame/1', sources=source_records, fixtures=fixture_records,
        runtimeReceipt=identity(effective_path), recipeReceipt=identity(recipe_path), recipeJar=identity(recipe_jar),
        imageOverlay=identity(image_path), imageClassesDirectory=image['imageClassesDirectory'],
        replacedEphemeralDependencies=replacements,
        frozenInputs=frozen, runner=identity(__file__), commands=[], deviceOperations=False,
        partitionWrites=False, SDKOrAPKBuild=False)

    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), cwd=ROOT / 'manager', stdin=subprocess.DEVNULL,
                                capture_output=True)
        for stream in ['stdout', 'stderr']:
            (out / (label + '.' + stream + '.log')).write_bytes(getattr(result, stream))
        receipt['commands'].append(dict(label=label, argv=list(map(str, argv)), exitCode=result.returncode))
        print(result.stdout.decode('utf-8', 'replace'), end='')
        print(result.stderr.decode('utf-8', 'replace'), end='')
        return result.returncode

    code = run('compile', [java, '-Xmx768m', '-cp', compiler_cp,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '17',
        '-Xfriend-paths=' + ','.join([runtime_jar, str(recipe_jar)]), '-classpath', classpath,
        '-d', classes, *copies])
    if not code:
        code = run('tests', [java, '-Xmx768m', '-cp', classpath, 'org.junit.runner.JUnitCore',
            *['dev.maplesu.manager.ultrakernel.' + name for name in suites]])
    jar = out / 'tested-walker-overlay.jar'
    with zipfile.ZipFile(jar, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(classes.rglob('*')):
            if path.is_file():
                archive.write(path, path.relative_to(classes).as_posix())
    receipt.update(exitCode=code, sourcesUnchanged=all(identity(r['path']) == r for r in source_records),
        fixturesUnchanged=all(identity(r['path']) == r for r in fixture_records),
        frozenInputsUnchanged=all(identity(r['path']) == r for r in frozen),
        classes=[identity(path) for path in sorted(classes.rglob('*.class'))], overlay=identity(jar))
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
