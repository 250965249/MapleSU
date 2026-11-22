"""Run current permanent-removal logic with the frozen image recovery consumers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def identity(path):
    path = Path(path)
    return dict(path=str(path), bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--service', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    consumer_path = Path('C:/Temp/MapleSU-P2-embedded-recovery-r1/final/receipt.json')
    overlay_path = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence/owned-recovery-union-r1/green/OVERLAY.json'
    mode_path = Path('C:/Temp/MapleSU-P2-mode-source-record-r1/green/receipt.json')
    effective_path = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence/embedded-real-lifecycle-r2/effective-runtime.json'
    consumer = json.loads(consumer_path.read_bytes())
    overlay = json.loads(overlay_path.read_bytes())
    mode = json.loads(mode_path.read_bytes())
    effective = json.loads(effective_path.read_bytes())
    provenance = []
    for row in effective['sources']:
        snapshot = effective_path.parent / 'source' / Path(row['path']).relative_to(ROOT)
        provenance.append(dict(row, path=str(snapshot)))
    frozen = [effective['runtime']['jar'], *provenance, *effective['javaClasses'],
              *consumer['runtime']['dependencies'], *consumer['runtime']['buildDependencies'],
              *consumer['testDependencies']]
    for row in frozen:
        assert identity(row['path']) == row, 'Frozen input changed: ' + row['path']
    test_command = next(row['argv'] for row in mode['commands'] if row['label'] == 'tests')
    java = test_command[0]
    entries = test_command[test_command.index('-cp') + 1].split(os.pathsep)
    entries[1] = effective['runtime']['jar']['path']
    entries[2] = overlay['imageClassesDirectory']
    json_jar = next((Path.home() / '.gradle/caches/modules-2/files-2.1/org.json/json/20240303').glob('*/*.jar'))
    classes = out / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(map(str, [classes, json_jar, *entries]))
    installer = ROOT / 'manager/src/main/java/dev/maplesu/manager/installer'
    source_names = ['StockOriginalResolver', 'StockRestoreTargets', 'InstallerTaskResult',
                    'InstallerSnapshot', 'StockBackupResolver', 'NativeInstallSequence', 'NativeStockBaseline']
    sources = [installer / (name + '.kt') for name in source_names]
    tests = ['OwnedEnvironmentRemovalTest', 'StockOriginalResolverTest', 'StockRestoreTargetsTest',
             'InstallerTaskResultTest', 'NativeInstallSequenceTest', 'StockOriginalAvbTest', 'StockBackupResolverTest']
    suites = ['dev.maplesu.manager.installer.' + name for name in tests]
    sources += [ROOT / 'manager/src/test/java/dev/maplesu/manager/installer' / (name + '.kt') for name in tests]
    if args.service:
        sources += [installer / (name + '.kt') for name in ['NativeInstallTransaction', 'InstallerServiceClient']]
        sources += [ROOT / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentUninstaller.kt',
                    ROOT / 'manager/src/test/java/dev/maplesu/manager/runtime/ultra/UltraEnvironmentUninstallerTest.kt']
        suites += ['dev.maplesu.manager.runtime.ultra.UltraEnvironmentUninstallerTest']
    source_records, source_copies = [], []
    for source in sources:
        target = out / 'source' / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        source_records.append(identity(source))
        source_copies.append(target)
    runtime = consumer['runtime']
    compiler = next(row['path'] for row in runtime['buildDependencies'] if 'kotlin-compiler-embeddable' in row['path'])
    coroutines = next(row['path'] for row in runtime['buildDependencies'] if 'kotlinx-coroutines-core-jvm' in row['path'])
    compiler_cp = os.pathsep.join([compiler, *runtime['classpath'].split(os.pathsep)[:2], coroutines])
    friends = ','.join([entries[0], effective['runtime']['jar']['path'], runtime['jar']['path'],
                       *[p for p in entries if p.endswith('compileDebugKotlin\\classes')]])
    receipt = dict(schema='maplesu-owned-environment-removal/1', sources=source_records,
                   consumerReceipt=identity(consumer_path), imageOverlay=identity(overlay_path),
                   effectiveRuntime=identity(effective_path),
                   runtimeSourceDifferences=[dict(recorded=row, current=identity(row['path']))
                       for row in effective['sources'] if identity(row['path']) != row],
                   frozenInputs=frozen, java=identity(java), jsonJar=identity(json_jar),
                   runner=identity(__file__), commands=[], deviceOperations=False, SDKOrAPKBuild=False)

    def run(label, command):
        result = subprocess.run(list(map(str, command)), cwd=ROOT / 'manager', stdin=subprocess.DEVNULL,
                                capture_output=True)
        for name in ('stdout', 'stderr'):
            (out / (label + '.' + name + '.log')).write_bytes(getattr(result, name))
        receipt['commands'].append(dict(label=label, argv=list(map(str, command)), exitCode=result.returncode))
        print(result.stdout.decode('utf-8', 'replace'), end='')
        print(result.stderr.decode('utf-8', 'replace'), end='')
        return result.returncode

    code = run('compile', [java, '-Xmx768m', '-cp', compiler_cp,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '17',
        '-Xfriend-paths=' + friends, '-classpath', classpath, '-d', classes, *source_copies])
    if not code:
        code = run('tests', [java, '-Xmx768m', '-cp', classpath, 'org.junit.runner.JUnitCore', *suites])
    receipt.update(exitCode=code, sourcesUnchanged=all(identity(row['path']) == row for row in source_records),
                   frozenInputsUnchanged=all(identity(row['path']) == row for row in frozen),
                   classes=[identity(p) for p in sorted(classes.rglob('*.class'))])
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
