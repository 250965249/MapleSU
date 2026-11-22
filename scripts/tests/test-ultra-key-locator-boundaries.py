"""Compile just the actual credential class and its pure SDK-locator boundary tests."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools/specgen'))
from specgen.product import cached_jar


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source_paths = [ROOT / 'manager/src/main/java/dev/maplesu/manager/ultrakernel/UltraKernelCredential.kt',
                    ROOT / 'manager/src/test/java/dev/maplesu/manager/ultrakernel/UltraKernelMetadataLocatorBoundsTest.kt']
    snapshots = []
    for source in source_paths:
        target = out / source.name
        target.write_bytes(source.read_bytes())
        snapshots.append(target)
    frozen_runner = out / Path(__file__).name
    frozen_runner.write_bytes(Path(__file__).read_bytes())
    dependencies = [cached_jar(*item) for item in [
        ('org.jetbrains.kotlin', 'kotlin-stdlib', '2.4.20'),
        ('org.jetbrains', 'annotations', '13.0'),
        ('org.jetbrains.kotlinx', 'kotlinx-coroutines-core-jvm', '1.11.0'),
        ('junit', 'junit', '4.13.2'), ('org.hamcrest', 'hamcrest-core', '1.3')]]
    compiler = cached_jar('org.jetbrains.kotlin', 'kotlin-compiler-embeddable', '2.4.20')
    java = Path(shutil.which('java') or 'java').resolve()
    classpath = os.pathsep.join(map(str, dependencies))
    compiler_classpath = os.pathsep.join(map(str, [compiler, *dependencies[:3]]))
    jar = out / 'credential-tests.jar'
    commands = [
        ('compile', [java, '-Xmx384m', '-cp', compiler_classpath,
                     'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect',
                     '-jvm-target', '17', '-classpath', classpath, '-d', jar, *snapshots]),
        ('tests', [java, '-Xmx128m', '-cp', str(jar) + os.pathsep + classpath,
                   'org.junit.runner.JUnitCore', 'dev.maplesu.manager.ultrakernel.UltraKernelMetadataLocatorBoundsTest']),
    ]
    sources = [identity(path) for path in [*source_paths,
        ROOT / 'runtime/maplesu-sdk/sdk/src/module/module_append_package_parser.cpp']]
    build_inputs = [identity(path) for path in [java, compiler, *dependencies]]
    rows = []
    for name, argv in commands:
        result = subprocess.run(list(map(str, argv)), cwd=out, capture_output=True,
                                text=True, encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        print(result.stdout + result.stderr, end='')
        rows.append(dict(name=name, argv=list(map(str, argv)), exit=result.returncode))
        if result.returncode:
            break
    stable = all(identity(row['path']) == row for row in [*sources, *build_inputs])
    passed = stable and len(rows) == len(commands) and all(row['exit'] == 0 for row in rows)
    receipt = dict(schema='maplesu-key-locator-bounds/1', sources=sources, buildInputs=build_inputs,
                   runner=identity(__file__), snapshots=[identity(path) for path in [*snapshots, frozen_runner]],
                   commands=rows, inputsUnchanged=stable, passed=passed,
                   SDKOrAPKBuild=False, deviceOperations=False, partitionWrites=False,
                   scope='Actual Kotlin credential class and pure synthetic Key fixtures; SDK parser source comparison only')
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
