"""Replay two recorded legacy entry windows against the frozen current product overlays."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'docs/dual-mode/impl/_work/2026-11-15-p2/evidence'
SAVED = ROOT / 'docs/dual-mode/impl/_work/2026-11-16/evidence/saved-id-frame-r1'


def identity(path):
    path = Path(path)
    return dict(path=str(path), bytes=path.stat().st_size,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--synthetic-pac-control', action='store_true')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tested = json.loads((SAVED / 'final/receipt.json').read_bytes())
    captured_path = EVIDENCE / 'hook-entry-readonly-r1/receipt.json'
    captured = json.loads(captured_path.read_bytes())
    runtime_path = EVIDENCE / 'embedded-real-lifecycle-r2/effective-runtime.json'
    runtime = json.loads(runtime_path.read_bytes())['runtime']
    walker = SAVED / 'final/tested-walker-overlay.jar'
    assert identity(walker)['sha256'] == tested['overlay']['sha256']
    recipe = json.loads(Path(tested['recipeReceipt']['path']).read_bytes())
    sources = tested['sources'] + recipe['sources']
    dependencies = [identity(walker), tested['recipeJar'], *tested['frozenInputs']]
    for row in sources + dependencies:
        assert identity(row['path']) == row, 'Changed input: ' + row['path']
    cases, inputs = [], []
    for row in captured['cases']:
        if row['case'] not in [7, 17]:
            continue
        assert identity(row['input']['path']) == row['input']
        inputs.append(row['input'])
        cases.append(dict(case=row['case'], entryOffset=row['symbols']['do_execveat_common'],
            notifyOffset=row['symbols']['arm64_notify_die'], dieOffset=row['symbols']['die'],
            entryBytes64=row['entryBytes64'], notifyFrameActual52=row['notifyFrameActual52']))
    fixture = out / 'windows.json'
    fixture.write_text(json.dumps(cases, indent=2) + '\n', encoding='utf-8')
    source = ROOT / 'scripts/tests/fixtures/RemainingLegacyHookProbe.kt'
    frozen_source = out / source.name
    frozen_source.write_bytes(source.read_bytes())
    compiler = next(row['path'] for row in runtime['buildDependencies'] if 'kotlin-compiler-embeddable' in row['path'])
    coroutines = next(row['path'] for row in runtime['buildDependencies'] if 'kotlinx-coroutines-core-jvm' in row['path'])
    compiler_cp = os.pathsep.join([compiler, *runtime['classpath'].split(os.pathsep)[:2], coroutines])
    replaced = {row['path'] for row in tested.get('replacedEphemeralDependencies', [])}
    runtime_cp = [entry for entry in runtime['classpath'].split(os.pathsep) if entry not in replaced]
    classpath = os.pathsep.join([str(walker), tested['recipeJar']['path'],
        tested['imageClassesDirectory'], runtime['jar']['path'], *runtime_cp])
    java = runtime['java']['path']
    harness = out / 'probe.jar'
    receipt = dict(schema='maplesu-remaining-legacy-hook/1', source=identity(source),
        capturedReceipt=identity(captured_path), runtimeReceipt=identity(runtime_path),
        fixture=identity(fixture), inputs=inputs, sources=sources, dependencies=dependencies,
        runner=identity(__file__), commands=[], mode='synthetic-pac-control' if args.synthetic_pac_control else 'actual-recorded-window',
        deviceOperations=False, partitionWrites=False, SDKOrAPKBuild=False, largeImageGeneration=False)
    commands = [('compile', [java, '-Xmx512m', '-cp', compiler_cp,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '17',
        '-Xfriend-paths=' + ','.join([runtime['jar']['path'], str(walker), tested['recipeJar']['path']]),
        '-classpath', classpath, '-d', harness, frozen_source]),
        ('probe', [java, '-Xmx512m', '-cp', str(harness) + os.pathsep + classpath,
        'dev.maplesu.manager.ultrakernel.RemainingLegacyHookProbeKt', fixture, out / 'result.json',
        'synthetic-pac-control' if args.synthetic_pac_control else 'actual-recorded-window'])]
    code = 1
    for label, argv in commands:
        result = subprocess.run(list(map(str, argv)), cwd=ROOT / 'manager', capture_output=True, stdin=subprocess.DEVNULL)
        for stream in ['stdout', 'stderr']:
            (out / (label + '.' + stream + '.log')).write_bytes(getattr(result, stream))
        receipt['commands'].append(dict(label=label, argv=list(map(str, argv)), exitCode=result.returncode))
        print(result.stdout.decode('utf-8', 'replace'), end='')
        print(result.stderr.decode('utf-8', 'replace'), end='')
        code = result.returncode
        if code:
            break
    if (out / 'result.json').is_file():
        receipt['result'] = json.loads((out / 'result.json').read_bytes())
    receipt.update(exitCode=code, sourcesUnchanged=all(identity(row['path']) == row for row in sources),
        inputsUnchanged=all(identity(row['path']) == row for row in inputs),
        dependenciesUnchanged=all(identity(row['path']) == row for row in dependencies))
    if harness.is_file():
        receipt['harness'] = identity(harness)
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
