"""Run bounded remaining phases against the existing read-only real case04 candidate."""
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
    parser.add_argument('--candidate-receipt', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    tested = json.loads(args.overlay_receipt.read_bytes())
    previous = json.loads(args.candidate_receipt.read_bytes())
    effective_path = BASE / 'embedded-real-lifecycle-r2/effective-runtime.json'
    effective = json.loads(effective_path.read_bytes())
    runtime = effective['runtime']
    assert tested['exitCode'] == 0 and tested['sourcesUnchanged'] and tested['frozenInputsUnchanged']
    dependencies = [tested['overlay'], tested['recipeJar'], *tested['frozenInputs']]
    for row in dependencies + tested['sources']:
        assert identity(row['path']) == row, 'Phase input changed: ' + row['path']
    candidate = previous['result']['stages']['prepareTarget']['preparation']['image']
    assert identity(candidate['path']) == candidate
    base = previous['input']
    assert identity(base['path']) == base
    receipt_dir = Path(candidate['path']).parent
    key_spec = next(receipt_dir.glob('*.spec'))
    source = ROOT / 'scripts/tests/fixtures/SavedIdFrameRemainingMain.kt'
    frozen_source = out / source.name
    frozen_source.write_bytes(source.read_bytes())
    compiler = next(row['path'] for row in runtime['buildDependencies'] if 'kotlin-compiler-embeddable' in row['path'])
    coroutines = next(row['path'] for row in runtime['buildDependencies'] if 'kotlinx-coroutines-core-jvm' in row['path'])
    compiler_cp = os.pathsep.join([compiler, *runtime['classpath'].split(os.pathsep)[:2], coroutines])
    replaced = {row['path'] for row in tested.get('replacedEphemeralDependencies', [])}
    runtime_cp = [entry for entry in runtime['classpath'].split(os.pathsep) if entry not in replaced]
    classpath = os.pathsep.join([tested['overlay']['path'], tested['recipeJar']['path'],
        tested['imageClassesDirectory'], runtime['jar']['path'], *runtime_cp])
    java = runtime['java']['path']
    harness = out / 'remaining-harness.jar'
    receipt = dict(schema='maplesu-saved-id-frame-remaining/1', base=base, installed=candidate,
        overlayReceipt=identity(args.overlay_receipt), candidateReceipt=identity(args.candidate_receipt),
        effectiveReceipt=identity(effective_path), source=identity(source), frozenSource=identity(frozen_source),
        keySpec=identity(key_spec), dependencies=dependencies, productionSources=tested['sources'], commands=[],
        runner=identity(__file__), deviceOperations=False, partitionWrites=False, SDKOrAPKBuild=False)
    commands = [('compile', [java, '-Xmx512m', '-cp', compiler_cp,
        'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '17',
        '-Xfriend-paths=' + ','.join([runtime['jar']['path'], tested['overlay']['path'], tested['recipeJar']['path']]),
        '-classpath', classpath, '-d', harness, frozen_source]),
        ('phases', [java, '-Xmx768m', '-cp', str(harness) + os.pathsep + classpath,
        'dev.maplesu.manager.ultrakernel.SavedIdFrameRemainingMainKt', base['path'], candidate['path'],
        receipt_dir, key_spec, out / 'work', ROOT / 'manager/src/main/assets'])]
    code = 1
    for label, argv in commands:
        result = subprocess.run(list(map(str, argv)), cwd=ROOT, capture_output=True, stdin=subprocess.DEVNULL)
        for stream in ['stdout', 'stderr']:
            (out / (label + '.' + stream + '.log')).write_bytes(getattr(result, stream))
        receipt['commands'].append(dict(label=label, argv=list(map(str, argv)), exitCode=result.returncode))
        print(result.stdout.decode('utf-8', 'replace'), end='')
        print(result.stderr.decode('utf-8', 'replace'), end='')
        code = result.returncode
        if code:
            break
    result_path = out / 'work/result.json'
    if result_path.is_file():
        receipt['result'] = json.loads(result_path.read_bytes())
        receipt['allFourPhasesPassed'] = len(receipt['result']['stages']) == 4 and all(
            stage['passed'] for stage in receipt['result']['stages'].values())
    receipt.update(exitCode=code, baseUnchanged=identity(base['path']) == base,
        installedUnchanged=identity(candidate['path']) == candidate,
        sourcesUnchanged=all(identity(row['path']) == row for row in tested['sources']) and identity(source) == receipt['source'],
        dependenciesUnchanged=all(identity(row['path']) == row for row in dependencies))
    if harness.is_file():
        receipt['harness'] = identity(harness)
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
