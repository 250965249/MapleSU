"""Check kernel build orchestration with isolated file fixtures and recorded commands."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'runtime/maplesu-sdk/sdk/tools'))
import source_backend as SB

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--json', type=Path)
args = parser.parse_args()
cases = []


def passed(name):
    cases.append(dict(name=name, passed=True))


def rejects(name, action, message):
    try:
        action()
    except ValueError as exc:
        assert message in str(exc), (name, str(exc))
    else:
        raise AssertionError(name + ' accepted invalid input')
    passed(name)


assert SB.compiler_target([{'command': 'clang --target=aarch64-none-linux-android31 -c a.cpp'}] * 10) == 'aarch64-none-linux-android31'
passed('backend target comes from all actual API31 compiler commands')
for name, rows in (
        ('empty compiler commands', []),
        ('missing compiler target', [{'command': 'clang -c a.cpp'}]),
        ('mixed compiler targets', [{'command': 'clang --target=aarch64-linux-android21'},
                                    {'command': 'clang --target=aarch64-none-linux-android31'}])):
    rejects(name, lambda rows=rows: SB.compiler_target(rows), 'single compiler target')

work = ROOT / '.tmp/source-kernel-bootstrap-tests'
work.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='run-', dir=work) as raw:
    directory = Path(raw)
    prepared = directory / 'prepared'
    prepared.mkdir()
    with patch.object(SB.S, 'run') as runner:
        rejects('missing explicit 6.18 preparation paths', lambda: SB.build_kernel_bundle(
            directory / 'missing', source_618=None, objtree_618=None, toolchain_618=None),
            '--kernel-source-618, --kernel-objtree-618, --kernel-toolchain-618')
        runner.assert_not_called()

    source = directory / 'fixture.c'
    assembly = directory / 'fixture.S'
    source.write_text('/* Test fixture, not a kernel program. */\n', encoding='utf-8')
    assembly.write_text('// Test fixture, not a kernel program.\n', encoding='utf-8')
    source_hashes = {SB.S.rel(path): SB.S.sha256_file(path) for path in (source, assembly)}
    families = ['android12-5.10', 'android13-5.15', 'android14-6.1',
                'android15-6.6', 'android16-6.12', 'android17-6.18']
    commands = []

    def write(path, value):
        path.write_text(json.dumps(value), encoding='utf-8')

    def execute(argv, **kwargs):
        argv = list(map(str, argv))
        commands.append(argv)
        script = Path(argv[1]).name
        if script == 'test-ultra-policy-kernel.py':
            assert not set(families).intersection(argv), 'production must use maintained default targets'
            output = Path(argv[argv.index('--output') + 1])
            results = []
            for family in families:
                target = output / family
                target.mkdir(parents=True)
                for name in ('policy-view.so', 'compiled-layout.json', 'target-identity.json',
                             'System.map', 'target.config', 'fixture.c', 'fixture.S',
                             '.fixture.o.cmd', 'maplesu_policy_view.mod'):
                    (target / name).write_text('fixture ' + name, encoding='utf-8')
                if family != 'android12-5.10':
                    (target / 'vmlinux.btf').write_bytes(b'fixture BTF')
                image = target / 'policy-view.so'
                results.append(dict(kernel=family, exitCode=0, picPayload=dict(
                    passed=True, bytes=image.stat().st_size, sha256=SB.S.sha256_file(image))))
            write(Path(argv[argv.index('--save') + 1]), dict(sourcesUnchanged=True,
                hostTests=dict(exitCode=0), results=results, sourceSha256=source_hashes))
        elif script == 'build-ultra-policy-config-declarations.py':
            assert Path(argv[2]).name != 'android17-6.18'
            assert (Path(argv[2]) / 'kernel-compatibility.json').is_file(), 'declarations consume the existing compatibility imports'
            write(Path(argv[2]) / 'config-declarations.json', dict(fixture=True))
        elif script == 'build-ultra-policy-compatibility.py':
            target = Path(argv[2])
            series = target.name.split('-')[-1]
            policy = json.loads((ROOT / 'runtime/ultra/policy/kernel_compatibility_profiles.json').read_text())
            variants = policy['profilesBySeries'].get(series, [])
            write(target / 'kernel-compatibility.json', dict(kernelSeries=series,
                config={key: 'y' for profile in variants for key in profile},
                equivalentConfigs=variants, inputSha256={'policy-view.so': SB.S.sha256_file(target / 'policy-view.so')}))
        elif script == 'build-ultra-policy-bundles.py':
            output = Path(argv[-1])
            output.write_text('// Generated fixture bundle, not a deliverable.\n', encoding='utf-8')
            write(output.with_suffix('.json'), dict(generatedSourceSha256=SB.S.sha256_file(output),
                generatorSha256=SB.S.sha256_file(ROOT / 'scripts/build-ultra-policy-bundles.py'),
                profilePolicySha256=SB.S.sha256_file(ROOT / 'runtime/ultra/policy/kernel_compatibility_profiles.json'),
                kernelSourceSha256=source_hashes, bundles=[dict(directory=str(Path(path)),
                    sourceSha256={name: SB.S.sha256_file(Path(path) / name) for name in (
                        'policy-view.so', 'compiled-layout.json', 'target-identity.json', 'System.map', 'target.config')})
                    for path in argv[2:argv.index('--output')]]))
        elif script == 'collect-ultra-policy-kbuild-inputs.py':
            output = Path(argv[argv.index('--output') + 1])
            write(output, dict(schema='maplesu-kernel-kbuild-inputs/1',
                inputs=[SB.P.file_record(source, ROOT), SB.P.file_record(assembly, ROOT)]))
        else:
            raise AssertionError(script)
        return SimpleNamespace(returncode=0, stdout='fixture command passed\n', stderr='')

    with patch.object(SB.S, 'run', execute):
        report = SB.build_kernel_bundle(directory / 'kernel', source_618=prepared,
                                       objtree_618=prepared, toolchain_618=prepared)
    bundle = ROOT / report['bundle']
    metadata = json.loads(bundle.with_suffix('.json').read_text())
    inputs = SB.bundle_inputs(bundle)
    assert all(any(path.name == name for path, role in inputs) for name in (
        'kernel-build.json', 'kernel-contracts.json', 'kernel-build-inputs.json',
        'fixture.c', 'fixture.S', '.fixture.o.cmd'))
    assert len(metadata['bundles']) == 6
    passed('default six-family orchestration closes source commands and contracts')
    assert not any(Path(cmd[1]).name == 'build-ultra-policy-config-declarations.py' and
                   Path(cmd[2]).name == 'android17-6.18' for cmd in commands)
    passed('6.18 uses its compatibility tool without DDK declaration path')
    assert [Path(cmd[1]).name for cmd in commands if len(cmd) == 3 and
            Path(cmd[2]).name == 'android13-5.15'] == [
        'build-ultra-policy-compatibility.py', 'build-ultra-policy-config-declarations.py',
        'build-ultra-policy-compatibility.py']
    passed('declaration imports come from base compatibility then refresh the final contract')

    def change_metadata(change):
        changed = copy.deepcopy(metadata)
        change(changed)
        write(bundle.with_suffix('.json'), changed)
        try:
            SB.bundle_inputs(bundle)
        finally:
            write(bundle.with_suffix('.json'), metadata)

    for name, mutate, expected in (
            ('generator drift', lambda m: m.update(generatorSha256='0' * 64), 'generator changed'),
            ('profile policy drift', lambda m: m.update(profilePolicySha256='0' * 64), 'profile policy changed'),
            ('missing actual Kbuild receipt', lambda m: m.pop('kernelBuildReceipt'), 'kernelBuildReceipt'),
            ('missing actual contract receipt', lambda m: m.pop('kernelContractReceipt'), 'kernelContractReceipt'),
            ('missing sixth family', lambda m: m['bundles'].pop(), 'family coverage differs'),
            ('kernel receipt identity drift', lambda m: m['kernelBuildReceipt'].update(sha256='0' * 64), 'receipt input changed')):
        rejects(name, lambda mutate=mutate: change_metadata(mutate), expected)

    def change_receipt(key, change, expected):
        path = ROOT / metadata[key]['path']
        original = path.read_bytes()
        receipt = json.loads(original)
        change(receipt)
        write(path, receipt)
        changed = copy.deepcopy(metadata)
        changed[key] = SB.P.file_record(path, ROOT)
        write(bundle.with_suffix('.json'), changed)
        try:
            rejects(key + ' ' + expected, lambda: SB.bundle_inputs(bundle), expected)
        finally:
            path.write_bytes(original)
            write(bundle.with_suffix('.json'), metadata)

    change_receipt('kernelBuildReceipt', lambda r: r.update(sourcesUnchanged=False), 'successful six-family')
    change_receipt('kernelBuildReceipt', lambda r: r['results'][0].update(exitCode=1), 'successful six-family')
    change_receipt('kernelBuildReceipt', lambda r: r['results'][0]['picPayload'].update(sha256='0' * 64), 'actual Kbuild payload')
    change_receipt('kernelContractReceipt', lambda r: r['commands'][0].update(exitCode=1), 'command receipt')
    change_receipt('kernelContractReceipt', lambda r: r['inputs'][0].update(sha256='0' * 64), 'receipt input changed')
    change_receipt('kernelContractReceipt', lambda r: r.pop('dependencyReceipt'), 'compiler dependency receipt')
    assert SB.bundle_inputs(bundle)

result = dict(passed=True, cases=cases, deviceAccess=False, kernelCompiled=False,
              scope='Isolated fixture files and mocked Kbuild commands; no runtime or actual Kbuild acceptance')
output = args.json or work / 'test-result.json'
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(f'{len(cases)} source kernel bootstrap checks PASS')
