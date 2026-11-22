"""Exercise the source bootstrap and generated policy bundle build contract."""
import copy
import argparse
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / '.tmp/source-bootstrap-tests'
WORK.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / 'runtime/maplesu-sdk/sdk/tools'))
import source_backend as SB

module = types.ModuleType('sdk_build_bootstrap_tests')
module.__file__ = str(ROOT / 'runtime/maplesu-sdk/sdk/build.py')
sys.modules[module.__name__] = module
exec(compile(Path(module.__file__).read_text(encoding='utf-8'), module.__file__, 'exec'), module.__dict__)
B = module
cases = []
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle-source', required=True, type=Path)
args_cli = parser.parse_args()


def passed(name):
    cases.append(dict(name=name, passed=True))


def rejects(name, action, exception):
    try:
        action()
    except exception:
        passed(name)
    else:
        raise AssertionError(name + ' accepted invalid input')


args = B.parse_args(['--source-payloads'])
assert all(B._select_stages(args).values())
assert not hasattr(args, 'helper_sdk_archive') and not hasattr(args, 'helper_backend_identity')
passed('source-only default selects full build without external archive identity parameters')
assert B.parse_args(['--all']).source_payloads is True
assert B.parse_args(['--all', '--reference-payloads']).source_payloads is False
passed('normal build defaults to source and historical payloads require explicit selection')
args = B.parse_args(['--payloads', '--source-payloads'])
selected = B._select_stages(args)
assert all(selected[key] for key in ('manifest', 'compile', 'compose', 'pack', 'payloads'))
passed('explicit source payload stage includes core and final archive dependencies')

installers = {row[4] for row in B.PH.TABLE}
entries = [types.SimpleNamespace(idx=i, name=name, sources=[Path('maintained.cpp')])
           for i, name in enumerate(['core.o', *sorted(installers)])]
args = B.parse_args(['--all', '--source-payloads', '--policy-bundle-source', 'candidate.cpp'])
events = []


def compile_core(rows, tc, args, report, vendor):
    assert {row.name for row in rows}.isdisjoint(installers)
    report['compile'] = dict(rows=[dict(idx=row.idx, name=row.name) for row in rows])
    events.append('compile-maintained-core')


def compose_core(rows, tc, args, report):
    report['compose'] = dict(rows=[dict(idx=row.idx, name=row.name) for row in rows])
    events.append('compose-core-without-reference-archive')


def pack_core(rows, tc, args, report, archive):
    assert archive.parts[-5:] == ('bootstrap', 'sdk', 'lib', 'arm64-v8a', 'libkernel_module_kit_static.a')
    report['pack'] = dict(archive=str(archive))
    events.append('pack-this-invocation-core')


def backend(tc, sdk, bundle, output, **kwargs):
    assert events[-1] == 'pack-this-invocation-core'
    events.append('compile-backend-from-explicit-bundle')
    return dict(pairing='new-pair')


with patch.object(B, 'stage_compile', compile_core), patch.object(B, 'stage_compose', compose_core), \
        patch.object(B, 'stage_pack', pack_core), patch.object(B.shutil, 'copytree'), \
        patch.object(SB, 'build_backend', backend), patch.object(SB, 'bundle_inputs', return_value=[]):
    report = {}
    remaining = B.stage_source_bootstrap(entries, None, args, report, None)
    assert {row.name for row in remaining} == installers and len(remaining) == 4
    assert events == ['compile-maintained-core', 'compose-core-without-reference-archive',
                      'pack-this-invocation-core', 'compile-backend-from-explicit-bundle']
    passed('source core excludes every installer and produces backend before helper payloads')
    report['compile'] = dict(rows=[dict(idx=row.idx, name=row.name) for row in remaining])
    B.merge_bootstrap_rows(report, 'compile')
    assert len(report['compile']['rows']) == len(entries) == report['compile']['members']
    assert [row['idx'] for row in report['compile']['rows']] == list(range(len(entries)))
    passed('final compile receipt covers core and installers exactly once')
    bad = copy.copy(args)
    bad.policy_bundle_source = None
    rejects('default source bootstrap needs prepared kernel inputs before core compilation',
            lambda: B.stage_source_bootstrap(entries, None, bad, {}, None), B.StageError)
    rejects('source bootstrap detects missing installer member',
            lambda: B.stage_source_bootstrap(entries[:-1], None, args, {}, None), B.StageError)
    no_source = copy.deepcopy(entries)
    no_source[0].sources = []
    rejects('source bootstrap excludes preserved old object as core source',
            lambda: B.stage_source_bootstrap(no_source, None, args, {}, None), B.StageError)

    def kernel(output, **kwargs):
        events.append('compile-six-kernel-source-contracts')
        return dict(bundle='generated/policy-bundles.cpp')

    events.clear()
    with patch.object(SB, 'build_kernel_bundle', kernel):
        report = {}
        remaining = B.stage_source_bootstrap(entries, None, bad, report, None)
    assert events == ['compile-six-kernel-source-contracts', 'compile-maintained-core',
                      'compose-core-without-reference-archive', 'pack-this-invocation-core',
                      'compile-backend-from-explicit-bundle']
    assert report['source_kernel']['bundle'] == 'generated/policy-bundles.cpp'
    assert len(remaining) == 4
    passed('default source bootstrap generates kernel bundle before core and backend')

    events.clear()
    with patch.object(SB, 'bundle_inputs', side_effect=ValueError('invalid bundle fixture')):
        rejects('invalid bundle rejected before expensive core compilation',
                lambda: B.stage_source_bootstrap(entries, None, args, {}, None), B.StageError)
    assert events == []

build = Path('D:/build')
deps = SB.parse_dependencies('obj.o: #deps 1, deps mtime 1 (VALID)\n    D:/source/main.cpp\n', build)
assert deps == {'obj.o': [Path('D:/source/main.cpp')]}
passed('Windows compiler dependency drive path remains intact')
rejects('stale compiler dependency rejected',
        lambda: SB.parse_dependencies('obj.o: #deps 1, deps mtime 1 (STALE)\n', build), ValueError)
rejects('orphan compiler dependency rejected',
        lambda: SB.parse_dependencies('    D:/source/main.cpp\n', build), ValueError)

actual = args_cli.bundle_source.resolve()
inputs = SB.bundle_inputs(actual)
assert any(role == 'kernel_source' and path.suffix == '.c' for path, role in inputs)
assert any(role == 'kernel_source' and path.suffix == '.S' for path, role in inputs)
assert any(role == 'kernel_build_input' and path.name == 'policy-view.so' for path, role in inputs)
passed('actual bundle source receipt closes through kernel C assembly and built inputs')
with tempfile.TemporaryDirectory(prefix='bundle-', dir=WORK) as raw:
    directory = Path(raw)
    candidate = directory / actual.name
    candidate.write_bytes(actual.read_bytes())
    metadata = json.loads(actual.with_suffix('.json').read_text(encoding='utf-8'))
    for name, mutate in (
            ('bundle generated-source drift', lambda row: row.update(generatedSourceSha256='0' * 64)),
            ('bundle kernel-source drift', lambda row: row['kernelSourceSha256'].update(
                {next(iter(row['kernelSourceSha256'])): '0' * 64})),
            ('bundle kernel-artifact drift', lambda row: row['bundles'][0]['sourceSha256'].update(
                {'policy-view.so': '0' * 64}))):
        changed = copy.deepcopy(metadata)
        mutate(changed)
        candidate.with_suffix('.json').write_text(json.dumps(changed), encoding='utf-8')
        rejects(name, lambda: SB.bundle_inputs(candidate), ValueError)

result = dict(passed=True, cases=cases, deviceAccess=False)
(WORK / 'test-result.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(f'{len(cases)} source bootstrap checks PASS')
