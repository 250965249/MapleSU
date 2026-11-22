"""Exercise the real source SDK validator using isolated copies of a candidate."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from source_sdk_delivery import checked, record, source_inputs, verify_source_delivery


def records(value):
    if isinstance(value, dict):
        if {'path', 'size', 'sha256'} <= value.keys():
            yield value
        for child in value.values():
            yield from records(child)
    elif isinstance(value, list):
        for child in value:
            yield from records(child)


def remap(value, paths):
    if isinstance(value, str):
        return paths.get(value, value)
    if isinstance(value, dict):
        return {paths.get(key, key): remap(child, paths) for key, child in value.items()}
    if isinstance(value, list):
        return [remap(child, paths) for child in value]
    return value


def build_objects(build):
    for row in build['compile']['rows']:
        for output in row['outputs']:
            yield dict(path=output['object'], size=output['bytes'], sha256=output['sha256'])
    for item in build['pack']['member_inputs']:
        yield record(ROOT / item['object'], ROOT)
    for unit in build.get('provenance', {}).get('translation_units', []):
        yield dict(path=unit['object'], size=unit['bytes'], sha256=unit['sha256'])
    if build.get('source_backend'):
        yield build['source_backend']['file']
        if build['source_backend'].get('compileCommands'):
            yield build['source_backend']['compileCommands']
        yield from records(build['final_archive_stability'])


def build_directory(manifest):
    name = manifest['sourceBuild'].get('buildDirectory')
    return (ROOT / name).resolve() if name else None


def retained_inputs(manifest):
    retained = json.loads(checked(manifest['sourceBuild']['retainedRelease'], ROOT).read_text(encoding='utf-8-sig'))
    helper = checked(retained['helper'], ROOT)
    yield retained['helper']
    for path in sorted((helper.parents[1] / 'maintenance/entry').rglob('*')):
        if path.is_file():
            yield record(path, ROOT)


class Fixture:
    def __init__(self, candidate, manifest, directory):
        self.directory = directory.resolve()
        self.changed = {}
        shutil.copytree(candidate, self.directory / 'candidate')
        paths = {}

        original_build_root = build_directory(manifest)

        def target_path(source):
            if source.is_relative_to(candidate):
                return self.directory / 'candidate' / source.relative_to(candidate)
            if original_build_root is not None and source.is_relative_to(original_build_root):
                return self.directory / 'inputs/external-build' / source.relative_to(original_build_root)
            assert source.is_relative_to(ROOT), 'Fixture input outside allowed directories: ' + str(source)
            return self.directory / 'inputs' / source.relative_to(ROOT)

        if original_build_root is not None:
            paths[manifest['sourceBuild']['buildDirectory']] = target_path(original_build_root).relative_to(ROOT).as_posix()
        original_build = json.loads(checked(manifest['sourceBuild']['buildReport'], ROOT,
                                            original_build_root).read_text(encoding='utf-8'))
        for item in list(records(manifest)) + list(build_objects(original_build)) + list(retained_inputs(manifest)):
            source = checked(item, ROOT, original_build_root)
            target = target_path(source)
            paths[item['path']] = target.relative_to(ROOT).as_posix()
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
        for name in original_build['compile']['include_dirs']:
            directory = (ROOT / name).resolve()
            target = target_path(directory)
            paths[name] = target.relative_to(ROOT).as_posix()
            target.mkdir(parents=True, exist_ok=True)
        for item in original_build.get('provenance', {}).get('optional_inputs', []):
            target = target_path((ROOT / item['path']).resolve())
            paths[item['path']] = target.relative_to(ROOT).as_posix()
        self.manifest = remap(manifest, paths)
        build_item = self.manifest['sourceBuild']['buildReport']
        build_path = ROOT / build_item['path']
        build = remap(json.loads(build_path.read_text(encoding='utf-8')), paths)
        helper_item = self.manifest['sourceBuild'].get('helperBuildReport')
        if helper_item is not None:
            helper_path = ROOT / helper_item['path']
            helper = remap(json.loads(helper_path.read_text(encoding='utf-8')), paths)
            helper_path.write_text(json.dumps(helper, indent=2) + '\n', encoding='utf-8')
            helper_item.update(record(helper_path, ROOT))
            for item in list(records(self.manifest)) + list(records(build)):
                if item['path'] == helper_item['path']:
                    item.update(helper_item)
            build['source_helper'] = {**helper, 'reportPath': helper_item['path']}
            build['assets']['helper']['report'] = copy.deepcopy(helper_item)
        build_path.write_text(json.dumps(build, indent=2) + '\n', encoding='utf-8')
        build_item.update(record(build_path, ROOT))
        if original_build_root is not None:
            assert build_path.resolve() == build_directory(self.manifest) / 'report/build-report.json'
        retained_item = self.manifest['sourceBuild']['retainedRelease']
        retained_path = ROOT / retained_item['path']
        retained = remap(json.loads(retained_path.read_text(encoding='utf-8-sig')), paths)
        assert checked(retained['helper'], ROOT).is_relative_to(self.directory)
        retained_path.write_text(json.dumps(retained, indent=2) + '\n', encoding='utf-8')
        retained_item.update(record(retained_path, ROOT))

    def write(self, item, data):
        path = (ROOT / item['path']).resolve()
        assert path.is_relative_to(self.directory), 'Test attempted to write outside its fixture'
        self.changed.setdefault(path, path.read_bytes() if path.is_file() else None)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def corrupt(self, item, refresh=False):
        data = bytearray((ROOT / item['path']).read_bytes())
        assert data, 'Nonempty real candidate input required'
        data[-1] ^= 1
        self.write(item, data)
        if refresh:
            item.update(record(ROOT / item['path'], ROOT))

    def edit_json(self, item, mutate):
        value = json.loads((ROOT / item['path']).read_text(encoding='utf-8-sig'))
        mutate(value)
        self.write(item, (json.dumps(value, indent=2) + '\n').encode())
        item.update(record(ROOT / item['path'], ROOT))

    def build(self, manifest, mutate):
        self.edit_json(manifest['sourceBuild']['buildReport'], mutate)

    def restore(self):
        for path, data in self.changed.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(data)
        self.changed.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    candidate = args.candidate.resolve()
    output = args.output.resolve()
    assert candidate.is_relative_to(ROOT), 'Candidate must be inside the repository'
    release_path = candidate / 'SDK-RELEASE.json'
    manifest = json.loads(release_path.read_text(encoding='utf-8-sig'))
    baseline = verify_source_delivery(manifest, ROOT)
    original_build_root = build_directory(manifest)
    original_build = json.loads(checked(manifest['sourceBuild']['buildReport'], ROOT,
                                        original_build_root).read_text(encoding='utf-8'))
    original_retained = list(retained_inputs(manifest))
    original_optional = original_build.get('provenance', {}).get('optional_inputs', [])
    original = {item['path']: record(checked(item, ROOT, original_build_root), ROOT)
                for item in list(records(manifest)) + list(build_objects(original_build)) + original_retained}
    results = [dict(name='real-candidate', passed=True, result=baseline)]
    temporary_root = ROOT / '.tmp'
    temporary_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='source-sdk-contract-', dir=temporary_root) as temporary:
        fixture = Fixture(candidate, manifest, Path(temporary))

        def check(name, mutate=None):
            test = copy.deepcopy(fixture.manifest)
            try:
                if mutate is not None:
                    try:
                        mutate(test)
                    except Exception as error:
                        results.append(dict(name=name, passed=False, rejected=False,
                                            fixtureError=type(error).__name__ + ': ' + str(error)))
                        return
                try:
                    result = verify_source_delivery(test, ROOT)
                except AssertionError as error:
                    results.append(dict(name=name, passed=mutate is not None,
                                        rejected=True, diagnostic=str(error)))
                except Exception as error:
                    results.append(dict(name=name, passed=False, rejected=False,
                                        unexpected=type(error).__name__ + ': ' + str(error)))
                else:
                    results.append(dict(name=name, passed=mutate is None,
                                        rejected=False, result=result))
            finally:
                if results[-1]['name'] == name and not results[-1]['passed']:
                    failure_root = output.parent / (output.stem + '-fixtures')
                    failure_root.mkdir(parents=True, exist_ok=True)
                    saved = Path(tempfile.mkdtemp(prefix=name + '-', dir=failure_root))
                    shutil.copytree(fixture.directory, saved / 'fixture')
                    (saved / 'manifest.json').write_text(json.dumps(test, indent=2) + '\n', encoding='utf-8')
                    results[-1].update(fixture=saved.as_posix(), originalFixture=fixture.directory.as_posix())
                fixture.restore()

        def source(test):
            return test['sourceBuild']

        check('isolated-candidate')
        for field in ('archive', 'helper'):
            check(field + '-bytes', lambda test, field=field: fixture.corrupt(test[field]))
        check('backend-bytes', lambda test: fixture.corrupt(test['environmentPolicyBoot']['backend']))
        for payload in manifest['sourceBuild']['payloads']:
            name = payload['name']
            check('payload-bytes-' + name, lambda test, name=name:
                  fixture.corrupt(next(item['file'] for item in source(test)['payloads'] if item['name'] == name)))
        for field in ('input', 'staged'):
            check('header-' + field + '-bytes', lambda test, field=field:
                  fixture.corrupt(source(test)['headers'][0][field]))
        check('header-content-pair', lambda test: fixture.corrupt(source(test)['headers'][0]['staged'], True))
        check('compiled-source-bytes', lambda test: fixture.corrupt(next(
              (item for item in source(test)['inputs'] if 'tu' in item.get('roles', [])), source(test)['inputs'][0])))
        check('retained-entry-bytes', lambda test: fixture.corrupt(source(test)['retainedEntry'][0]))
        for index, item in enumerate(manifest['sourceBuild']['retainedPolicyFiles']):
            check('retained-policy-bytes-' + Path(item['path']).name,
                  lambda test, index=index: fixture.corrupt(source(test)['retainedPolicyFiles'][index]))
        for index, item in enumerate(manifest['sourceBuild'].get('policyFiles', [])):
            check('source-policy-bytes-' + Path(item['path']).name,
                  lambda test, index=index: fixture.corrupt(source(test)['policyFiles'][index]))
        check('source-receipt-hash', lambda test: source(test)['inputs'][0].update(sha256='0' * 64))
        check('source-receipt-missing', lambda test: source(test)['inputs'].pop())

        for field, value in (('sha256', '0' * 64), ('bytes', 0)):
            check('pack-' + field, lambda test, field=field, value=value:
                  fixture.build(test, lambda build: build['pack'].update({field: value})))
        check('build-failure', lambda test: fixture.build(test, lambda build: build.update(failure='fixture')))
        check('compile-failure', lambda test: fixture.build(test,
              lambda build: build['compile'].update(failures=[dict(idx=0, error='fixture')])))
        check('member-gate-failure', lambda test: fixture.build(test,
              lambda build: build['gate'].update(exit_code=1)))
        check('pack-member-hash', lambda test: fixture.build(test,
              lambda build: build['pack']['member_inputs'][0].update(object_sha256='0' * 64)))
        check('pack-member-missing', lambda test: fixture.build(test,
              lambda build: build['pack']['member_inputs'].pop()))
        if original_build.get('source_backend'):
            if original_build['source_backend'].get('compileCommands'):
                check('backend-target-receipt-drift', lambda test: fixture.build(test,
                      lambda build: build['source_backend']['provenance']['toolchain'].update(target='fixture-target')))
                check('backend-compile-commands-drift', lambda test: fixture.build(test,
                      lambda build: build['source_backend']['compile_commands'][0].update(command='fixture command')))
            check('bootstrap-archive-bytes', lambda test: fixture.corrupt(next(
                  item for item in source(test)['inputs'] if 'sdk_archive' in item.get('roles', []))))
            check('bootstrap-member-count', lambda test: fixture.build(test,
                  lambda build: build['bootstrap']['pack'].update(members=260)))
            check('backend-source-identity', lambda test: fixture.build(test,
                  lambda build: build['source_backend']['identity'].update(sha256='0' * 64)))
            check('final-archive-stability-missing', lambda test: fixture.build(test,
                  lambda build: build.pop('final_archive_stability')))
            check('final-archive-stability-false', lambda test: fixture.build(test,
                  lambda build: build['final_archive_stability'].update(passed=False)))
            for kind in ('backend', 'helper'):
                check('final-' + kind + '-identity', lambda test, kind=kind: fixture.build(test,
                      lambda build: build['final_archive_stability'][kind].update(identical=False)))
                check('final-' + kind + '-selected-members', lambda test, kind=kind: fixture.build(test,
                      lambda build: build['final_archive_stability'][kind].update(selected_sdk_members=[])))
        check('compile-output-hash', lambda test: fixture.build(test,
              lambda build: build['compile']['rows'][0]['outputs'][0].update(sha256='0' * 64)))
        check('compose-member-hash', lambda test: fixture.build(test,
              lambda build: build['compose']['rows'][0].update(sha256='0' * 64)))
        check('compose-member-input', lambda test: fixture.build(test,
              lambda build: build['compose']['rows'][0].update(inputs=[])))
        check('compose-member-missing', lambda test: fixture.build(test,
              lambda build: build['compose']['rows'].pop()))

        def corrupt_object(test, composed):
            build = json.loads((ROOT / source(test)['buildReport']['path']).read_text(encoding='utf-8'))
            outputs = {output['object'] for row in build['compile']['rows'] for output in row['outputs']}
            name = (next(item['object'] for item in build['pack']['member_inputs'] if item['object'] not in outputs)
                    if composed else build['compile']['rows'][0]['outputs'][0]['object'])
            fixture.corrupt(record(ROOT / name, ROOT))

        check('compile-object-bytes', lambda test: corrupt_object(test, False))
        check('composed-object-bytes', lambda test: corrupt_object(test, True))

        def source_hash_missing(build):
            row = next(row for row in build['compile']['rows'] if row['sources'])
            row['source_sha256'].pop(row['sources'][0])

        check('source-hash-missing', lambda test: fixture.build(test, source_hash_missing))

        def build_source_hash_changed(build):
            row = next(row for row in build['compile']['rows'] if row['build_source_sha256'])
            name = next(iter(row['build_source_sha256']))
            row['build_source_sha256'][name] = '0' * 64

        check('build-source-hash', lambda test: fixture.build(test, build_source_hash_changed))
        for field in ('source_sha256', 'build_source_sha256'):
            check('output-' + field, lambda test, field=field: fixture.build(test,
                  lambda build: next(row['outputs'][0] for row in build['compile']['rows'] if row['outputs']).update({field: '0' * 64})))

        def members(test, change):
            item = source(test)['memberManifest']
            rows = [json.loads(line) for line in (ROOT / item['path']).read_text(encoding='utf-8').splitlines() if line.strip()]
            change(rows)
            fixture.write(item, ('\n'.join(json.dumps(row) for row in rows) + '\n').encode())
            item.update(record(ROOT / item['path'], ROOT))

        check('manifest-member-name', lambda test: members(test, lambda rows: rows[0].update(name='fixture.o')))
        check('manifest-member-missing', lambda test: members(test, lambda rows: rows.pop()))
        check('helper-key-slot', lambda test: test['helper'].update(keySlotOffset=0))
        check('helper-build-id', lambda test: test['helper'].update(buildId='fixture'))
        if original_build.get('source_helper'):
            check('source-helper-receipt-bytes', lambda test: fixture.corrupt(source(test)['helperBuildReport']))
            check('source-helper-receipt-identity', lambda test: fixture.edit_json(source(test)['helperBuildReport'],
                  lambda helper: helper['surface'].update(sha256='0' * 64)))
            check('source-helper-origin', lambda test: source(test).update(helperOrigin='reference-copy'))
            check('source-helper-selection', lambda test: fixture.build(test,
                  lambda build: build['assets']['helper'].update(builtFromSource=False)))
            check('source-payload-origin', lambda test: source(test)['payloads'][0].update(origin='reference-copy'))
        else:
            check('retained-helper-identity', lambda test: fixture.edit_json(source(test)['retainedRelease'],
                  lambda retained: retained['helper'].update(sha256='0' * 64)))
        check('backend-identity', lambda test: test['environmentPolicyBoot']['backend'].update(fileName='fixture.so'))
        check('backend-helper-pair', lambda test: test['environmentPolicyBoot'].update(entryHelperSha256='0' * 64))
        check('payload-missing', lambda test: source(test)['payloads'].pop())
        check('payload-duplicate', lambda test: source(test)['payloads'].append(copy.deepcopy(source(test)['payloads'][0])))
        check('device-acceptance-claim', lambda test: source(test).update(deviceAcceptance=True))
        check('final-source-acceptance-claim', lambda test: source(test).update(finalSourceAcceptance=True))

        # Removing proof must not turn an incomplete delivery into a valid one.
        check('headers-empty', lambda test: source(test).update(headers=[]))
        check('header-proof-missing', lambda test: source(test)['headers'].pop())
        check('retained-entry-empty', lambda test: source(test).update(retainedEntry=[]))
        check('retained-entry-proof-missing', lambda test: source(test)['retainedEntry'].pop())

        def remove_compile_rows(test, all_rows):
            def mutate(build):
                if all_rows:
                    build['compile']['rows'] = []
                else:
                    build['compile']['rows'].pop()
            fixture.build(test, mutate)
            build = json.loads((ROOT / source(test)['buildReport']['path']).read_text(encoding='utf-8'))
            if 'provenance' not in build:
                source(test)['inputs'] = source_inputs(build, ROOT, build_directory(test))

        check('compile-proof-empty', lambda test: remove_compile_rows(test, True))
        check('compile-row-proof-missing', lambda test: remove_compile_rows(test, False))

        if 'provenance' in original_build:
            def proof_input(test, predicate):
                return next(item for item in source(test)['inputs'] if predicate(item))

            for name, predicate in (
                    ('private-header', lambda item: 'header' in item['roles'] and '/sdk/include/' in item['path']),
                    ('build-rule', lambda item: 'build_rule' in item['roles']),
                    ('program-json', lambda item: Path(item['path']).name == 'program.json')):
                check('provenance-' + name + '-bytes', lambda test, predicate=predicate:
                      fixture.corrupt(proof_input(test, predicate)))

            check('provenance-missing', lambda test: fixture.build(test, lambda build: build.pop('provenance')))
            check('provenance-schema', lambda test: source(test).update(provenanceSchema='fixture/invalid'))
            check('build-directory-report-mismatch', lambda test:
                  source(test).update(buildDirectory=source(test)['buildDirectory'] + '-other'))
            check('provenance-closure-false', lambda test: fixture.build(test,
                  lambda build: build['provenance'].update(closure_complete=False)))
            check('provenance-incomplete-reasons', lambda test: fixture.build(test,
                  lambda build: build['provenance'].update(incomplete_reasons=['fixture'])))
            check('provenance-dependency-kind-missing', lambda test: fixture.build(test,
                  lambda build: build['provenance']['translation_units'][0].pop('dependency_kind')))

            def remove_input_roles(test):
                source(test)['inputs'][0].pop('roles')
                fixture.build(test, lambda build: build['provenance']['inputs'][0].pop('roles'))

            check('provenance-input-roles-missing', remove_input_roles)
            check('source-input-roles', lambda test: source(test)['inputs'][0].update(roles=[]))

            def compile_output(build):
                return next(row['outputs'][0] for row in build['compile']['rows'] if row['outputs'])

            check('compile-dependency-kind-missing', lambda test: fixture.build(test,
                  lambda build: compile_output(build).pop('dependency_kind')))
            check('compile-dependency-incomplete', lambda test: fixture.build(test,
                  lambda build: compile_output(build).update(dependency_complete=False)))
            check('compile-dependency-errors', lambda test: fixture.build(test,
                  lambda build: compile_output(build).update(dependency_errors=['fixture'])))
            check('compile-dependency-snapshot-drift', lambda test: fixture.build(test,
                  lambda build: compile_output(build)['dependencies'][0].update(sha256='0' * 64)))
            check('compile-dependency-set-drift', lambda test: fixture.build(test,
                  lambda build: compile_output(build).update(dependencies=[])))
            check('compile-provenance-source-drift', lambda test: fixture.build(test,
                  lambda build: next(unit for unit in build['provenance']['translation_units']
                                     if unit['stage'] == 'compile').update(source='fixture-missing.cpp')))

            def remove_compose_proof(build, both):
                row = next(row for row in build['compose']['rows'] if row.get('outputs'))
                objects = {item['object'] for item in row['outputs']}
                if both:
                    row.pop('outputs')
                build['provenance']['translation_units'] = [
                    unit for unit in build['provenance']['translation_units']
                    if (unit['stage'], unit['object']) not in {('compose', name) for name in objects}]

            check('compose-provenance-unit-missing', lambda test: fixture.build(test,
                  lambda build: remove_compose_proof(build, False)))
            check('compose-output-proof-missing', lambda test: fixture.build(test,
                  lambda build: next(row for row in build['compose']['rows'] if row.get('outputs')).pop('outputs')))
            check('compose-proof-removed-together', lambda test: fixture.build(test,
                  lambda build: remove_compose_proof(build, True)))
            for tool in ('clang', 'llvm-ar', 'ld.lld'):
                check('toolchain-version-missing-' + tool, lambda test, tool=tool: fixture.build(test,
                      lambda build: build['provenance']['toolchain']['versions'].pop(tool)))

            if 'gate' in original_build.get('stages_run', []):
                check('optional-inputs-table-missing', lambda test: fixture.build(test,
                      lambda build: build['provenance'].pop('optional_inputs')))
                check('optional-inputs-table-empty', lambda test: fixture.build(test,
                      lambda build: build['provenance'].update(optional_inputs=[])))

                def remove_optional_proof_and_stage(build):
                    build['provenance'].pop('optional_inputs')
                    build['stages_run'] = [stage for stage in build['stages_run'] if stage != 'gate']

                check('optional-proof-removed-with-stage', lambda test: fixture.build(test, remove_optional_proof_and_stage))
                check('optional-input-present-drift', lambda test: fixture.build(test,
                      lambda build: build['provenance']['optional_inputs'][0].update(
                          present=not build['provenance']['optional_inputs'][0]['present'])))
                check('optional-input-present-type', lambda test: fixture.build(test,
                      lambda build: build['provenance']['optional_inputs'][0].update(present=1)))
                check('optional-input-role', lambda test: fixture.build(test,
                      lambda build: build['provenance']['optional_inputs'][0].update(role='fixture')))

                def change_optional_snapshot(test, remove):
                    def mutate(build):
                        name = next(item['path'] for item in build['provenance']['optional_inputs'] if item['present'])
                        if remove:
                            build['provenance']['inputs'] = [item for item in build['provenance']['inputs'] if item['path'] != name]
                            source(test)['inputs'] = [item for item in source(test)['inputs'] if item['path'] != name]
                        else:
                            for rows in (build['provenance']['inputs'], source(test)['inputs']):
                                next(item for item in rows if item['path'] == name)['roles'] = ['fixture']
                    fixture.build(test, mutate)

                check('optional-present-snapshot-missing', lambda test: change_optional_snapshot(test, True))
                check('optional-present-snapshot-role', lambda test: change_optional_snapshot(test, False))

                def create_absent_optional(test):
                    build = json.loads((ROOT / source(test)['buildReport']['path']).read_text(encoding='utf-8'))
                    item = next((item for item in build['provenance']['optional_inputs'] if not item['present']), None)
                    if item is None:
                        path = fixture.directory / 'inputs/absent-optional-build-rule.json'
                        assert not path.exists()
                        item = dict(path=path.relative_to(ROOT).as_posix(), role='build_rule', present=False)
                        fixture.build(test, lambda build: build['provenance']['optional_inputs'].append(item))
                    verify_source_delivery(test, ROOT)
                    fixture.write(item, b'real optional input created after the build\n')

                check('optional-absent-file-created', create_absent_optional)

            for stage in sorted({unit['stage'] for unit in original_build['provenance']['translation_units']}
                                - {'compile', 'compose'}):
                def remove_stage_unit(build, stage=stage):
                    units = build['provenance']['translation_units']
                    units.pop(next(index for index, unit in enumerate(units) if unit['stage'] == stage))

                check('provenance-unit-missing-' + stage, lambda test, mutate=remove_stage_unit:
                      fixture.build(test, mutate))

                def corrupt_stage_object(test, stage=stage):
                    build = json.loads((ROOT / source(test)['buildReport']['path']).read_text(encoding='utf-8'))
                    unit = next(unit for unit in build['provenance']['translation_units'] if unit['stage'] == stage)
                    fixture.corrupt(dict(path=unit['object'], size=unit['bytes'], sha256=unit['sha256']))
                check('provenance-object-bytes-' + stage, corrupt_stage_object)

            with tempfile.TemporaryDirectory(prefix='source-sdk-outside-') as outside:
                outside_path = Path(outside) / 'outside-allowed-roots.txt'
                assert not outside_path.resolve().is_relative_to(ROOT)
                outside_path.write_text('real input outside ROOT and buildDirectory\n', encoding='utf-8')

                def add_outside_input(test):
                    item = dict(record(outside_path, ROOT), roles=['build_rule'])
                    source(test)['inputs'].append(copy.deepcopy(item))
                    fixture.build(test, lambda build: build['provenance']['inputs'].append(item))

                check('provenance-input-outside-allowed-roots', add_outside_input)
                if 'gate' in original_build.get('stages_run', []):
                    check('optional-input-outside-allowed-roots', lambda test: fixture.build(test,
                          lambda build: build['provenance']['optional_inputs'].append(dict(
                              path=(Path(outside) / 'absent-optional.json').as_posix(), role='build_rule', present=False))))

    optional_preserved = all((ROOT / item['path']).is_file() == item['present'] for item in original_optional)
    preserved = optional_preserved and all(record(checked(item, ROOT, original_build_root), ROOT) == item for item in original.values())
    report = dict(passed=preserved and all(item['passed'] for item in results),
                  cases=len(results), results=results, candidate=candidate.relative_to(ROOT).as_posix(),
                  manifestSha256=record(release_path, ROOT)['sha256'], originalInputsPreserved=preserved,
                  retainedOriginalInputs=[original[item['path']] for item in original_retained],
                  optionalOriginalInputs=original_optional, optionalInputStatesPreserved=optional_preserved,
                  provenanceSchema=original_build.get('provenance', {}).get('schema'),
                  translationUnits=len(original_build.get('provenance', {}).get('translation_units', [])),
                  deviceAccess=False, machineCodeExecuted=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'], cases=len(results),
                         failures=[item['name'] for item in results if not item['passed']],
                         originalInputsPreserved=preserved, deviceAccess=False)))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
