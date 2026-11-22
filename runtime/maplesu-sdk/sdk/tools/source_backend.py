"""Build the paired backend through the existing runtime CMake target."""
from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import shutil
import sys

import sdk_common as S
import source_provenance as P


def command_arguments(row: dict) -> list[str]:
    if row.get('arguments'):
        return list(row['arguments'])
    if sys.platform != 'win32':
        return shlex.split(row['command'])
    # CMake emits Windows command-line quoting, including embedded quotes in
    # -I/-D arguments. shlex(posix=False) splits these incorrectly at spaces.
    import ctypes
    from ctypes import wintypes
    count = ctypes.c_int()
    split = ctypes.WinDLL('shell32', use_last_error=True).CommandLineToArgvW
    split.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    split.restype = ctypes.POINTER(wintypes.LPWSTR)
    values = split(row['command'], ctypes.byref(count))
    if not values:
        raise ctypes.WinError(ctypes.get_last_error())
    free = ctypes.WinDLL('kernel32', use_last_error=True).LocalFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = ctypes.c_void_p
    try:
        return [values[index] for index in range(count.value)]
    finally:
        free(ctypes.cast(values, ctypes.c_void_p))


def compiler_target(compiles: list[dict]) -> str:
    targets = [[arg.removeprefix('--target=') for arg in command_arguments(row)
                if arg.startswith('--target=')] for row in compiles]
    if not targets or any(len(row) != 1 for row in targets) or len({row[0] for row in targets}) != 1:
        raise ValueError('backend compile commands have no single compiler target')
    return targets[0][0]


def build_kernel_bundle(output: Path, *, source_618: Path | None,
                        objtree_618: Path | None, toolchain_618: Path | None) -> dict:
    """Run the maintained six-family Kbuild and contract tools in this output."""
    prepared = {'--kernel-source-618': source_618, '--kernel-objtree-618': objtree_618,
                '--kernel-toolchain-618': toolchain_618}
    missing = [name for name, path in prepared.items() if path is None or not Path(path).is_dir()]
    if missing:
        raise ValueError('six-kernel source build needs prepared directories: ' + ', '.join(missing))
    output = output.resolve()
    logs = output / 'logs'
    logs.mkdir(parents=True, exist_ok=True)
    scripts = S.REPO_ROOT / 'scripts'
    commands = []

    def run(label, argv):
        done = S.run(argv, cwd=S.REPO_ROOT)
        S.write_text(logs / (label + '.stdout.txt'), done.stdout)
        S.write_text(logs / (label + '.stderr.txt'), done.stderr)
        commands.append({'label': label, 'argv': list(map(str, argv)), 'exitCode': done.returncode})
        if done.returncode:
            raise ValueError('kernel ' + label + ' failed: ' + (done.stderr or done.stdout)[-3000:])

    build_receipt = output / 'kernel-build.json'
    run('kbuild', [sys.executable, scripts / 'tests/test-ultra-policy-kernel.py',
        '--output', output, '--save', build_receipt, '--source-618', source_618,
        '--objtree-618', objtree_618, '--toolchain-618', toolchain_618])
    built = json.loads(build_receipt.read_text(encoding='utf-8'))
    if not built['sourcesUnchanged'] or built['hostTests']['exitCode'] or any(
            row['exitCode'] for row in built['results']):
        raise ValueError('kernel source build receipt reports failure')
    directories = [output / row['kernel'] for row in built['results']]
    inputs = [scripts / name for name in ('tests/test-ultra-policy-kernel.py',
        'build-ultra-policy-config-declarations.py', 'policy_config_declarations.py',
        'build-ultra-policy-config-equivalence.py', 'build-ultra-policy-compatibility.py',
        'build-ultra-policy-bundles.py', 'collect-ultra-policy-kbuild-inputs.py',
        'policy_btf_abi.py', 'policy_payload_inspect.py')]
    bundles = []
    for directory in directories:
        compatibility = declaration = None
        if (directory / 'vmlinux.btf').is_file():
            run(directory.name + '-compatibility', [sys.executable,
                scripts / 'build-ultra-policy-compatibility.py', directory])
            if directory.name != 'android17-6.18':
                run(directory.name + '-declarations', [sys.executable,
                    scripts / 'build-ultra-policy-config-declarations.py', directory])
                declaration = P.file_record(directory / 'config-declarations.json', S.REPO_ROOT)
                run(directory.name + '-compatibility-declarations', [sys.executable,
                    scripts / 'build-ultra-policy-compatibility.py', directory])
            path = directory / 'kernel-compatibility.json'
            contract = json.loads(path.read_text(encoding='utf-8'))
            compatibility = P.file_record(path, S.REPO_ROOT)
            inputs += [directory / name for name in contract['inputSha256']]
        inputs += [path for path in directory.iterdir() if path.is_file() and (
            path.name.endswith(('.cmd', '.mod', '.c', '.S', '.h')) or path.name in (
                'policy-view.so', 'compiled-layout.json', 'target-identity.json', 'System.map',
                'target.config', 'vmlinux.btf', 'kernel-compatibility.json',
                'config-declarations.json', 'config-equivalence.json'))]
        bundles.append({'directory': directory.as_posix(), 'compatibility': compatibility,
                        'declaration': declaration})
    dependency_receipt = output / 'kernel-build-inputs.json'
    run('kbuild-inputs', [sys.executable, scripts / 'collect-ultra-policy-kbuild-inputs.py',
        *directories, '--output', dependency_receipt, '--source-618', source_618,
        '--objtree-618', objtree_618, '--toolchain-618', toolchain_618])
    dependencies = json.loads(dependency_receipt.read_text(encoding='utf-8'))
    if dependencies.get('schema') != 'maplesu-kernel-kbuild-inputs/1' or not dependencies.get('inputs'):
        raise ValueError('kernel compiler dependency receipt is incomplete')
    inputs.append(dependency_receipt)
    for item in dependencies['inputs']:
        path = S.REPO_ROOT / item['path']
        if P.file_record(path, S.REPO_ROOT) != item:
            raise ValueError('kernel compiler dependency input changed: ' + str(path))
        inputs.append(path)
    bundle = output / 'policy-bundles.cpp'
    run('bundle', [sys.executable, scripts / 'build-ultra-policy-bundles.py',
                  *directories, '--output', bundle])
    contract_receipt = output / 'kernel-contracts.json'
    S.write_json(contract_receipt, {'schema': 'maplesu-kernel-source-contracts/1',
        'commands': commands, 'inputs': [P.file_record(path, S.REPO_ROOT)
                                       for path in sorted(set(inputs))], 'bundles': bundles,
        'dependencyReceipt': P.file_record(dependency_receipt, S.REPO_ROOT)})
    metadata_path = bundle.with_suffix('.json')
    metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    metadata.update(kernelBuildReceipt=P.file_record(build_receipt, S.REPO_ROOT),
                    kernelContractReceipt=P.file_record(contract_receipt, S.REPO_ROOT))
    S.write_json(metadata_path, metadata)
    return {'bundle': S.rel(bundle), 'kernelBuildReceipt': metadata['kernelBuildReceipt'],
            'kernelContractReceipt': metadata['kernelContractReceipt'], 'commands': commands}


def bundle_inputs(bundle: Path) -> list[tuple[Path, str]]:
    """Retain the generator's exact kernel-source and artifact input closure."""
    metadata = bundle.with_suffix('.json')
    data = json.loads(metadata.read_text(encoding='utf-8'))
    if S.sha256_file(bundle) != data['generatedSourceSha256']:
        raise ValueError('policy bundle source differs from its generator receipt')
    inputs = [(bundle, 'generated_source'), (metadata, 'manifest')]
    generator = S.REPO_ROOT / 'scripts/build-ultra-policy-bundles.py'
    profiles = S.REPO_ROOT / 'runtime/ultra/policy/kernel_compatibility_profiles.json'
    if data.get('generatorSha256') != S.sha256_file(generator):
        raise ValueError('policy bundle generator changed; regenerate the bundle')
    if data.get('profilePolicySha256') != S.sha256_file(profiles):
        raise ValueError('policy bundle config profile policy changed; regenerate the bundle')
    inputs += [(generator, 'build_script'), (profiles, 'build_rule')]

    def checked(record, role):
        path = (S.REPO_ROOT / record['path']).resolve()
        if path.stat().st_size != record['size'] or S.sha256_file(path) != record['sha256']:
            raise ValueError('policy bundle receipt input changed: ' + str(path))
        inputs.append((path, role))
        return path

    for key in ('kernelBuildReceipt', 'kernelContractReceipt'):
        if key not in data:
            raise ValueError('policy bundle lacks actual ' + key)
    built = json.loads(checked(data['kernelBuildReceipt'], 'manifest').read_text(encoding='utf-8'))
    contracts = json.loads(checked(data['kernelContractReceipt'], 'manifest').read_text(encoding='utf-8'))
    if (built.get('sourcesUnchanged') is not True or not built.get('sourceSha256')
            or built.get('hostTests', {}).get('exitCode') != 0
            or len(built.get('results', [])) != 6 or any(row.get('exitCode') != 0 for row in built['results'])):
        raise ValueError('policy bundle Kbuild receipt is not a successful six-family source build')
    if (contracts.get('schema') != 'maplesu-kernel-source-contracts/1' or not contracts.get('inputs')
            or not contracts.get('commands')
            or any(row.get('exitCode') != 0 or not row.get('argv') for row in contracts['commands'])):
        raise ValueError('policy bundle contract command receipt is incomplete')
    for item in contracts['inputs']:
        checked(item, 'kernel_build_input')
    if 'dependencyReceipt' not in contracts:
        raise ValueError('policy bundle lacks actual kernel compiler dependency receipt')
    dependencies = json.loads(checked(contracts['dependencyReceipt'], 'manifest').read_text(encoding='utf-8'))
    if dependencies.get('schema') != 'maplesu-kernel-kbuild-inputs/1' or not dependencies.get('inputs'):
        raise ValueError('policy bundle kernel compiler dependency receipt is incomplete')
    for item in dependencies['inputs']:
        checked(item, 'kernel_build_input')
    compiled = {row['kernel']: row for row in built['results']}
    contracted = {Path(row['directory']).resolve(): row for row in contracts['bundles']}
    directories = [Path(row['directory']).resolve() for row in data['bundles']]
    if (len(set(directories)) != 6 or {path.name for path in directories} != set(compiled)
            or set(directories) != set(contracted) or 'android17-6.18' not in compiled):
        raise ValueError('policy bundle Kbuild/contract family coverage differs')
    for name, digest in built['sourceSha256'].items():
        path = S.REPO_ROOT / name
        if S.sha256_file(path) != digest:
            raise ValueError('policy bundle Kbuild source changed: ' + name)
        inputs.append((path, 'kernel_source'))
    sources = data['kernelSourceSha256']
    if not sources or not data['bundles']:
        raise ValueError('policy bundle has no kernel source closure')
    for name, digest in sources.items():
        path = S.REPO_ROOT / name
        if S.sha256_file(path) != digest or built['sourceSha256'].get(name) != digest:
            raise ValueError('policy bundle kernel source changed: ' + name)
        inputs.append((path, 'kernel_source'))
    for row in data['bundles']:
        directory = Path(row['directory']).resolve()
        payload = compiled[directory.name].get('picPayload', {})
        image = directory / 'policy-view.so'
        if (payload.get('passed') is not True or payload.get('bytes') != image.stat().st_size
                or payload.get('sha256') != S.sha256_file(image)):
            raise ValueError('policy bundle differs from its actual Kbuild payload')
        for name, key in (('kernel-compatibility.json', 'compatibility'),
                          ('config-declarations.json', 'declaration')):
            path, item = directory / name, contracted[directory][key]
            if path.is_file() != (item is not None) or (item is not None and checked(
                    item, 'kernel_build_input') != path):
                raise ValueError('policy bundle contract selection differs: ' + str(path))
        if (directory / 'vmlinux.btf').is_file() and contracted[directory]['compatibility'] is None:
            raise ValueError('policy bundle BTF input lacks its compiled compatibility contract')
        if contracted[directory]['compatibility'] is not None:
            contract = json.loads((directory / 'kernel-compatibility.json').read_text(encoding='utf-8'))
            for name, digest in contract['inputSha256'].items():
                path = directory / name
                if S.sha256_file(path) != digest:
                    raise ValueError('policy bundle compatibility input changed: ' + str(path))
                inputs.append((path, 'kernel_build_input'))
            policy = json.loads(profiles.read_text(encoding='utf-8'))
            for profile in policy['profilesBySeries'].get(contract['kernelSeries'], []):
                variant = {key: value for key, value in profile.items()
                           if key in contract['config'] and contract['config'][key] != value}
                if variant and variant not in contract['equivalentConfigs']:
                    raise ValueError('policy bundle lacks compiler-verified config profile')
        for name, digest in row['sourceSha256'].items():
            path = directory / name
            if S.sha256_file(path) != digest:
                raise ValueError('policy bundle artifact changed: ' + str(path))
            inputs.append((path, 'kernel_build_input'))
        for name in ('kernel-compatibility.json', 'config-declarations.json', 'vmlinux.btf',
                     'compiled-layout.h', 'compile_commands.json'):
            path = directory / name
            if path.is_file():
                inputs.append((path, 'kernel_build_input'))
    return inputs


def parse_dependencies(text: str, build: Path) -> dict[str, list[Path]]:
    objects: dict[str, list[Path]] = {}
    current = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith('    '):
            if current is None:
                raise ValueError('compiler dependency has no object')
            path = Path(line.strip())
            objects[current].append(path.resolve() if path.is_absolute() else (build / path).resolve())
        else:
            match = re.fullmatch(r'(.+): #deps (\d+), deps mtime \d+ \(VALID\)', line)
            if not match:
                raise ValueError('invalid compiler dependency entry: ' + line)
            current = match[1].replace('\\', '/')
            objects[current] = []
    return objects


def build_backend(tc: S.Toolchain, sdk: Path, bundle: Path, output: Path,
                  *, cmake: Path | None = None, jobs: int = 4) -> dict:
    scripts = S.REPO_ROOT / 'scripts'
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    from policy_backend_identity import describe_backend, write_identity

    bundle = Path(bundle).resolve()
    input_snapshots = P.snapshot_inputs([(Path(__file__), 'build_script'),
        (Path(S.__file__), 'build_script'), (Path(P.__file__), 'build_script'),
        (scripts / 'policy_backend_identity.py', 'build_script'),
        (S.REPO_ROOT / 'runtime/CMakeLists.txt', 'build_rule'),
        (sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a', 'sdk_archive'),
        (bundle, 'generated_source'), (bundle.with_suffix('.json'), 'manifest')], S.REPO_ROOT)
    inputs = bundle_inputs(bundle)
    input_snapshots += P.snapshot_inputs(inputs, S.REPO_ROOT)
    output = Path(output).resolve()
    build, logs, pairing = output / 'cmake', output / 'logs', output / 'pairing'
    logs.mkdir(parents=True, exist_ok=True)
    pairing.mkdir(exist_ok=True)
    scratch = output / 'scratch'
    scratch.mkdir(exist_ok=True)
    suffix = '.exe' if sys.platform == 'win32' else ''
    cmake = Path(cmake) if cmake else tc.ndk.parents[1] / 'cmake/3.22.1/bin' / ('cmake' + suffix)
    ninja = cmake.with_name('ninja' + suffix)
    commands = []

    def run(label, argv):
        done = S.run(argv, cwd=S.REPO_ROOT, env={'TEMP': str(scratch), 'TMP': str(scratch)})
        S.write_text(logs / (label + '.stdout.txt'), done.stdout)
        S.write_text(logs / (label + '.stderr.txt'), done.stderr)
        commands.append({'label': label, 'argv': list(map(str, argv)), 'exit_code': done.returncode})
        if done.returncode:
            raise ValueError('backend ' + label + ' failed: ' + (done.stderr or done.stdout)[-3000:])
        return done.stdout

    run('configure', [cmake, '-S', S.REPO_ROOT / 'runtime', '-B', build, '-G', 'Ninja',
        '-DCMAKE_MAKE_PROGRAM=' + ninja.as_posix(),
        '-DCMAKE_TOOLCHAIN_FILE=' + (tc.ndk / 'build/cmake/android.toolchain.cmake').as_posix(),
        '-DANDROID_ABI=arm64-v8a', '-DANDROID_PLATFORM=android-31',
        '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -g0',
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DMAPLESU_ULTRA_SDK_DIRECTORY=' + sdk.as_posix(),
        '-DMAPLESU_POLICY_BUNDLE_SOURCE=' + bundle.as_posix()])
    input_snapshots += P.snapshot_inputs([(build / 'compile_commands.json', 'compiler_commands')], S.REPO_ROOT)
    compiles = json.loads((build / 'compile_commands.json').read_text(encoding='utf-8'))
    # Scope the scan to the two targets actually linked by this backend. All
    # target objects must be newly emitted, rather than inherited from Ninja's
    # cache with no observed compile boundary in this invocation.
    compiles = [row for row in compiles if any(target in
                (row.get('command') or ' '.join(row.get('arguments') or [])) for target in
                ('maplesu_policy_boot.dir', 'maplesu_kernel_layout.dir'))]
    compile_inputs = {}
    for row in compiles:
        argv = command_arguments(row)
        if argv.count('-o') != 1 or argv.count('-c') != 1 or any(value.startswith('@') for value in argv):
            raise ValueError('backend compiler command is not an explicit single compilation')
        cwd = Path(row['directory']).resolve()
        source = Path(row['file'])
        source = source.resolve() if source.is_absolute() else (cwd / source).resolve()
        name = argv[argv.index('-o') + 1].replace('\\', '/')
        obj = Path(name)
        obj = obj.resolve() if obj.is_absolute() else (cwd / obj).resolve()
        if obj.exists():
            raise ValueError('backend compile-start provenance requires a new object output: ' + str(obj))
        if name in compile_inputs:
            raise ValueError('backend compiler commands share one object output')
        compile_inputs[name] = (source, obj, P.precompile_snapshot(argv, source, obj, cwd, S.REPO_ROOT,
            include_system=True, excluded_roots=(tc.ndk,)))
    backend = build / 'libmaplesu_policy_boot.so'
    backend.unlink(missing_ok=True)
    run('build', [ninja, '-C', build, '-v', '-j' + str(max(1, jobs)), 'maplesu_policy_boot'])
    run('link-commands', [ninja, '-C', build, '-t', 'commands', 'maplesu_policy_boot'])
    dependencies = parse_dependencies(run('dependencies', [ninja, '-C', build, '-t', 'deps']), build)
    units = []
    for name, (source, obj, precompile) in compile_inputs.items():
        paths = [path for path in dependencies.pop(name) if not path.is_relative_to(tc.ndk)]
        if source not in paths:
            raise ValueError('backend compiler dependency omits its source')
        observed = [P.file_record(path, S.REPO_ROOT) for path in dict.fromkeys(paths)]
        units.append({'source': S.rel(source), 'build_source': S.rel(source),
            'object': S.rel(obj), 'bytes': obj.stat().st_size, 'sha256': S.sha256_file(obj),
            'stage': 'source-backend', 'program': 'maplesu_policy_boot',
            'dependencies': observed,
            'dependency_kind': 'compiler-mmd', 'dependency_complete': True, 'dependency_errors': [],
            **P.precompile_comparison(precompile, source, obj, observed, S.REPO_ROOT)})
    if dependencies or not units:
        raise ValueError('backend compiler dependency coverage differs from compile commands')
    identity = describe_backend(backend)
    shutil.copyfile(backend, pairing / identity['fileName'])
    S.write_json(pairing / 'backend-identity.json', identity)
    write_identity(pairing / 'environment_backend_identity.h', identity)
    inputs += [(Path(__file__), 'build_script'), (Path(S.__file__), 'build_script'),
               (Path(P.__file__), 'build_script'), (scripts / 'policy_backend_identity.py', 'build_script'),
               (S.REPO_ROOT / 'runtime/CMakeLists.txt', 'build_rule'),
               (build / 'compile_commands.json', 'compiler_commands'),
               (sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a', 'sdk_archive')]
    toolchain = P.toolchain_record(tc, S.REPO_ROOT)
    toolchain['target'] = compiler_target(compiles)
    proof = P.build_receipt(units, inputs, S.REPO_ROOT, toolchain, input_snapshots=input_snapshots)
    if not proof['closure_complete']:
        raise ValueError('backend source closure is incomplete: ' + '; '.join(proof['incomplete_reasons']))
    report = {'schema': 'maplesu-sdk-source-backend/1', 'out': S.rel(backend),
              'file': P.file_record(backend, S.REPO_ROOT),
              'identity': identity, 'pairing': S.rel(pairing), 'bundle': S.rel(bundle),
              'compileCommands': P.file_record(build / 'compile_commands.json', S.REPO_ROOT),
              'commands': commands, 'compile_commands': compiles, 'provenance': proof}
    S.write_json(output / 'backend-build.json', report)
    return report


def verify_final_archive(tc: S.Toolchain, backend: dict, helper: dict, archive: Path,
                         installers: set[str], output: Path) -> dict:
    """Prove the complete archive preserves pairing and has no payload cycle."""
    output.mkdir(parents=True, exist_ok=True)
    backend_build = Path(S.REPO_ROOT / backend['out']).parent
    link = (backend_build.parent / 'logs/link-commands.stdout.txt').read_text(encoding='utf-8').splitlines()[-1]
    if sys.platform == 'win32':
        prefix, suffix = 'cmd.exe /C "cd . && ', ' && cd ."'
        if not link.startswith(prefix) or not link.endswith(suffix):
            raise ValueError('unexpected backend linker wrapper')
        raw = shlex.split(link[len(prefix):-len(suffix)], posix=False)
        backend_argv = [value[1:-1] if value.startswith('"') and value.endswith('"') else value for value in raw]
    else:
        link = link.removeprefix(': && ').removesuffix(' && :')
        backend_argv = shlex.split(link)
    old_archive = Path(S.REPO_ROOT / helper['sdkArchive']['source']).resolve()
    archive_arguments = [i for i, value in enumerate(backend_argv)
                         if value.endswith('.a') and Path(value).resolve() == old_archive]
    if len(archive_arguments) != 1:
        raise ValueError('backend link does not select its source bootstrap archive once')
    backend_argv[archive_arguments[0]] = str(archive)
    helper_argv = list(helper['linkCommand'])
    if helper_argv.count(str(old_archive)) != 1:
        raise ValueError('helper link does not select its source bootstrap archive once')
    helper_argv[helper_argv.index(str(old_archive))] = str(archive)
    results = {}
    for name, argv, cwd, original in (
            ('backend', backend_argv, backend_build, backend['identity']['sha256']),
            ('helper', helper_argv, S.REPO_ROOT, helper['surface']['sha256'])):
        target = output / (name + '.elf')
        argv[argv.index('-o') + 1] = str(target)
        trace = output / (name + '-why-extract.tsv')
        argv += ['-Wl,--why-extract=' + trace.as_posix()]
        done = S.run(argv, cwd=cwd)
        S.write_text(output / (name + '-link.log'), S.fmt_cmd(argv) + '\n' + done.stdout + done.stderr)
        if done.returncode:
            raise ValueError(name + ' final archive link failed: ' + done.stderr[-3000:])
        if name == 'helper':
            strip = tc.bin_dir / ('llvm-strip.exe' if sys.platform == 'win32' else 'llvm-strip')
            stripped = S.run([strip, '--strip-all', target])
            if stripped.returncode:
                raise ValueError('final helper strip failed: ' + stripped.stderr)
        digest = S.sha256_file(target)
        selected = sorted(set(re.findall(r'libkernel_module_kit_static\.a\(([^)]+)\)',
                                        trace.read_text(encoding='utf-8'))))
        if digest != original or not selected or installers.intersection(selected):
            raise ValueError(name + ' final archive changed pairing or selected payload installers')
        results[name] = {'file': P.file_record(target, S.REPO_ROOT), 'identical': True,
                         'trace': P.file_record(trace, S.REPO_ROOT), 'selected_sdk_members': selected,
                         'installers_selected': []}
    return {'passed': True, 'archive': P.file_record(archive, S.REPO_ROOT), **results}
