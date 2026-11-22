"""Run only the actual SDK live-BTF name boundary scenarios in the existing TU harness."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CASES = ['live-name-offset-wrap', 'live-name-offset-errptr', 'live-name-edge-terminated',
         'live-name-edge-unterminated', 'live-name-read-error-retry',
         'live-name-long', 'live-name-long-prefix', 'live-name-tail-terminated',
         'live-name-tail-unterminated', 'live-name-size-u32-max', 'live-name-one-byte-empty',
         'live-name-zero-size', 'live-name-boundary-nonnull', 'live-name-boundary-errptr',
         'live-name-boundary-mismatch', 'live-name-boundary-error', 'live-name-boundary-wrap',
         'live-name-boundary-mid-error', 'live-name-boundary-mid-errptr']


def compile_ndk(out):
    sdk = ROOT / 'runtime/maplesu-sdk/sdk'
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(sdk / 'tools'))
    import sdk_common as S

    def identity(path):
        path = path.resolve()
        data = path.read_bytes()
        return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    manifest = sdk / 'manifest/0028_module_base_kernel_btf_resolver.o.json'
    entry = json.loads(manifest.read_text(encoding='utf-8-sig'))
    source = sdk / 'src/module_base/module_base_kernel_btf_resolver.cpp'
    if entry['idx'] != 28 or str(source.relative_to(sdk)).replace('\\', '/') not in entry['sources']:
        raise ValueError('Resolver TU is absent from its member manifest')
    source_before = identity(source)
    out.mkdir(parents=True, exist_ok=True)
    compiler = S.DEFAULT_NDK / S.TOOLCHAIN_SUBDIR / 'clang++.exe'
    version = subprocess.run([str(compiler), '--version'], capture_output=True, text=True,
                             encoding='utf-8', errors='replace')
    (out / 'version.log').write_text(version.stdout + version.stderr, encoding='utf-8')
    flags = S.profile_flags(entry['flagsProfile'], 'cxx', entry.get('extraFlags', []))
    flags += ['-Wall', '-Wextra', '-I', str(sdk.parent / 'include'), '-I', str(sdk / 'include')]
    target = out / 'resolver.o'
    depfile = out / 'resolver.d'
    command = list(map(str, [compiler, *flags, '-MD', '-MF', depfile, '-MT', 'resolver-object',
                            '-c', source, '-o', target]))
    # Resolve member include paths against the SDK root, preserving the
    # manifest recipe (for example -I../../ultra/policy).
    done = subprocess.run(command, cwd=sdk, capture_output=True, text=True,
                          encoding='utf-8', errors='replace')
    (out / 'compile.log').write_text(done.stdout + done.stderr, encoding='utf-8')
    dependencies = []
    if depfile.exists():
        text = depfile.read_text(encoding='utf-8').replace('\\\n', ' ').split(':', 1)[1]
        for token in re.findall(r'(?:\\.|[^\s])+', text):
            path = Path(token.replace('\\ ', ' ').replace('\\:', ':').replace('\\#', '#'))
            dependencies.append(identity(path if path.is_absolute() else sdk / path))
    unchanged = source_before['sha256'] == identity(source)['sha256']
    dependency_paths = {row['path'].replace('\\', '/').lower() for row in dependencies}
    checks = {'versionMatches': version.returncode == 0 and S.EXPECTED_CLANG in version.stdout,
              'compileExitZero': done.returncode == 0, 'objectPresent': target.exists(),
              'sourceUnchanged': unchanged,
              'publicUmbrellaUsed': (sdk.parent / 'include/kernel_module_kit_umbrella.h').as_posix().lower() in dependency_paths,
              'privateLayoutHeaderUsed': (sdk / 'include/maplesu_kernel_layout_private.h').as_posix().lower() in dependency_paths,
              'sharedLayoutHeaderUsed': (ROOT / 'runtime/ultra/policy/kernel_layout.h').as_posix().lower() in dependency_paths,
              'noTestStubHeaders': not any('/tools/tests/' in name for name in dependency_paths)}
    passed = all(checks.values())
    receipt = {'passed': passed, 'scope': 'Actual resolver TU Android compilation only; no composed member, archive, link or device',
               'checks': checks,
               'manifest': identity(manifest), 'flagsProfile': entry['flagsProfile'],
               'extraFlags': entry.get('extraFlags', []), 'layout': entry['layout'],
               'source': source_before, 'sourceUnchanged': unchanged,
               'compiler': identity(compiler), 'version': version.stdout + version.stderr,
               'flagDefinitions': identity(sdk / 'tools/sdk_common.py'),
               'argv': command, 'cwd': str(sdk), 'exit': done.returncode,
               'dependencies': dependencies, 'object': identity(target) if target.exists() else None}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(f'NDK resolver compile: exit={done.returncode}, dependencies={len(dependencies)}, passed={passed}')
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--ndk', action='store_true', help='Compile only the actual resolver TU using its member manifest')
    args = parser.parse_args()
    command = [sys.executable, str(ROOT / 'runtime/maplesu-sdk/sdk/tools/tests/kernel_layout/run.py'),
               '--out', str(args.out.resolve()), '--sanitize']
    for case in CASES:
        command += ['--case', case]
    result = subprocess.run(command, cwd=ROOT).returncode
    if result or not args.ndk:
        return result
    return compile_ndk(args.out.resolve() / 'ndk')


if __name__ == '__main__':
    raise SystemExit(main())
