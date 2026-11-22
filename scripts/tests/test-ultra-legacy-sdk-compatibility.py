"""Verify the legacy module ABI against the released SDK, without kernel operations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--adb', type=Path)
    parser.add_argument('--serial')
    args = parser.parse_args()
    if args.adb and not args.serial:
        parser.error('--adb requires an explicit --serial')
    repo = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    archive = repo / 'runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a'
    release = json.loads((repo / 'runtime/maplesu-sdk/SDK-RELEASE.json').read_text())
    baseline = args.baseline or repo / 'runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a'
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest(archive) == release['archive']['sha256'], 'release archive identity mismatch'

    def run(command, name, check=True, timeout=60):
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=timeout)
        (build / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        if check and result.returncode:
            raise RuntimeError(name + ' failed:\n' + (result.stdout + result.stderr)[-5000:])
        return result

    def definitions(path, label):
        result = run([tool / 'llvm-nm.exe', '--defined-only', '--extern-only', path], label)
        symbols = {}
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3 and len(fields[-2]) == 1:
                symbol, kind = fields[-1], fields[-2]
                if symbol not in symbols or kind not in ('W', 'w', 'V', 'v'):
                    symbols[symbol] = kind
        assert symbols, 'empty symbol inventory'
        return symbols

    old, current = definitions(baseline, 'baseline-symbols'), definitions(archive, 'sdk-symbols')
    strong = {symbol for symbol, kind in old.items() if kind not in ('W', 'w', 'V', 'v')}
    removed = sorted(strong - current.keys())
    assert not removed, 'missing legacy definitions: ' + ', '.join(removed[:10])
    public_prefixes = ('_ZN13kernel_module', '_ZN7maplesu3sdk', '_ZN11kernel_root',
                       '_ZNK13kernel_module', '_ZNK7maplesu3sdk', '_ZNK11kernel_root',
                       '__get_current_module_', '__set_current_module_', '__maplesu_module_')
    missing_public = sorted(symbol for symbol in old.keys() - current.keys()
                            if symbol.startswith(public_prefixes))
    assert not missing_public, 'missing legacy SDK API: ' + ', '.join(missing_public[:10])
    fixture = repo / 'runtime/tests/pro_legacy_sdk_compatibility_test.cpp'
    binary = build / 'legacy-sdk-contract.test'
    run([tool / 'clang++.exe', '--target=aarch64-linux-android26', '-std=c++20',
         '-fPIE', '-pie', '-fno-rtti', '-ffunction-sections', '-fdata-sections',
         '-Wno-packed-non-pod', '-Wl,--gc-sections', '-static-libstdc++',
         '-I' + str(repo / 'runtime/maplesu-sdk/include'), fixture, archive,
         '-ldl', '-llog', '-lz', '-o', binary], 'compile')
    binary_symbols = definitions(binary, 'fixture-symbols')
    required = [
        '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x6d\x61\x69\x6e\x5f\x31\x38\x66\x64\x66\x33\x39\x33\x38\x38\x35\x33\x36\x33\x37\x31\x32\x33\x34\x39\x65\x66\x33\x64\x65\x35\x34\x31\x31\x62\x64\x35',
        '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x6f\x6e\x5f\x69\x6e\x73\x74\x61\x6c\x6c\x5f\x6b\x36\x4a\x6b\x69\x62\x72\x6a\x55\x77\x7a\x58\x46\x70\x73\x68\x76\x46\x75\x49\x77\x64\x55\x4e\x52\x50\x34\x66\x59\x74\x4c\x41',
        '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x6f\x6e\x5f\x75\x6e\x69\x6e\x73\x74\x61\x6c\x6c\x5f\x65\x70\x6d\x6f\x73\x6f\x38\x35\x68\x77\x34\x77\x31\x72\x7a\x6a\x61\x67\x69\x75\x7a\x64\x6d\x6e\x79\x71\x61\x6d\x6b\x37\x65\x70',
        '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x77\x65\x62\x5f\x75\x69\x5f\x6d\x61\x69\x6e\x5f\x63\x65\x62\x36\x66\x30\x62\x62\x65\x62\x65\x35\x63\x38\x39\x37\x38\x65\x62\x32\x31\x36\x38\x37\x39\x39\x61\x61\x30\x63\x61\x34',
        '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x6c\x61\x73\x74\x5f\x77\x65\x62\x5f\x75\x69\x5f\x73\x65\x72\x76\x65\x72\x5f\x70\x6f\x72\x74\x5f\x64\x62\x32\x61\x32\x62\x65\x62\x65\x32\x62\x31\x39\x30\x34\x38\x32\x61\x64\x30\x61\x63\x37\x33\x39\x39\x36\x63\x37\x62\x38\x36',
        '\x5f\x5f\x73\x6b\x72\x6f\x6f\x74\x5f\x6d\x6f\x64\x75\x6c\x65\x5f\x62\x65\x66\x6f\x72\x65\x5f\x73\x65\x72\x76\x65\x72\x5f\x65\x78\x69\x74\x5f\x61\x63\x74\x69\x6f\x6e\x5f\x38\x31\x61\x39\x38\x35\x33\x35\x66\x31\x32\x63\x39\x36\x61\x30\x62\x33\x65\x34\x35\x37\x37\x32\x37\x37\x30\x35\x65\x34\x34\x63',
    ]
    assert all(symbol in binary_symbols for symbol in required), 'missing legacy fixture exports'
    report = {
        'sdkVersion': '5.1.0', 'sdkBuildId': release['sdkBuildId'], 'archiveSha256': digest(archive),
        'baselineSha256': digest(baseline), 'baselineDefinitions': len(old),
        'candidateDefinitions': len(current), 'preservedStrongDefinitions': len(strong),
        'removedStrongDefinitions': removed, 'removedPublicSdkDefinitions': missing_public,
        'legacyEntryPoints': required,
        'fixtureSourceSha256': digest(fixture), 'fixtureSha256': digest(binary),
        'deviceVerification': False, 'kernelOperations': False,
        'webUiBoundary': 'modeled server implementation; real legacy header wrappers',
    }
    if args.adb:
        adb = [args.adb, '-s', args.serial]
        remote = '/data/local/tmp/maplesu-legacy-sdk-compat-' + str(os.getpid())
        run([*adb, 'shell', 'mkdir', remote], 'device-mkdir')
        try:
            run([*adb, 'push', binary, remote + '/fixture'], 'device-push')
            run([*adb, 'shell', 'chmod', '700', remote + '/fixture'], 'device-chmod')
            result = run([*adb, 'shell', remote + '/fixture'], 'device-run')
            checks = [line for line in result.stdout.splitlines() if line.startswith('PASS ')]
            assert len(checks) == 5, 'incomplete legacy callback verification'
            report.update(deviceVerification=True, checks=checks, deviceExitCode=result.returncode)
            print(result.stdout, end='')
        finally:
            run([*adb, 'shell', 'rm', remote + '/fixture'], 'device-cleanup', check=False)
            run([*adb, 'shell', 'rmdir', remote], 'device-rmdir', check=False)
    assert digest(archive) == report['archiveSha256'], 'SDK changed during verification'
    (build / 'legacy-sdk-compatibility.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS legacy strong SDK definitions preserved:', len(strong))
    print('PASS legacy entry, callbacks and WebUI symbols linked against SDK 5.1.0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
