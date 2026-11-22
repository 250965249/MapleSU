"""Compare the shared Java inspector/round trip with unmodified AOSP boot tools."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
AOSP_COMMIT = 'd2bb0af5ba6d3198a3e99529c97eda1be0b5a093'
AOSP_FILES = ('include/bootimg/bootimg.h', 'mkbootimg.py', 'unpack_bootimg.py',
              'gki/generate_gki_certificate.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args):
    result = subprocess.run([str(arg) for arg in args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check_rebuilds(args, jar_hash):
    """Compare changed images with an independently generated AOSP oracle."""
    output = (args.out or ROOT / '.analysis/aosp-boot-rebuild').resolve()
    output.mkdir(parents=True, exist_ok=True)
    work = output / 'cases'
    work.mkdir()  # Preserve earlier evidence instead of overwriting it.
    commands, records = [], []

    def logged(*argv):
        argv = [str(arg) for arg in argv]
        result = subprocess.run(argv, capture_output=True, text=True,
                                encoding='utf-8', errors='replace')
        commands.append(dict(argv=argv, exitCode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        require(result.returncode == 0, f'command {len(commands)} exited {result.returncode}')
        return result.stdout

    def payload(size, seed):
        return random.Random(seed).randbytes(size)

    for version, page, image_page_flag in ((0, 2048, 3), (1, 8192, 2),
                                            (2, 16384, 3), (3, 4096, 2)):
        name = f'v{version}-p{page}'
        case = work / name
        case.mkdir()
        record = dict(case=name, checks=[], passed=False)
        records.append(record)

        def check(condition, message):
            record['checks'].append(dict(check=message, passed=bool(condition)))

        def kernel(size, seed):
            raw = bytearray(payload(size, seed))
            struct.pack_into('<QQQ', raw, 8, 0x80000, size, image_page_flag << 1)
            raw[56:60] = b'ARM\x64'
            return bytes(raw)

        components = dict(kernel=kernel(page - 17, 101 + version),
                          ramdisk=payload(page + 137, 201 + version))
        if version == 1:
            components['recovery_dtbo'] = payload(2 * page + 11, 301)
        if version == 2:
            components['second'] = payload(page + 83, 302)
            components['dtb'] = payload(page + 59, 303)
        replacement = kernel(2 * page + 19, 401 + version)
        for component, content in components.items():
            (case / component).write_bytes(content)
        (case / 'replacement-kernel').write_bytes(replacement)
        inputs = {path.name: digest(path) for path in case.iterdir() if path.is_file()}
        source, oracle = case / 'source.img', case / 'oracle.img'
        candidate, repeat = case / 'candidate.img', case / 'repeat.img'
        try:
            common = [sys.executable, args.aosp / 'mkbootimg.py', '--header_version', version,
                      '--pagesize', page, '--os_version', '13.2.1', '--os_patch_level', '2026-11',
                      '--board', 'MapleSU-fixture', '--base', '0x10000000',
                      '--kernel_offset', '0x80000', '--ramdisk_offset', '0x2000000',
                      '--second_offset', '0x3000000', '--tags_offset', '0x100',
                      '--dtb_offset', '0x4000000',
                      '--cmdline', 'maplesu.aosp.fixture=1 ' + 'x' * 750]
            for image, kernel_path in ((source, case / 'kernel'),
                                       (oracle, case / 'replacement-kernel')):
                command = common + ['--output', image, '--kernel', kernel_path]
                for component in components:
                    if component != 'kernel':
                        command.extend(['--' + component, case / component])
                logged(*command)
            source_hash = digest(source)
            rebuilt = json.loads(logged(args.java, '-jar', args.jar, 'rebuild',
                                        source, case / 'replacement-kernel', candidate))
            for image, unpacked in ((candidate, 'candidate-unpacked'), (oracle, 'oracle-unpacked')):
                logged(sys.executable, args.aosp / 'unpack_bootimg.py',
                       '--boot_img', image, '--out', case / unpacked)
            logged(args.java, '-jar', args.jar, 'rebuild', candidate,
                   case / 'replacement-kernel', repeat)
            actual, expected = candidate.read_bytes(), oracle.read_bytes()
            check(actual == expected, 'complete image equals independent AOSP writer')
            check(len(actual) == len(expected), 'output size equals AOSP oracle')
            check(digest(repeat) == digest(candidate), 'same-kernel rebuild is byte-identical')
            check(digest(source) == source_hash, 'source image is unchanged')
            check(all(digest(case / name) == sha for name, sha in inputs.items()),
                  'all component inputs are unchanged')
            check(struct.unpack_from('<I', actual, 40)[0] == version, 'header version is preserved')
            if version < 3:
                check(struct.unpack_from('<I', actual, 36)[0] == page, 'container page is preserved')
                check(actual[576:608] == expected[576:608], 'legacy ID equals AOSP oracle')
            if version in (1, 2):
                check(actual[1636:1644] == expected[1636:1644], 'DTBO offset equals AOSP oracle')
                if version == 2:
                    check(struct.unpack_from('<Q', actual, 1636)[0] == 0, 'absent DTBO has zero offset')
            allowed = [(8, 12)]
            if version < 3:
                allowed.append((576, 608))
            if version in (1, 2):
                allowed.append((1636, 1644))
            original_header = source.read_bytes()[:page]
            check(all(a == b or any(start <= i < end for start, end in allowed)
                      for i, (a, b) in enumerate(zip(original_header, actual[:page]))),
                  'all other header metadata is preserved')
            for component in ('kernel', 'ramdisk', 'second', 'recovery_dtbo', 'dtb'):
                want = replacement if component == 'kernel' else components.get(component, b'')
                for folder in ('candidate-unpacked', 'oracle-unpacked'):
                    extracted = case / folder / component
                    got = extracted.read_bytes() if extracted.exists() else b''
                    check(got == want, f'{folder}: {component} equals expected bytes')
            check((case / 'candidate-unpacked/kernel').read_bytes()[24:32] == replacement[24:32],
                  'synthetic raw Image page flags are preserved')
            check(rebuilt['kernelChanged'] and rebuilt['sourceUnchanged']
                  and rebuilt['equivalenceVerified'] and rebuilt['outputReadbackVerified'],
                  'production rebuild report confirms changed kernel and preservation')
            record['passed'] = all(item['passed'] for item in record['checks'])
            record['firstDifferentByte'] = next((i for i, (a, b) in enumerate(zip(actual, expected))
                                                  if a != b), None)
        except Exception as error:
            record['error'] = f'{type(error).__name__}: {error}'
        record['files'] = {str(path.relative_to(case)): dict(bytes=path.stat().st_size, sha256=digest(path))
                           for path in sorted(case.rglob('*')) if path.is_file()}
        print(f"{'PASS' if record['passed'] else 'FAIL'} {name}", flush=True)
    result = dict(schemaVersion=2, passed=all(record['passed'] for record in records),
                  aospCommit=AOSP_COMMIT, commands=commands, cases=records,
                  aospFiles={path: digest(args.aosp / path) for path in AOSP_FILES},
                  testScriptSha256=digest(Path(__file__)), jarSha256=jar_hash,
                  jarUnchanged=digest(args.jar) == jar_hash,
                  sourceFiles={str(path.relative_to(ROOT)): digest(path)
                               for path in sorted((ROOT / 'image-core/src/main/java').rglob('*.java'))},
                  scope='Synthetic changed-container interoperability only; no SDK packaging or device boot.')
    result['passed'] = result['passed'] and result['jarUnchanged']
    (output / 'results.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    require(result['passed'], 'AOSP rebuild interoperability failed; see ' + str(output / 'results.json'))
    print(f'PASS {len(records)} changed-image AOSP cases; report: {output / "results.json"}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--aosp', type=Path, default=ROOT / '.research/aosp-mkbootimg')
    parser.add_argument('--java', default='java')
    parser.add_argument('--jar', type=Path, default=ROOT / 'image-core/build/libs/image-core.jar')
    parser.add_argument('--rebuild-only', action='store_true', help='Run only four changed-image oracle cases')
    parser.add_argument('--out', type=Path, help='Preserved output directory for --rebuild-only')
    args = parser.parse_args()
    require(run('git', '-C', args.aosp, 'rev-parse', 'HEAD') == AOSP_COMMIT, 'AOSP commit differs')
    require(not run('git', '-C', args.aosp, 'status', '--porcelain', '--untracked-files=no'),
            'AOSP reference tools have local changes')
    jar_hash = digest(args.jar)
    if args.rebuild_only:
        check_rebuilds(args, jar_hash)
        return
    records = []
    with tempfile.TemporaryDirectory(prefix='maplesu-aosp-interop-') as directory:
        work = Path(directory)
        raw = bytearray(random.Random(20261024).randbytes(5017))
        raw[56:60] = b'ARM\x64'
        banner = b'Linux version 6.6.66-aosp-format-fixture '
        raw[80:80 + len(banner)] = banner
        for version in range(5):
            pages = (2048, 4096, 8192, 16384) if version < 3 else (4096,)
            layouts = ((False, False), (True, False)) if version < 3 else ((False, False),)
            if version in (1, 2):
                layouts += ((False, True), (True, True))
            for page in pages:
                for second_present, recovery_present in layouts:
                    for compressed in (False, True):
                        name = (f'v{version}-p{page}-second{int(second_present)}'
                                f'-dtbo{int(recovery_present)}-gzip{int(compressed)}')
                        case = work / name
                        case.mkdir()
                        payloads = {'kernel': gzip.compress(raw, mtime=0) if compressed else bytes(raw),
                                    'ramdisk': random.Random(71).randbytes(71)}
                        if second_present:
                            payloads['second'] = random.Random(53).randbytes(53)
                        if recovery_present:
                            payloads['recovery_dtbo'] = random.Random(31).randbytes(31)
                        if version == 2:
                            payloads['dtb'] = random.Random(19).randbytes(19)
                        image = case / 'boot.img'
                        command = [sys.executable, args.aosp / 'mkbootimg.py', '--header_version', version,
                                   '--pagesize', page, '--output', image]
                        for component, payload in payloads.items():
                            path = case / component
                            path.write_bytes(payload)
                            command.extend(['--' + component, path])
                        run(*command)
                        # Exercise preservation of opaque footer/partition bytes as well as components.
                        with image.open('ab') as output:
                            output.write(b'MapleSU format test trailer\x00\xff')
                        before = digest(image)
                        run(sys.executable, args.aosp / 'unpack_bootimg.py', '--boot_img', image,
                            '--out', case / 'unpacked')
                        report = json.loads(run(args.java, '-jar', args.jar, 'inspect', image))
                        verified = json.loads(run(args.java, '-jar', args.jar, 'roundtrip', image))
                        require(report['headerVersion'] == version and report['pageSize'] == page,
                                name + ': header layout differs')
                        require(report['sha256'] == before and verified['image'] == report,
                                name + ': image identity differs')
                        require(verified['decodedKernelSize'] == len(raw)
                                and verified['decodedKernelSha256'] == hashlib.sha256(raw).hexdigest(),
                                name + ': decoded kernel differs')
                        require(verified['containerByteIdentical'] is True
                                and verified['codecRoundTripVerified'] is True
                                and verified['sourceUnchanged'] is True
                                and verified['flashableCandidate'] is False, name + ': verification differs')
                        image_bytes = image.read_bytes()
                        fields = {'kernel': 'kernel', 'ramdisk': 'ramdisk', 'second': 'second',
                                  'recovery_dtbo': 'recoveryDtbo', 'dtb': 'dtb'}
                        for component, field in fields.items():
                            payload = payloads.get(component, b'')
                            require(report[field + 'Size'] == len(payload), name + ': size differs: ' + component)
                            if payload:
                                offset = report[field + 'Offset']
                                require(image_bytes[offset:offset + len(payload)] == payload,
                                        name + ': Java component position differs: ' + component)
                                require((case / 'unpacked' / component).read_bytes() == payload,
                                        name + ': AOSP component differs: ' + component)
                        require(digest(image) == before, name + ': source changed')
                        records.append({'case': name, 'sha256': before})
    require(digest(args.jar) == jar_hash, 'JAR changed during validation')
    result = {'schemaVersion': 1, 'passed': True, 'aospCommit': AOSP_COMMIT,
              'aospFiles': {path: digest(args.aosp / path) for path in AOSP_FILES},
              'testScriptSha256': digest(Path(__file__)), 'jarSha256': jar_hash,
              'cases': records, 'scope': 'Synthetic format interoperability only; no kernel patch or boot validation.'}
    destination = ROOT / '.analysis/aosp-boot-interop.json'
    destination.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(f'PASS {len(records)} AOSP boot format interoperability cases')


if __name__ == '__main__':
    main()
