"""Compile the production v4 writer and verify file-only init_boot reconstruction.

The prepared ramdisk is data supplied by the caller. This does not install a
loader or kernel bridge and never writes device partitions.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path):
    return {'bytes': path.stat().st_size, 'sha256': digest(path)}


def entries(report):
    return Counter((entry['path'], entry['mode'], entry['size'], entry['sha256'])
                   for entry in report['entries'])


def run(args):
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {'schemaVersion': 1, 'passed': False, 'partitionWrites': False,
              'kernelBridgeInstalled': False, 'executableEntryInstalled': False,
              'deviceBootTestPerformed': False, 'readyToFlash': False, 'commands': []}
    sources = sorted((ROOT / 'image-core/src/main/java').rglob('*.java'))
    tests = sorted((ROOT / 'image-core/src/test/java').rglob('*.java'))
    inputs = [args.init_boot, *sources, *tests]
    if args.prepared_ramdisk:
        inputs.append(args.prepared_ramdisk)
    if args.boot:
        inputs.append(args.boot)
    before = {str(path.resolve()): identity(path) for path in inputs}

    def command(name, argv):
        process = subprocess.run([str(value) for value in argv], capture_output=True, timeout=120)
        (output / (name + '.stdout')).write_bytes(process.stdout)
        (output / (name + '.stderr')).write_bytes(process.stderr)
        record['commands'].append({'name': name, 'argv': [str(value) for value in argv],
                                   'exitCode': process.returncode})
        if process.returncode:
            raise ValueError(name + ' returned ' + str(process.returncode))
        return process.stdout.decode('utf-8-sig')

    try:
        with tempfile.TemporaryDirectory(prefix='maplesu-initboot-', dir=args.work_directory) as temporary:
            work = Path(temporary)
            classes = work / 'classes'
            classes.mkdir()
            command('compile', [args.javac, '-encoding', 'UTF-8', '--release', '17',
                                '-d', classes, *sources, *tests])
            java = [args.java, '-Xmx512m', '-cp', classes]
            for suite in ('RamdiskRebuilderTest', 'BootImageRebuilderTest',
                          'BootImageEquivalenceTest', 'RamdiskInspectorTest'):
                command(suite, [*java, 'dev.maplesu.image.' + suite])
            tool = [*java, 'dev.maplesu.image.ImageTool']
            original = json.loads(command('original-inspect', [*tool, 'inspect', args.init_boot]))
            if original['headerVersion'] != 4 or original['kernelSize'] != 0:
                raise ValueError('This sample check requires kernel-free init_boot v4')
            raw = args.init_boot.read_bytes()
            original_ramdisk = raw[original['ramdiskOffset']:original['ramdiskOffset'] + original['ramdiskSize']]
            extracted = work / 'original-ramdisk'
            extracted.write_bytes(original_ramdisk)
            original_entries = json.loads(command('original-ramdisk',
                [*java, 'dev.maplesu.image.RamdiskInspector', args.init_boot]))
            results = []
            replacements = [('noop', extracted)]
            if args.prepared_ramdisk:
                replacements.append(('prepared', args.prepared_ramdisk))
            for label, ramdisk in replacements:
                candidate = work / (label + '.NOT-FOR-FLASH.img')
                report = json.loads(command(label + '-rebuild',
                    [*tool, 'rebuild-ramdisk-v4', args.init_boot, ramdisk, candidate]))
                inspected = json.loads(command(label + '-inspect', [*tool, 'inspect', candidate]))
                decoded = json.loads(command(label + '-ramdisk',
                    [*java, 'dev.maplesu.image.RamdiskInspector', candidate]))
                actual = candidate.read_bytes()
                replacement = ramdisk.read_bytes()
                header = bytearray(raw[:4096])
                struct.pack_into('<I', header, 12, len(replacement))
                struct.pack_into('<I', header, 1580, 0)
                if actual[:4096] != header or inspected['kernelSize'] != 0:
                    raise ValueError('Header/kernel preservation failed: ' + label)
                start = inspected['ramdiskOffset']
                if actual[start:start + inspected['ramdiskSize']] != replacement:
                    raise ValueError('Independent ramdisk readback failed: ' + label)
                if entries(original_entries) - entries(decoded):
                    raise ValueError('An original CPIO entry changed: ' + label)
                if not report['equivalenceVerified'] or not report['declaredDiffOnly']:
                    raise ValueError('Declared difference verification failed: ' + label)
                results.append({'name': label, 'image': inspected, 'candidateSha256': digest(candidate),
                                'imageByteIdentical': actual == raw,
                                'originalEntriesPreserved': True, 'kernelSizeRemainsZero': True,
                                'headerFieldsPreserved': True, 'ramdiskReadback': True,
                                'declaredDiffOnly': True, 'candidateRetained': False,
                                'ramdiskEntryCount': len(decoded['entries']),
                                'originalSignaturesReverified': report['originalSignaturesReverified'],
                                'avbFooterPreserved': report['avbFooterPreserved']})
                candidate.unlink()
            after = {str(path.resolve()): identity(path) for path in inputs}
            if before != after:
                raise ValueError('Source/tool input changed during checks')
            record.update({'passed': True, 'results': results, 'inputsUnchanged': True,
                           'inputs': before, 'originalEntryCount': len(original_entries['entries']),
                           'scope': 'Production v4 component reconstruction, synthetic regressions, '
                                    'and supplied ramdisk samples; no Ultra boot/runtime claim.'})
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        record['error'] = str(error)
    record['verifier'] = identity(Path(__file__))
    (output / 'PUBLICATION.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--init-boot', required=True, type=Path)
    parser.add_argument('--prepared-ramdisk', type=Path,
                        help='Optional replacement preserving the original CPIO entries; omit for a no-op rebuild.')
    parser.add_argument('--boot', type=Path)
    parser.add_argument('--java', default=shutil.which('java'))
    parser.add_argument('--javac', default=shutil.which('javac'))
    parser.add_argument('--work-directory', type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    args = parser.parse_args()
    record = run(args)
    print(json.dumps({key: value for key, value in record.items() if key not in ('inputs', 'commands')}, indent=2))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
