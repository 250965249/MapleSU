"""Read-only device/material checks using image-core and fixed official AOSP tools.

This checks RAW_ARM64 boot + kernel-free init_boot materials. It does not approve
an installation or authenticate the embedded AVB key against the device root of trust.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
MKBOOTIMG_COMMIT = 'd2bb0af5ba6d3198a3e99529c97eda1be0b5a093'
AVB_COMMIT = 'c5066a96caa7bf4150c0a8cc8cc14ab81733fdc7'


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_repository(path, commit, names):
    head = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
    changes = subprocess.check_output(['git', '-C', str(path), 'status', '--porcelain',
                                       '--untracked-files=no'], text=True)
    if head != commit or changes:
        raise ValueError('AOSP source differs from fixed clean revision: ' + str(path))
    return {'commit': head, 'files': {name: sha256(path / name) for name in names}}


def run(args):
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=False)
    record = {'schemaVersion': 1, 'passed': False, 'readyToFlash': False,
              'scope': 'Original boot/init_boot integrity, file roundtrip, AOSP component agreement, '
                       'AVB verification with embedded keys, and live read-only identity.',
              'deviceBootPartitionHashVerified': False, 'firmwarePackageProvenanceVerified': False,
              'deviceRootOfTrustKeyVerified': False, 'restoreProcedureVerified': False,
              'bootloaderUnlockIndependentlyVerified': False,
              'partitionWrites': False, 'deviceBootTestPerformed': False}
    env = os.environ.copy()
    if args.openssl:
        env['PATH'] = str(args.openssl.resolve(strict=True).parent) + os.pathsep + env['PATH']
    logs = {}

    def command(name, arguments, expected_exit=0):
        result = subprocess.run([str(value) for value in arguments], capture_output=True,
                                timeout=120, env=env)
        data = result.stdout + result.stderr
        (output / (name + '.log')).write_bytes(data)
        logs[name] = {'exitCode': result.returncode, 'sha256': hashlib.sha256(data).hexdigest()}
        if result.returncode != expected_exit:
            raise ValueError('Unexpected exit for ' + name + ': ' + str(result.returncode))
        return data.decode('utf-8-sig', errors='replace').strip()

    try:
        if (args.avb_root / 'avb_openssl').exists():
            raise ValueError('Unexpected local avb_openssl would override the selected OpenSSL')
        openssl = shutil.which('openssl', path=env['PATH'])
        if not openssl:
            raise ValueError('OpenSSL is required to verify signed boot vbmeta')
        record['opensslSha256'] = sha256(Path(openssl))
        repositories = {
            'mkbootimg': checked_repository(args.mkbootimg_root, MKBOOTIMG_COMMIT,
                                            ['unpack_bootimg.py', 'mkbootimg.py', 'include/bootimg/bootimg.h',
                                             'gki/certify_bootimg.py']),
            'avb': checked_repository(args.avb_root, AVB_COMMIT, ['avbtool.py', 'README.md']),
        }
        jar_hash = sha256(args.jar)
        source_hashes = {name: sha256(path) for name, path in (('boot', args.boot), ('init_boot', args.init_boot))}
        images = {}
        for name, source in (('boot', args.boot), ('init_boot', args.init_boot)):
            if source.name != name + '.img':
                raise ValueError('AOSP descriptor verification requires the material name ' + name + '.img')
            image = json.loads(command(name + '-inspect', [args.java, '-jar', args.jar, 'inspect', source]))
            if image['sha256'] != source_hashes[name]:
                raise ValueError('Source changed before inspection')
            if name == 'boot' and (not image['containsKernel'] or image['compression'] != 'RAW_ARM64'):
                raise ValueError('This material check requires a RAW_ARM64 boot kernel')
            if name == 'init_boot' and image['containsKernel']:
                raise ValueError('Expected kernel-free init_boot')
            unpacked = output / name
            command(name + '-aosp-unpack', [sys.executable, args.mkbootimg_root / 'unpack_bootimg.py',
                                          '--boot_img', source, '--out', unpacked])
            components = {}
            for component in ('kernel', 'ramdisk'):
                size, offset = image[component + 'Size'], image[component + 'Offset']
                path = unpacked / component
                if size:
                    with source.open('rb') as stream:
                        stream.seek(offset)
                        expected = hashlib.sha256(stream.read(size)).hexdigest()
                    if path.stat().st_size != size or sha256(path) != expected:
                        raise ValueError('AOSP component differs from image-core: ' + name + '/' + component)
                    components[component] = {'size': size, 'sha256': expected}
                elif path.exists() and path.stat().st_size:
                    raise ValueError('AOSP returned an unexpected nonempty component')
            info = command(name + '-avb-info', [sys.executable, args.avb_root / 'avbtool.py',
                                              'info_image', '--image', source])
            verified = command(name + '-avb-verify', [sys.executable, args.avb_root / 'avbtool.py',
                                                      'verify_image', '--image', source])
            algorithm = re.findall(r'^Algorithm:\s+(\S+)\s*$', info, re.MULTILINE)
            partitions = re.findall(r'^\s+Partition Name:\s+(\S+)\s*$', info, re.MULTILINE)
            if len(algorithm) != 1 or partitions != [name] or 'Successfully verified sha256 hash' not in verified:
                raise ValueError('Unexpected AVB verification contract: ' + name)
            images[name] = {'inspection': image, 'aospComponents': components,
                            'avbAlgorithm': algorithm[0], 'avbDescriptorVerified': True,
                            'embeddedSignatureVerified': algorithm[0] != 'NONE'}
        roundtrip = json.loads(command('boot-roundtrip', [args.java, '-Xmx512m', '-jar', args.jar,
                                                         'roundtrip', args.boot]))
        if not all(roundtrip[key] for key in ('codecRoundTripVerified', 'containerByteIdentical', 'sourceUnchanged')):
            raise ValueError('Image roundtrip did not verify')
        if roundtrip['decodedKernelSha256'] != images['boot']['aospComponents']['kernel']['sha256']:
            raise ValueError('Decoded kernel differs from AOSP extraction')
        # Reuse AOSP's AVB classes for the certificate layout used by certify_bootimg.
        spec = importlib.util.spec_from_file_location('maplesu_aosp_avb_reference', args.avb_root / 'avbtool.py')
        avb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(avb)
        with args.boot.open('rb') as stream:
            stream.seek(-avb.AvbFooter.SIZE, os.SEEK_END)
            footer = avb.AvbFooter(stream.read(avb.AvbFooter.SIZE))
            payload_end = images['boot']['inspection']['signatureOffset']
            if (images['boot']['inspection']['signatureSize'] == 0
                    and footer.original_image_size - payload_end == 16 * 1024):
                stream.seek(payload_end)
                tail = stream.read(16 * 1024)
                certificates, position = [], 0
                with tempfile.TemporaryDirectory(prefix='maplesu-gki-check-') as temporary:
                    directory = Path(temporary)
                    shutil.copyfile(args.boot, directory / 'boot.img')
                    shutil.copyfile(output / 'boot/kernel', directory / 'generic_kernel.img')
                    for index in (1, 2):
                        header = avb.AvbVBMetaHeader(tail[position:position + avb.AvbVBMetaHeader.SIZE])
                        size = header.SIZE + header.authentication_data_block_size + header.auxiliary_data_block_size
                        certificate = tail[position:position + size]
                        if size > len(tail) - position:
                            raise ValueError('GKI certificate exceeds the trailing area')
                        path = directory / ('certificate' + str(index) + '.img')
                        path.write_bytes(certificate)
                        command('gki-certificate-' + str(index), [sys.executable, args.avb_root / 'avbtool.py',
                                                                 'verify_image', '--image', path])
                        certificates.append({'imageOffset': payload_end + position, 'size': size,
                                             'sha256': hashlib.sha256(certificate).hexdigest(),
                                             'embeddedSignatureVerified': header.algorithm_type != 0,
                                             'descriptorVerified': True})
                        position += size
                if any(tail[position:]):
                    raise ValueError('Unrecognized data follows the GKI certificates')
                record['gkiCertificates'] = {'offset': payload_end, 'size': len(tail),
                                              'sha256': hashlib.sha256(tail).hexdigest(),
                                              'certificates': certificates}
        # One changed payload byte must invalidate the original descriptor, even though
        # the untouched vbmeta signature itself remains valid. The copy is discarded.
        with tempfile.TemporaryDirectory(prefix='maplesu-avb-negative-') as temporary:
            corrupted = Path(temporary) / 'boot.img'
            shutil.copyfile(args.boot, corrupted)
            with corrupted.open('r+b') as stream:
                offset = images['boot']['inspection']['kernelOffset'] + 64
                stream.seek(offset)
                before = stream.read(1)
                stream.seek(offset)
                stream.write(bytes([before[0] ^ 1]))
            rejected = command('avb-payload-change-rejection', [sys.executable, args.avb_root / 'avbtool.py',
                                                                'verify_image', '--image', corrupted], 1)
            if 'does not match digest in descriptor' not in rejected:
                raise ValueError('Payload corruption failed for an unexpected reason')
        device = {}
        properties = ('ro.product.model', 'ro.build.display.id', 'ro.build.version.incremental',
                      'ro.build.version.security_patch', 'ro.boot.slot_suffix', 'ro.boot.flash.locked',
                      'ro.boot.verifiedbootstate', 'ro.boot.vbmeta.device_state', 'ro.boot.vbmeta.digest')
        for prop in properties:
            device[prop] = command('device-' + prop, [args.adb, '-s', args.serial, 'shell', 'getprop', prop])
        device['kernelRelease'] = command('device-uname', [args.adb, '-s', args.serial, 'shell', 'uname', '-r'])
        device['selinux'] = command('device-selinux', [args.adb, '-s', args.serial, 'shell', 'getenforce'])
        device['identity'] = command('device-id', [args.adb, '-s', args.serial, 'shell', 'id'])
        matches = roundtrip['kernelRelease'] == device['kernelRelease']
        if not matches:
            raise ValueError('Full kernel release differs from the running device')
        if any(sha256(path) != source_hashes[name] for name, path in (('boot', args.boot), ('init_boot', args.init_boot))):
            raise ValueError('Source materials changed during validation')
        if sha256(args.jar) != jar_hash:
            raise ValueError('Image tool changed during validation')
        if sha256(Path(openssl)) != record['opensslSha256']:
            raise ValueError('OpenSSL changed during validation')
        if checked_repository(args.avb_root, AVB_COMMIT, ['avbtool.py', 'README.md']) != repositories['avb']:
            raise ValueError('AVB sources changed during validation')
        if checked_repository(args.mkbootimg_root, MKBOOTIMG_COMMIT,
                              ['unpack_bootimg.py', 'mkbootimg.py', 'include/bootimg/bootimg.h',
                               'gki/certify_bootimg.py']) != repositories['mkbootimg']:
            raise ValueError('mkbootimg sources changed during validation')
        record.update({'passed': True, 'images': images, 'roundtrip': roundtrip,
                       'sourcesUnchanged': True, 'imageToolSha256': jar_hash, 'aospSources': repositories,
                       'kernelReleaseMatchesDevice': matches, 'device': device,
                       'modifiedPayloadRejectedByOriginalAvb': True,
                       'blockers': ['No verified production candidate/runtime/installer.',
                                    'No current partition hashes or independently bound firmware provenance.',
                                    'No complete device restore rehearsal.']})
        if device['ro.boot.flash.locked'] == '1' or device['ro.boot.vbmeta.device_state'] == 'locked':
            record['blockers'].append('Bootloader properties report locked; independently verify installation '
                                      'conditions because existing root may alter these properties.')
        if 'gkiCertificates' in record:
            record['blockers'].append('Candidate generation must handle the original trailing GKI certificates explicitly.')
    except (OSError, ValueError, LookupError, struct.error, subprocess.SubprocessError) as error:
        record['passed'] = False
        record['error'] = str(error)
    record['logs'] = logs
    record['verifierSha256'] = sha256(Path(__file__))
    (output / 'materials.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('boot', 'init-boot', 'java', 'mkbootimg-root', 'avb-root', 'adb'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--openssl', type=Path)
    parser.add_argument('--jar', type=Path, default=ROOT / 'image-core/build/libs/image-core.jar')
    parser.add_argument('--output-directory', type=Path,
                        default=ROOT / '.analysis' / ('boot-materials-' + uuid.uuid4().hex))
    args = parser.parse_args()
    try:
        record = run(args)
    except OSError as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps(record, indent=2))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
