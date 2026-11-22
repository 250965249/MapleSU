"""Read-only, independent verification of an unsigned offline boot v4 candidate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PAGE = 4096
MAX_KERNEL = 128 * 1024 * 1024
FALSE_FLAGS = ('flashableCandidate', 'deviceBootTestPerformed', 'runtimeElevationVerified',
               'fullProParityVerified', 'kernelPayloadExecuted', 'partitionWrites',
               'candidateGkiSignaturePresent', 'candidateAvbFooterPresent')
SOURCE_NAMES = ('boot', 'kernel', 'analyzer', 'repack', 'imageCoreJar', 'builder', 'codecDriver',
                'runtimeNativeEntry', 'runtimeKeyTransform', 'runtimeManagerEntry',
                'java', 'javac', 'python')
AOSP_SOURCES = {
    'mkbootimg': ('aosp-mkbootimg', 'd2bb0af5ba6d3198a3e99529c97eda1be0b5a093',
                  ('mkbootimg.py', 'unpack_bootimg.py', 'gki/generate_gki_certificate.py',
                   'include/bootimg/bootimg.h')),
    'avb': ('aosp-avb', 'c5066a96caa7bf4150c0a8cc8cc14ab81733fdc7', ('avbtool.py',)),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'Duplicate JSON field')
        result[name] = value
    return result


class Snapshots:
    """Hash before use and again at completion, including file identity and timestamps."""
    def __init__(self):
        self.files = {}

    @staticmethod
    def state(path):
        info = path.stat()
        require(stat.S_ISREG(info.st_mode), 'Evidence input must be a regular file')
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = path.stat()
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        require(identity(info) == identity(after), 'Input changed while hashing')
        return identity(after), checksum

    def track(self, path, expected=None, size=None):
        path = Path(path).resolve(strict=True)
        state = self.state(path)
        if path in self.files:
            require(state == self.files[path], 'Input changed during verification')
        self.files[path] = state
        if expected is not None:
            require(re.fullmatch(r'[0-9a-f]{64}', expected) is not None,
                    'Invalid SHA-256 record')
            require(state[1] == expected, 'SHA-256 mismatch')
        if size is not None:
            require(state[0][2] == size, 'Recorded input size mismatch')
        return path

    def read(self, path, maximum):
        path = self.track(path)
        require(self.files[path][0][2] <= maximum, 'Input exceeds verification size limit')
        data = path.read_bytes()
        require(digest(data) == self.files[path][1], 'Input changed while reading')
        return data

    def unchanged(self):
        try:
            return all(self.state(path) == before for path, before in self.files.items())
        except (OSError, ValueError):
            return False


def boot_v4(data):
    require(len(data) >= PAGE and data[:8] == b'ANDROID!', 'Invalid boot header')
    kernel, ramdisk, os_version, header = struct.unpack_from('<4I', data, 8)
    version = struct.unpack_from('<I', data, 40)[0]
    signature = struct.unpack_from('<I', data, 1580)[0]
    require(version == 4 and header == 1584 and 0 < kernel <= MAX_KERNEL,
            'Expected boot v4 with a bounded kernel')
    require(not any(data[24:40]) and not any(data[1584:PAGE]), 'Nonzero header padding')
    command = data[44:1580]
    end = command.find(b'\0')
    require(end >= 0 and not any(command[end:]), 'Invalid command line framing')
    command = command[:end].decode('utf-8')
    align = lambda value: (value + PAGE - 1) // PAGE * PAGE
    ramdisk_offset = PAGE + align(kernel)
    signature_offset = ramdisk_offset + align(ramdisk)
    body_end = signature_offset + align(signature)
    require(body_end <= len(data), 'Boot component exceeds container bounds')
    for start, stop in ((PAGE + kernel, ramdisk_offset),
                        (ramdisk_offset + ramdisk, signature_offset),
                        (signature_offset + signature, body_end)):
        require(not any(data[start:stop]), 'Nonzero component padding')
    return {'headerVersion': version, 'headerSize': header, 'osVersionField': os_version,
            'cmdline': command, 'kernelOffset': PAGE, 'kernelSize': kernel,
            'ramdiskOffset': ramdisk_offset, 'ramdiskSize': ramdisk,
            'signatureOffset': signature_offset, 'signatureSize': signature, 'bodyEnd': body_end}


def compression(data):
    if data[:4] == bytes((2, 33, 76, 24)):
        return 'LZ4_LEGACY'
    if data[:2] == b'\x1f\x8b':
        return 'GZIP'
    require(len(data) >= 64 and data[56:60] == b'ARMd', 'Unrecognized kernel compression')
    return 'RAW_ARM64'


def replay_plan(text, source, credential):
    """Reconstruct every byte without importing or running the candidate builder."""
    def one(pattern):
        values = re.findall(pattern, text, re.MULTILINE)
        require(len(values) == 1, 'Missing or ambiguous plan marker')
        return values[0]

    require(not re.search(r'(?m)^\w+_FAILED\s*$', text), 'Plan contains a failure')
    for marker in ('PATCH_PLAN_OK', 'PLAN_REPLAY_OK', 'PLAN_SLOT'):
        require(sum(line.startswith(marker) for line in text.splitlines()) == 1,
                'Missing or ambiguous plan marker')
    count = int(one(r'^PATCH_PLAN_OK edits=(\d+) credentialInitialized=false flashableCandidate=false\s*$'))
    changed = int(one(r'^PLAN_REPLAY_OK changedBytes=(\d+)\s*$'))
    offset, length = map(int, one(r'^PLAN_SLOT offset=(\d+) length=(\d+)\s*$'))
    lines = [line for line in text.splitlines() if line.startswith('PLAN_EDIT')]
    require(count > 0 and len(lines) == count, 'Plan edit count mismatch')
    require(len(credential) == 48 and re.fullmatch(rb'[A-Za-z0-9]{48}', credential),
            'Invalid runtime credential framing')
    output, previous_end, slot_covered = bytearray(source), 64, False
    for line in lines:
        match = re.fullmatch(r'PLAN_EDIT offset=(\d+) expected=([0-9a-fA-F]+) replacement=([0-9a-fA-F]+)', line)
        require(match is not None, 'Malformed plan edit')
        start = int(match[1])
        before, after = bytes.fromhex(match[2]), bytes.fromhex(match[3])
        stop = start + len(before)
        require(start >= previous_end and len(before) == len(after) and stop <= len(source),
                'Plan overlap, length mismatch or bounds violation')
        require(source[start:stop] == before, 'Plan preimage mismatch')
        output[start:stop] = after
        previous_end = stop
        slot_covered |= start <= offset and offset + length <= stop
    require(sum(a != b for a, b in zip(source, output)) == changed and changed > 0,
            'Plan replay change count mismatch')
    require(length == 48 and offset >= 64 and offset + length <= len(source) and slot_covered,
            'Credential slot exceeds plan bounds')
    require(output[offset:offset + length] == bytes(48), 'Credential slot replacement is not zero')
    output[offset:offset + length] = credential[:-1] + b'\0'
    return output, {'edits': count, 'offset': offset, 'length': length,
                    'changedBytes': sum(a != b for a, b in zip(source, output))}


def java_tools():
    paths = []
    for name in ('java', 'javac'):
        path = shutil.which(name)
        require(path is not None, 'JDK tools are required for independent decoding')
        paths.append(Path(path).resolve(strict=True))
    return paths


def decode_components(items, source_inputs, snapshots):
    """Compile the repository codec in temporary storage; never execute kernel payloads."""
    java, javac = java_tools()
    for name, path in (('java', java), ('javac', javac),
                       ('codecDriver', ROOT / 'tools/patch/KernelCodec.java'),
                       ('imageCoreJar', ROOT / 'image-core/build/libs/image-core.jar')):
        require(Path(source_inputs[name]['path']).resolve() == path.resolve(),
                'Decoder tool identity differs from the local toolchain')
    with tempfile.TemporaryDirectory(prefix='maplesu-independent-verifier-') as directory:
        work = Path(directory)
        jar, driver, classes = work / 'image-core.jar', work / 'KernelCodec.java', work / 'classes'
        jar.write_bytes(snapshots.read(source_inputs['imageCoreJar']['path'], MAX_KERNEL))
        driver.write_bytes(snapshots.read(source_inputs['codecDriver']['path'], 1024 * 1024))
        classes.mkdir()

        def run(arguments):
            result = subprocess.run([str(item) for item in arguments], capture_output=True, timeout=120)
            require(result.returncode == 0, 'Independent Java codec failed')

        run([javac, '-cp', jar, '-d', classes, driver])
        decoded = []
        for index, (data, format_name) in enumerate(items):
            incoming, outgoing = work / f'{index}.component', work / f'{index}.raw'
            incoming.write_bytes(data)
            run([java, '-cp', str(jar) + os.pathsep + str(classes),
                 'dev.maplesu.image.KernelCodec', 'decode', incoming, outgoing, format_name])
            require(outgoing.stat().st_size <= MAX_KERNEL, 'Decoded kernel exceeds size limit')
            decoded.append(outgoing.read_bytes())
        return decoded


def verify(evidence_path):
    snapshots = Snapshots()
    try:
        return verify_snapshot(Path(evidence_path).resolve(strict=True), snapshots)
    finally:
        require(snapshots.unchanged(), 'Evidence or tool changed during verification')


def verify_snapshot(evidence_path, snapshots):
    snapshots.track(__file__)
    evidence = json.loads(snapshots.read(evidence_path, 4 * 1024 * 1024), object_pairs_hook=unique_object)
    require(evidence['schemaVersion'] == 2 and evidence['operation'] == 'BUILD_OFFLINE_CANDIDATE',
            'Unsupported candidate evidence schema')
    require(evidence['passed'] is True and evidence['credentialInitialized'] is True,
            'Expected a completed credential-initialized offline candidate')
    require(all(evidence[name] is False for name in FALSE_FLAGS), 'Invalid offline candidate status')
    require(evidence['sourceInputsUnchanged'] is True and evidence['changedInputs'] == [],
            'Builder records input drift')
    sources = evidence['sourceInputs']
    require(all(name in sources for name in SOURCE_NAMES), 'Missing source/tool provenance')
    for item in sources.values():
        snapshots.track(item['path'], item['sha256'])
    for name, expected in evidence['sources'].items():
        require(sources[name]['sha256'] == expected, 'Conflicting tool digest records')

    def artifact(item, maximum=MAX_KERNEL):
        path = snapshots.track(item['path'], item['sha256'], item.get('size'))
        return snapshots.read(path, maximum)

    boot = artifact(evidence['inputs']['boot'], 512 * 1024 * 1024)
    raw = artifact(evidence['inputs']['kernel'])
    patched = artifact(evidence['patchedKernel'])
    component = artifact(evidence['patchedComponent'])
    candidate = artifact(evidence['candidate'], 512 * 1024 * 1024)
    for name in ('boot', 'kernel'):
        require(Path(sources[name]['path']).resolve() == Path(evidence['inputs'][name]['path']).resolve()
                and sources[name]['sha256'] == evidence['inputs'][name]['sha256'],
                'Conflicting source input records')
    original_layout, candidate_layout = boot_v4(boot), boot_v4(candidate)
    for name, value in evidence['inputs']['layout'].items():
        require(original_layout[name] == value, 'Source boot layout record mismatch')
    require(candidate_layout['signatureSize'] == 0 and len(candidate) == candidate_layout['bodyEnd'],
            'Candidate contains signature or trailing metadata')
    expected_header = bytearray(boot[:PAGE])
    struct.pack_into('<I', expected_header, 8, len(component))
    struct.pack_into('<I', expected_header, 1580, 0)
    require(candidate[:PAGE] == expected_header, 'Candidate changed unrelated boot header bytes')
    start = original_layout['ramdiskOffset']
    original_ramdisk = boot[start:start + original_layout['ramdiskSize']]
    start = candidate_layout['ramdiskOffset']
    require(candidate[start:start + candidate_layout['ramdiskSize']] == original_ramdisk,
            'Candidate ramdisk differs from original')
    original_component = boot[PAGE:PAGE + original_layout['kernelSize']]
    candidate_component = candidate[PAGE:PAGE + candidate_layout['kernelSize']]
    require(candidate_component == component, 'Candidate contains a substituted kernel component')
    original_format, patched_format = compression(original_component), compression(component)
    require(original_format == patched_format == evidence['patchedComponent']['format'],
            'Candidate changed kernel compression')
    require(len(raw) >= 64 and raw[56:60] == b'ARMd' and len(raw) == len(patched),
            'Invalid raw ARM64 kernel framing')
    steps = evidence['steps']
    require([step['name'] for step in steps] == ['verify-source-pair', 'analyze', 'apply-plan',
            'structural-checks', 'encode', 'rebuild-container', 'verify-candidate'],
            'Unexpected builder step sequence')
    pair, analyze, apply, structural, encode, rebuild_step, final_step = steps
    for step, names in ((pair, ('bootKernelMatchesRaw',)), (analyze, ('deterministic',)),
                        (structural, ('diffsInsidePlannedRanges', 'allPlannedRegionsMatch')),
                        (encode, ('roundTripVerified',)),
                        (rebuild_step, ('containerVerified', 'replacementKernelVerified', 'ramdiskPreserved')),
                        (final_step, ('payloadMatch', 'credentialPresent'))):
        require(all(step[name] is True for name in names), 'Contradictory successful step evidence')
    require(analyze['exitCode'] == 0, 'Analyzer exit record is not successful')
    require(pair['compression'] == original_format and pair['componentSha256'] == digest(original_component)
            and pair['decodedSha256'] == digest(raw), 'Source pair digest record mismatch')
    plan_path = evidence_path.parent / 'work/plan.txt'
    snapshots.track(plan_path, analyze['planSha256'])
    plan = snapshots.read(plan_path, 16 * 1024 * 1024).decode('utf-8-sig')
    credential = evidence['credential']
    key = snapshots.read(credential['keyFile'], 1024).strip()
    require(digest(key) == credential['keySha256'], 'Runtime credential digest mismatch')
    require((credential['runtimeInputLength'], credential['kernelComparedLength'], credential['slotLength'],
             credential['runtimeTransform']) == (48, 47, 48, 'drop-last-character'),
            'Credential transform contract mismatch')
    require(credential['contractVerifiedStatically'] is True and credential['runtimeElevationVerified'] is False,
            'Credential evidence incorrectly claims runtime verification')
    expected, replay = replay_plan(plan, raw, key)
    require(patched == expected, 'Patched kernel differs from complete independent plan replay')
    require(analyze['edits'] == evidence['planEdits'] == replay['edits']
            and analyze['slot'] == {'offset': replay['offset'], 'length': 48}, 'Plan metadata mismatch')
    require(evidence['changedBytes'] == apply['changedBytes'] == structural['changedOffsets']
            == replay['changedBytes'] and apply['credentialSlot'] == replay['offset'],
            'Changed byte record mismatch')
    require(encode['format'] == patched_format and encode['rawBytes'] == len(patched)
            and encode['compressedBytes'] == len(component)
            and encode['compressedSha256'] == digest(component), 'Encoded component record mismatch')
    require(rebuild_step['sha256'] == digest(candidate) and rebuild_step['size'] == len(candidate),
            'Candidate rebuild record mismatch')
    inspect = final_step['inspect']
    require(inspect['sha256'] == digest(candidate) and inspect['fileSize'] == len(candidate)
            and inspect['compression'] == patched_format, 'Final candidate inspection mismatch')
    for name in ('headerVersion', 'headerSize', 'kernelOffset', 'kernelSize', 'ramdiskOffset',
                 'ramdiskSize', 'signatureOffset', 'signatureSize'):
        require(inspect[name] == candidate_layout[name], 'Final candidate layout mismatch')
    rebuild = json.loads(artifact(evidence['rebuildEvidence'], 4 * 1024 * 1024),
                         object_pairs_hook=unique_object)
    require(rebuild['schemaVersion'] == 1 and rebuild['passed'] is True, 'Invalid rebuild evidence')
    require(all(rebuild[name] is False for name in ('flashableCandidate', 'partitionWrites',
            'verificationDisabled', 'kernelPayloadExecuted', 'deviceBootTestPerformed',
            'candidateGkiSignaturePresent', 'candidateAvbFooterPresent')), 'Invalid offline rebuild status')
    require(rebuild['sourcesUnchanged'] is True and rebuild['toolSha256'] == sources['repack']['sha256'],
            'Rebuild tool provenance mismatch')
    require(rebuild['originalLayout'] == original_layout and rebuild['candidate']['layout'] == candidate_layout,
            'Rebuild boot layout mismatch')
    require(rebuild['candidate']['sha256'] == digest(candidate) and rebuild['candidate']['size'] == len(candidate)
            and Path(rebuild['candidate']['path']).resolve() == Path(evidence['candidate']['path']).resolve(),
            'Rebuild candidate identity mismatch')
    for label, item in (('boot', evidence['inputs']['boot']), ('kernel', evidence['patchedComponent'])):
        require(all(rebuild['inputs'][label][name] == item[name] for name in ('path', 'sha256', 'size')),
                'Rebuild input identity mismatch')
    require(rebuild['aospSources'] == evidence['rebuildEvidence']['aospSources'], 'AOSP source records differ')
    require(set(rebuild['aospSources']) == set(AOSP_SOURCES), 'Incomplete AOSP source provenance')
    for name, (relative, commit, files) in AOSP_SOURCES.items():
        require(rebuild['aospSources'][name]['commit'] == commit
                and set(rebuild['aospSources'][name]['files']) == set(files),
                'Unexpected AOSP revision or source set')
        for filename, expected_hash in rebuild['aospSources'][name]['files'].items():
            base = (ROOT / '.research' / relative).resolve()
            path = (base / filename).resolve()
            require(path.is_relative_to(base), 'AOSP source path exceeds repository bounds')
            snapshots.track(path, expected_hash)
    decoded = decode_components([(original_component, original_format), (component, patched_format),
                                 (candidate_component, patched_format)], sources, snapshots)
    require(decoded[0] == raw, 'Original boot kernel differs from raw input after decoding')
    require(decoded[1] == patched and decoded[2] == patched,
            'Candidate kernel differs from patched raw after decoding')
    return {'schemaVersion': 1, 'operation': 'VERIFY_OFFLINE_CANDIDATE_INDEPENDENTLY', 'passed': True,
            'scope': 'Artifact integrity, complete plan replay and static credential framing only.',
            **{name: False for name in FALSE_FLAGS},
            'evidencePath': str(evidence_path), 'evidenceSha256': snapshots.files[evidence_path][1],
            'candidatePath': evidence['candidate']['path'], 'candidateSha256': digest(candidate),
            'planSha256': analyze['planSha256'], 'verifierSha256': snapshots.files[Path(__file__).resolve()][1],
            'compression': patched_format, 'planEdits': replay['edits'], 'changedBytes': replay['changedBytes'],
            'credentialContract': {'runtimeInputLength': 48, 'kernelComparedLength': 47, 'slotLength': 48,
                                   'runtimeTransform': 'drop-last-character', 'slotTerminatedWithNul': True},
            'checks': {'sourceDigestsMatch': True, 'toolDigestsMatch': True, 'planDigestMatches': True,
                       'originalBootKernelMatchesRaw': True, 'candidateComponentMatchesPatchedRaw': True,
                       'candidateKernelMatchesComponent': True, 'ramdiskPreserved': True,
                       'unrelatedHeaderBytesPreserved': True, 'completePlanReplayMatches': True,
                       'allChangesInsidePlan': True, 'credentialSlotMatchesContract': True,
                       'evidenceAndToolsUnchangedDuringVerification': True},
            'checkedFiles': len(snapshots.files), 'readOnly': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--out', type=Path, help='New report outside the candidate evidence directory')
    args = parser.parse_args()
    target = None
    try:
        if args.out:
            requested = args.out.resolve()
            require(not requested.is_relative_to(args.evidence.resolve().parent),
                    'Report must be outside the candidate evidence directory')
            require(not requested.exists(), 'Report output already exists')
            target = requested
        report = verify(args.evidence)
    except (OSError, ValueError, KeyError, TypeError, struct.error, subprocess.SubprocessError) as error:
        # A fixed error avoids echoing contents of malformed evidence or credential files.
        report = {'schemaVersion': 1, 'operation': 'VERIFY_OFFLINE_CANDIDATE_INDEPENDENTLY',
                  'passed': False, 'error': 'Independent artifact verification failed; inspect inputs privately.',
                  'errorType': type(error).__name__,
                  **{name: False for name in FALSE_FLAGS}}
    output = json.dumps(report, indent=2) + '\n'
    if target is not None:
        try:
            with target.open('x', encoding='utf-8') as stream:
                stream.write(output)
        except OSError:
            print(json.dumps({'passed': False, 'error': 'Report output creation failed.'}))
            return 1
    print(output, end='')
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
