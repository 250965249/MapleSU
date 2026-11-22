"""Build an unsigned, explicitly non-flashable MapleSU offline boot candidate.

Pipeline (read-only inputs, no device I/O, no payload execution):
  1. run the source-built analyzer to obtain the Lite patch plan for a raw ARM64 kernel
  2. apply the plan preimages/replacements + initialise the 48-byte credential slot
  3. re-encode the patched kernel in its original compression format with the repository codec
  4. rebuild the boot v4 container with the fixed AOSP sources
  5. re-inspect the candidate and compare payloads independently

The result is a research artifact. It is not signed, its old GKI/AVB metadata is invalidated
by the kernel change, and it must not be described as flashable without a signed candidate
contract and a device boot record.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import string
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KEY_LEN = 48
ALPHABET = string.ascii_letters + string.digits
PLAN_EDIT = re.compile(r'^PLAN_EDIT offset=(\d+) expected=([0-9a-f]+) replacement=([0-9a-f]+)$')
PLAN_SLOT = re.compile(r'^PLAN_SLOT offset=(\d+) length=(\d+)$')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fail(message: str) -> None:
    raise SystemExit('BUILD_FAILED: ' + message)


def run(argv: list[str]) -> str:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    if result.returncode:
        fail(f"command failed ({result.returncode}): {' '.join(argv)}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def parse_plan(text: str) -> tuple[list[dict], dict]:
    edits, slot = [], None
    for line in text.splitlines():
        match = PLAN_EDIT.match(line)
        if match:
            edits.append({'offset': int(match.group(1)),
                          'expected': bytes.fromhex(match.group(2)),
                          'replacement': bytes.fromhex(match.group(3))})
            continue
        match = PLAN_SLOT.match(line)
        if match:
            if slot is not None:
                fail('analyzer produced duplicate PLAN_SLOT lines')
            slot = {'offset': int(match.group(1)), 'length': int(match.group(2))}
        elif line.startswith(('PLAN_EDIT', 'PLAN_SLOT')):
            fail('analyzer produced a malformed plan line')
    if not edits:
        fail('analyzer produced no PLAN_EDIT lines')
    if slot is None:
        fail('analyzer produced no PLAN_SLOT line')
    if slot['length'] != KEY_LEN:
        fail('credential slot length differs from the runtime contract')
    return edits, slot


def apply_plan(raw: bytearray, edits: list[dict], slot: dict, key: str) -> int:
    previous_end = 0
    for edit in edits:
        start = edit['offset']
        size = len(edit['expected'])
        if not size or size != len(edit['replacement']) or start < previous_end:
            fail('plan edit overlaps or has mismatched preimage/replacement length')
        if start < 0 or start + size > len(raw):
            fail('plan edit exceeds the kernel bounds')
        if bytes(raw[start:start + size]) != edit['expected']:
            fail(f'preimage mismatch at offset {start}')
        previous_end = start + size
    slot_start, slot_len = slot['offset'], slot['length']
    if slot_len != KEY_LEN or slot_start < 0 or slot_start + slot_len > len(raw):
        fail('credential slot exceeds the kernel bounds or differs from the contract')
    holder = next((e for e in edits
                   if e['offset'] <= slot_start and slot_start + slot_len <= e['offset'] + len(e['replacement'])), None)
    if holder is None:
        fail('credential slot is not inside a planned edit')
    relative_slot = slot_start - holder['offset']
    if any(holder['replacement'][relative_slot:relative_slot + slot_len]):
        fail('credential slot is not zero after the plan was applied')
    if len(key) != KEY_LEN - 1 or any(ch not in ALPHABET for ch in key):
        fail('slot credential must be 47 characters of [0-9A-Za-z]')
    payload = key.encode('ascii') + b'\x00'
    if len(payload) != KEY_LEN:
        fail('credential payload length differs from the slot')
    for edit in edits:
        raw[edit['offset']:edit['offset'] + len(edit['replacement'])] = edit['replacement']
    raw[slot_start:slot_start + slot_len] = payload
    return slot_start


def runtime_credential(key: str | None, credential_file: Path | None) -> str:
    if credential_file is not None:
        credential = credential_file.read_text(encoding='ascii').strip()
    elif key is not None:
        if len(key) != KEY_LEN - 1 or any(ch not in ALPHABET for ch in key):
            fail('--key must be 47 characters of [0-9A-Za-z]')
        credential = key + '0'  # Historical slot-key input; get_root drops this final character.
    else:
        credential = ''.join(secrets.choice(ALPHABET) for _ in range(KEY_LEN))
    if len(credential) != KEY_LEN or any(ch not in ALPHABET for ch in credential):
        fail('runtime credential must be 48 characters of [0-9A-Za-z]')
    return credential


def tool_path(name: str) -> Path:
    executable = name + ('.exe' if os.name == 'nt' else '')
    candidate = Path(os.environ.get('JAVA_HOME', '')) / 'bin' / executable
    resolved = candidate if candidate.is_file() else shutil.which(executable)
    if not resolved:
        fail('missing tool: ' + name)
    return Path(resolved).resolve()


def check_source_pair(boot_bytes: bytes, raw: bytes, inspect: dict,
                      java: Path, classpath: str, work: Path) -> dict:
    start, size = inspect['kernelOffset'], inspect['kernelSize']
    if start < 0 or size <= 0 or start + size > len(boot_bytes):
        fail('source boot kernel exceeds container bounds')
    component, decoded = work / 'source-kernel.component', work / 'source-kernel.raw'
    component.write_bytes(boot_bytes[start:start + size])
    run([str(java), '-cp', classpath, 'dev.maplesu.image.KernelCodec', 'decode',
         str(component), str(decoded), inspect['compression']])
    if decoded.read_bytes() != raw:
        fail('--kernel differs from the decoded kernel in --boot')
    return {'name': 'verify-source-pair', 'bootKernelMatchesRaw': True,
            'compression': inspect['compression'], 'componentSha256': sha256(component),
            'decodedSha256': sha256(decoded)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot', required=True, type=Path, help='original boot v4 image (read only)')
    parser.add_argument('--kernel', required=True, type=Path, help='raw ARM64 kernel extracted from that image')
    parser.add_argument('--out', required=True, type=Path, help='fresh output directory')
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument('--key', help='legacy 47-character slot key; runtime suffix 0 is appended')
    credentials.add_argument('--credential-file', type=Path,
                             help='file containing the 48-character runtime credential')
    parser.add_argument('--analyzer', type=Path,
                        default=ROOT / 'patch-engine/build/windows-x64/maplesu-kernel-analyze.exe')
    parser.add_argument('--repack', type=Path, default=ROOT / 'tools/research/repack_boot_v4.py')
    parser.add_argument('--jar', type=Path, default=ROOT / 'image-core/build/libs/image-core.jar')
    args = parser.parse_args()

    boot, kernel_raw, out = args.boot.resolve(), args.kernel.resolve(), args.out.resolve()
    for path in (boot, kernel_raw, args.analyzer, args.repack, args.jar, args.credential_file):
        if path is not None and (not path.is_file() or path.resolve().is_relative_to(out)):
            fail('missing input or input is inside the output directory: ' + str(path))
    if out.exists():
        fail('output directory already exists: ' + str(out))
    credential = runtime_credential(args.key, args.credential_file)
    out.mkdir(parents=True)
    record: dict = {'schemaVersion': 2, 'operation': 'BUILD_OFFLINE_CANDIDATE', 'passed': False,
                    'flashableCandidate': False, 'artifactKind': 'unsigned-offline-candidate-not-for-flashing',
                    'credentialInitialized': False, 'deviceBootTestPerformed': False,
                    'runtimeElevationVerified': False, 'fullProParityVerified': False,
                    'kernelPayloadExecuted': False, 'partitionWrites': False,
                    'blockers': ['No candidate signing or device trust-chain contract.',
                                 'No device boot, runtime, module or restore record for this candidate.',
                                 'Lite patch baseline only; Ultra parity has not been verified.'],
                    'inputs': {}, 'steps': []}
    try:
        build(args, credential, record)
    except (SystemExit, OSError, ValueError, KeyError, struct.error, subprocess.SubprocessError) as error:
        record['passed'] = False
        record['error'] = str(error)
    finally:
        if record.get('sourceInputs'):
            record['changedInputs'] = [name for name, item in record['sourceInputs'].items()
                                       if not Path(item['path']).is_file()
                                       or sha256(Path(item['path'])) != item['sha256']]
            record['sourceInputsUnchanged'] = not record['changedInputs']
            if record['changedInputs']:
                record['passed'] = False
                record['error'] = 'source or tool changed during build: ' + ', '.join(record['changedInputs'])
        if not record['passed']:
            record.pop('candidate', None)
        (out / 'evidence.json').write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n',
                                          encoding='utf-8')
    print(json.dumps({'passed': record['passed'], 'candidate': record.get('candidate'),
                      'changedBytes': record.get('changedBytes'), 'edits': record.get('planEdits'),
                      'error': record.get('error'), 'evidence': str(out / 'evidence.json')}, indent=2))
    return 0 if record['passed'] else 1


def build(args: argparse.Namespace, credential: str, record: dict) -> None:
    boot, kernel_raw, out = args.boot.resolve(), args.kernel.resolve(), args.out.resolve()
    work = out / 'work'
    work.mkdir()
    java, javac = tool_path('java'), tool_path('javac')
    sources = {'boot': boot, 'kernel': kernel_raw, 'analyzer': args.analyzer,
               'repack': args.repack, 'imageCoreJar': args.jar, 'builder': Path(__file__),
               'codecDriver': ROOT / 'tools/patch/KernelCodec.java',
               'runtimeNativeEntry': ROOT / 'runtime/src/exec_main.cpp',
               'runtimeKeyTransform': ROOT / 'runtime/upstream/src/jni/rootkit_command.cpp',
               'runtimeManagerEntry': ROOT / 'manager/src/main/java/dev/maplesu/manager/runtime/MapleSuCommandExecutor.kt',
               'java': java, 'javac': javac, 'python': Path(sys.executable)}
    if args.credential_file is not None:
        sources['credentialFile'] = args.credential_file.resolve()
    before = {name: sha256(path) for name, path in sources.items()}
    record['sourceInputs'] = {name: {'path': str(path.resolve()), 'sha256': before[name]}
                              for name, path in sources.items()}
    record['toolchain'] = {'java': run([str(java), '--version']).strip(),
                           'javac': run([str(javac), '--version']).strip(), 'python': sys.version}

    boot_bytes = boot.read_bytes()
    raw = bytearray(kernel_raw.read_bytes())
    if boot_bytes[:8] != b'ANDROID!' or len(boot_bytes) < 4096:
        fail('boot image is not an Android boot container')
    header_version = struct.unpack_from('<I', boot_bytes, 40)[0]
    header_size = struct.unpack_from('<I', boot_bytes, 20)[0]
    kernel_size = struct.unpack_from('<I', boot_bytes, 8)[0]
    ramdisk_size = struct.unpack_from('<I', boot_bytes, 12)[0]
    if (header_version, header_size) != (4, 1584):
        fail(f'expected boot v4/1584, got v{header_version}/{header_size}')
    if len(raw) < 64 or raw[56:60] != b'ARMd':
        fail('kernel is not a raw ARM64 image')
    record['inputs'] = {
        'boot': {'path': str(boot), 'size': len(boot_bytes), 'sha256': digest(boot_bytes)},
        'kernel': {'path': str(kernel_raw), 'size': len(raw), 'sha256': digest(bytes(raw))},
        'layout': {'headerVersion': header_version, 'headerSize': header_size,
                   'kernelOffset': 4096, 'kernelSize': kernel_size, 'ramdiskSize': ramdisk_size},
    }
    if record['inputs']['boot']['sha256'] != before['boot'] or record['inputs']['kernel']['sha256'] != before['kernel']:
        fail('input changed while reading the source snapshot')
    classes = work / 'classes'
    classes.mkdir()
    run([str(javac), '-cp', str(args.jar), '-d', str(classes), str(sources['codecDriver'])])
    classpath = str(args.jar) + os.pathsep + str(classes)
    source_inspect = json.loads(run([str(java), '-jar', str(args.jar), 'inspect', str(boot)]))
    record['steps'].append(check_source_pair(boot_bytes, bytes(raw), source_inspect,
                                             java, classpath, work))

    plan_text = run([str(args.analyzer), '--plan', str(kernel_raw)])
    plan_again = run([str(args.analyzer), '--plan', str(kernel_raw)])
    if plan_text != plan_again:
        fail('analyzer plan is not deterministic for the same input')
    (work / 'plan.txt').write_text(plan_text, encoding='utf-8')
    edits, slot = parse_plan(plan_text)
    record['steps'].append({'name': 'analyze', 'exitCode': 0, 'edits': len(edits),
                            'planSha256': sha256(work / 'plan.txt'), 'slot': slot,
                            'deterministic': True})

    key = credential[:-1]  # Match the unchanged upstream get_root() transformation.
    patched = bytearray(raw)
    slot_start = apply_plan(patched, edits, slot, key)
    changed = sum(1 for a, b in zip(raw, patched) if a != b)
    record['steps'].append({'name': 'apply-plan', 'changedBytes': changed, 'credentialSlot': slot_start})

    edited_ranges = [(e['offset'], e['offset'] + len(e['replacement'])) for e in edits]
    outside = [i for i in range(len(raw)) if raw[i] != patched[i]
               and not any(start <= i < end for start, end in edited_ranges)]
    if outside:
        fail(f'{len(outside)} changed bytes fall outside the planned edit ranges')
    for edit in edits:
        start, size = edit['offset'], len(edit['replacement'])
        expected = bytearray(edit['replacement'])
        if start <= slot_start < start + size:
            offset = slot_start - start
            expected[offset:offset + KEY_LEN] = key.encode('ascii') + b'\x00'
        if bytes(patched[start:start + size]) != bytes(expected):
            fail(f'patched region differs from the plan at offset {start}')
    record['steps'].append({'name': 'structural-checks',
                            'diffsInsidePlannedRanges': True,
                            'allPlannedRegionsMatch': True,
                            'changedOffsets': changed})

    patched_raw = out / 'kernel.patched.raw'
    patched_raw.write_bytes(patched)
    key_file = out / 'candidate-root-key.txt'
    key_file.write_text(credential + '\n', encoding='ascii')
    record['credentialInitialized'] = True

    compression = source_inspect['compression']
    extension = {'RAW_ARM64': 'raw', 'GZIP': 'gz', 'LZ4_LEGACY': 'lz4'}[compression]
    compressed = out / ('kernel.patched.' + extension)
    if compressed != patched_raw:
        run([str(java), '-cp', classpath, 'dev.maplesu.image.KernelCodec', 'encode',
             str(patched_raw), str(compressed), compression])
    roundtrip = work / 'kernel.roundtrip.raw'
    run([str(java), '-cp', classpath, 'dev.maplesu.image.KernelCodec', 'decode',
         str(compressed), str(roundtrip), compression])
    if roundtrip.read_bytes() != bytes(patched):
        fail('codec round-trip differs from the patched kernel')
    record['steps'].append({'name': 'encode', 'format': compression, 'rawBytes': len(patched),
                            'compressedBytes': compressed.stat().st_size,
                            'compressedSha256': sha256(compressed), 'roundTripVerified': True})

    repack_dir = out / 'container'
    run([sys.executable, str(args.repack), '--boot', str(boot), '--kernel', str(compressed),
         '--output-directory', str(repack_dir)])
    rebuild = json.loads((repack_dir / 'rebuild.json').read_text(encoding='utf-8'))
    if not rebuild.get('passed'):
        fail('container rebuild did not pass: ' + str(rebuild.get('error')))
    candidate = Path(rebuild['candidate']['path'])
    record['steps'].append({'name': 'rebuild-container', 'candidate': str(candidate),
                            'size': candidate.stat().st_size, 'sha256': sha256(candidate),
                            'containerVerified': rebuild.get('containerVerified'),
                            'replacementKernelVerified': rebuild.get('replacementKernelVerified'),
                            'ramdiskPreserved': rebuild.get('ramdiskPreserved')})
    record['rebuildEvidence'] = {'path': str(repack_dir / 'rebuild.json'),
                                  'sha256': sha256(repack_dir / 'rebuild.json'),
                                  'aospSources': rebuild['aospSources']}

    inspect = json.loads(run([str(java), '-jar', str(args.jar), 'inspect', str(candidate)]))
    if inspect['headerVersion'] != 4 or inspect['compression'] != compression:
        fail('candidate header or compression changed')
    if inspect['kernelSize'] != compressed.stat().st_size:
        fail('candidate kernel size differs from the patched component')
    if inspect['ramdiskSize'] != ramdisk_size:
        fail('candidate ramdisk size differs from the original')
    extracted = work / 'candidate-kernel.component'
    extracted.write_bytes(candidate.read_bytes()[inspect['kernelOffset']:
                                                 inspect['kernelOffset'] + inspect['kernelSize']])
    decoded = work / 'candidate-kernel.raw'
    run([str(java), '-cp', classpath, 'dev.maplesu.image.KernelCodec', 'decode',
         str(extracted), str(decoded), compression])
    if decoded.read_bytes() != bytes(patched):
        fail('candidate kernel payload differs from the patched kernel')
    if decoded.read_bytes()[slot_start:slot_start + KEY_LEN] != key.encode('ascii') + b'\x00':
        fail('candidate credential slot differs from the requested key')
    record['steps'].append({'name': 'verify-candidate', 'inspect': inspect, 'payloadMatch': True,
                            'credentialPresent': True})

    record.update({
        'passed': True,
        'candidate': {'path': str(candidate), 'size': candidate.stat().st_size, 'sha256': sha256(candidate)},
        'patchedKernel': {'path': str(patched_raw), 'size': patched_raw.stat().st_size,
                          'sha256': sha256(patched_raw)},
        'patchedComponent': {'path': str(compressed), 'format': compression,
                             'size': compressed.stat().st_size, 'sha256': sha256(compressed)},
        'credential': {'keyFile': str(key_file), 'keySha256': digest(credential.encode('ascii')),
                       'runtimeInputLength': KEY_LEN, 'kernelComparedLength': KEY_LEN - 1,
                       'slotLength': KEY_LEN, 'runtimeTransform': 'drop-last-character',
                       'contractVerifiedStatically': True, 'runtimeElevationVerified': False},
        'changedBytes': changed, 'planEdits': len(edits),
        'candidateGkiSignaturePresent': False, 'candidateAvbFooterPresent': False,
        'sources': {'analyzer': sha256(args.analyzer), 'repack': sha256(args.repack),
                    'imageCoreJar': sha256(args.jar), 'builder': sha256(Path(__file__)),
                    'codecDriver': sha256(sources['codecDriver'])},
    })


if __name__ == '__main__':
    sys.exit(main())
