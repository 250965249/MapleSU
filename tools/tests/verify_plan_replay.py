"""Independently replay and compare the host/Android experimental plans; writes evidence only."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def verify_plan(text, source):
    def one(pattern):
        values = re.findall(pattern, text, re.MULTILINE)
        if len(values) != 1:
            raise ValueError('Missing or ambiguous plan marker')
        return values[0]

    if re.search(r'(?m)^\w+_FAILED\s*$', text):
        raise ValueError('Plan log contains a failure')
    count = int(one(r'^PATCH_PLAN_OK edits=(\d+) credentialInitialized=false flashableCandidate=false\s*$'))
    changed = int(one(r'^PLAN_REPLAY_OK changedBytes=(\d+)\s*$'))
    slot, slot_length = map(int, one(r'^PLAN_SLOT offset=(\d+) length=(\d+)\s*$'))
    lines = [line for line in text.splitlines() if line.startswith('PLAN_EDIT')]
    if len(lines) != count or not count:
        raise ValueError('Plan edit count mismatch')
    output = bytearray(source)
    previous_end = 64
    edits = []
    for line in lines:
        match = re.fullmatch(r'PLAN_EDIT offset=(\d+) expected=([0-9a-fA-F]+) replacement=([0-9a-fA-F]+)', line)
        if not match:
            raise ValueError('Malformed plan edit')
        offset = int(match[1])
        before, after = bytes.fromhex(match[2]), bytes.fromhex(match[3])
        end = offset + len(before)
        if offset < previous_end or len(before) != len(after) or end > len(source):
            raise ValueError('Plan ranges overlap or exceed input')
        if source[offset:end] != before:
            raise ValueError('Plan preimage differs from input')
        output[offset:end] = after
        previous_end = end
        edits.append([offset, before.hex(), after.hex()])
    if changed != sum(a != b for a, b in zip(source, output)) or changed <= 0:
        raise ValueError('Replay change count mismatch')
    if slot_length != 48 or slot < 64 or slot + slot_length > len(source):
        raise ValueError('Invalid credential slot')
    if not any(offset <= slot and slot + slot_length <= offset + len(bytes.fromhex(after))
               for offset, before, after in edits):
        raise ValueError('Credential slot is outside plan')
    if output[slot:slot + slot_length] != bytes(slot_length):
        raise ValueError('Experimental plan contains initialized credentials')
    return {'edits': count, 'changedBytes': changed, 'credentialSlot': slot,
            'credentialInitialized': False, 'flashableCandidate': False,
            'planSha256': hashlib.sha256(json.dumps(edits, separators=(',', ':')).encode('ascii')).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', required=True, type=Path)
    parser.add_argument('--host-log', default=ROOT / '.analysis/native-host-validation.log', type=Path)
    parser.add_argument('--android-log', required=True, type=Path)
    args = parser.parse_args()
    args.host_log = args.host_log.resolve()
    args.android_log = args.android_log.resolve()
    source = args.kernel.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    # The host harness also records deliberately rejected inputs before its final plan invocation.
    host_sections = args.host_log.read_text(encoding='utf-8-sig').split('[plan] exit=0\n')
    if len(host_sections) != 2:
        raise SystemExit('Missing or ambiguous successful host plan invocation')
    records = [verify_plan(host_sections[1], source),
               verify_plan(args.android_log.read_text(encoding='utf-8-sig'), source)]
    if records[0] != records[1]:
        raise SystemExit('Host and Android plans differ')
    if hashlib.sha256(args.kernel.read_bytes()).hexdigest() != digest:
        raise SystemExit('Input changed during replay verification')
    binaries = {'windows': ROOT / 'patch-engine/build/windows-x64/maplesu-kernel-analyze.exe',
                'android': ROOT / 'patch-engine/build/android-arm64/maplesu-kernel-analyze'}
    record = {'schemaVersion': 1, 'passed': True, 'sourceSha256': digest, 'sourceUnchanged': True,
              'sourcePath': args.kernel.resolve().relative_to(ROOT).as_posix(),
              'analyzers': {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
              'verifierSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'logs': {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in (args.host_log, args.android_log)},
              **records[0], 'hostAndroidPlansEqual': True,
              'scope': 'Independent in-memory replay of reported edits; no candidate or partition write.'}
    destination = ROOT / '.analysis/experimental-plan-validation.json'
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(f"PASS matching host/Android plan: {record['edits']} edits, {record['changedBytes']} changed bytes")


if __name__ == '__main__':
    main()
