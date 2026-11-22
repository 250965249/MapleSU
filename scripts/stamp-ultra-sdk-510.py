"""Stamp the repaired SDK and helper; retain legacy module ABI and storage names."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar

DISPLAY = {
    b'MapleSU Default Module\n': b'MapleSU built-in mods\n',
    b'MapleSU Module\n': b'MapleSU mod\n',
    b'MapleSU Default Module': b'MapleSU Built-in Mods',
    b'MapleSU Module': b'MapleSU Mod',
    b'[Module End] name=%s, maplesu_module_main=%s, elapsed=%lld ms\n':
        b'[Module End] name=%s, module_entry=%s, elapsed=%lld ms\n',
    b'ERR_MAPLESU_ENV_NOT_INSTALL': b'ERR_MAPLESU_ENV_UNPREPARED',
    bytes.fromhex('736b726f6f742073646b3a2025752e25752e25750a'): b'MapleSU: %u.%u.%u\n',
    b'[MapleSU] set_current_module_run_state failed: id32=%s, state=%u, errno=%d (%s)\n':
        b'MapleSU: set_current_module_run_state failed: id32=%s, state=%u, errno=%d (%s)\n',
    b'[MapleSU] set_current_module_description failed: id32=%s, errno=%d (%s)\n':
        b'MapleSU: set_current_module_description failed: id32=%s, errno=%d (%s)\n',
}


def escaped(data):
    return ''.join(chr(b) if 32 <= b < 127 and b not in (34, 92) else '\\%02X' % b for b in data)


def replace_literals(data, mapping):
    changes = []
    for old, new in mapping.items():
        assert len(new) <= len(old), (old, new)
        needle = old + b'\0'
        count = data.count(needle)
        if count:
            data = data.replace(needle, new + bytes(len(needle)-len(new)))
            changes.append({'old': old.decode(), 'new': new.decode(), 'occurrences': count})
    return data, changes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    def run(name, *argv):
        subprocess.run([str(tool / (name+'.exe')), *map(str, argv)], check=True, capture_output=True)
    before = parse_ar(str(args.archive))
    data = args.archive.read_bytes()
    assert hashlib.sha256(data).hexdigest() == '18883676a595108a32032fb6d4ea4fcc78ec7e99af289e98f43301cc3517165b'
    rebuilt, literals, remaining = [], [], []
    helper = bytearray(args.helper.read_bytes())
    assert hashlib.sha256(helper).hexdigest() == '6ce823025ae594a7d5fe854461ab5f40daf76d2134191ea7899b8dcb899cf49e'
    helper, edits = replace_literals(helper, DISPLAY | {b'4.6.5': b'5.1.0'})
    assert any(x['old'] == '4.6.5' and x['occurrences'] == 1 for x in edits)
    assert helper[0x256e1:0x256e7] == b'5.1.0\0'
    literals.append({'member': 52, 'helper': edits})
    elf = ELFFile(io.BytesIO(helper))
    note = elf.get_section_by_name('.note.gnu.build-id')
    at = note['sh_offset'] + 16
    helper[at:at+20] = bytes(20)
    normalized = bytearray(helper)
    normalized[182886:182886+4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[at:at+20] = normalized[at:at+20] = build_id
    (args.out / 'embedded-bootstrap.elf').write_bytes(helper)
    for member in before['members']:
        ordinal = member['ord']
        payload = data[member['body_offset']:member['body_offset']+member['size']]
        obj = args.out / member['name']
        if payload.startswith(b'\x7fELF'):
            changed = False
            if ordinal == 52:
                original_helper = args.helper.read_bytes()
                assert payload.count(original_helper) == 1
                payload = payload.replace(original_helper, helper)
                changed = True
            elif ordinal == 53:
                assert payload.count(b'5.0.5\0') == 1
                payload, edits = replace_literals(payload, {b'5.0.5': b'5.1.0'})
                changed = True
                literals.append({'member': ordinal, 'edits': edits})
            payload, edits = replace_literals(payload, DISPLAY)
            if edits:
                changed = True
                literals.append({'member': ordinal, 'edits': edits})
            if changed:
                obj.write_bytes(payload)
                rebuilt.append(obj)
            continue
        assert payload.startswith(b'BC\xc0\xde'), member['name']
        bc = args.out / ('m%03d.original.bc' % ordinal)
        ll = bc.with_suffix('.ll')
        bc.write_bytes(payload)
        run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', bc, '-o', ll)
        ir = ll.read_text()
        patched = ir
        edits = []
        if ordinal == 52:
            match = re.search(r'\[145416 x i64\] \[(.*?)\]', ir)
            assert match
            words = struct.unpack('<'+'q'*145416, helper)
            patched = ir[:match.start(1)] + ', '.join('i64 '+str(x) for x in words) + ir[match.end(1):]
        # The SDK also carries standalone su and WebUI loader ELFs as i64 arrays.
        # Their display names/error text are independent of outer-layer literals.
        if ordinal in (48, 50):
            def embedded_display(match):
                values = [int(x)&((1<<64)-1) for x in re.findall(r'i64 (-?\d+)', match[2])]
                assert len(values) == int(match[1])
                payload = struct.pack('<'+'Q'*len(values), *values)
                if not payload.startswith(b'\x7fELF'): return match[0]
                payload, display_edits = replace_literals(payload, DISPLAY)
                if not display_edits: return match[0]
                payload = bytearray(payload)
                embedded = ELFFile(io.BytesIO(payload))
                note = embedded.get_section_by_name('.note.gnu.build-id')
                if note is not None:
                    note_at = note['sh_offset']+16
                    payload[note_at:note_at+20] = bytes(20)
                    payload[note_at:note_at+20] = hashlib.sha1(payload).digest()
                (args.out/('m%03d.embedded.elf'%ordinal)).write_bytes(payload)
                edits.extend(display_edits)
                words = struct.unpack('<'+'q'*len(values), payload)
                return '['+match[1]+' x i64] ['+', '.join('i64 '+str(x) for x in words)+']'
            patched = re.sub(r'\[(\d+) x i64\] \[(.*?)\]', embedded_display, patched)
        for old, new in DISPLAY.items():
            # Descriptor names can occupy larger fixed-size, zero-filled arrays.
            # Replace the complete NUL-terminated value without changing width.
            needle = escaped(old+b'\0')
            count = patched.count(needle)
            if count:
                replacement = new + bytes(len(old)+1-len(new))
                patched = patched.replace(needle, escaped(replacement))
                edits.append({'old': old.decode(), 'new': new.decode(), 'occurrences': count})
        for line in patched.splitlines():
            if line.startswith('@') and ' c"' in line and bytes.fromhex('736b726f6f74').decode() in line.lower():
                remaining.append({'member': ordinal, 'constant': line[:350]})
        if patched != ir:
            path = args.out / ('m%03d.patched.ll' % ordinal)
            path.write_text(patched)
            run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', path, '-o', obj)
            rebuilt.append(obj)
            if edits: literals.append({'member': ordinal, 'edits': edits})
        # Keep only changed IR and the compatibility metadata member for review.
        if patched == ir and ordinal not in (54, 63):
            ll.unlink()
            bc.unlink()
    archive = args.out / 'libkernel_module_kit_static.a'
    assert archive.resolve() != args.archive.resolve()
    archive.write_bytes(data)
    run('llvm-ar', 'rD', archive, *rebuilt)
    run('llvm-ar', 'sD', archive)
    after = parse_ar(str(archive))
    assert len(before['members']) == len(after['members']) == 255
    changes = []
    for old, new in zip(before['members'], after['members']):
        assert old['name'] == new['name']
        if old['sha256'] != new['sha256']:
            changes.append({'ordinal': old['ord'], 'name': old['name'], 'before': old['sha256'], 'after': new['sha256']})
    sha = lambda value: hashlib.sha256(value).hexdigest()
    metadata = {'sdkVersion': '5.1.0', 'archiveSha256': sha(archive.read_bytes()),
        'baselineArchiveSha256': sha(data), 'memberChanges': changes,
        'helperSha256': sha(helper), 'helperNormalizedSha256': sha(normalized),
        'helperBuildId': build_id.hex(), 'displayEdits': literals,
        'preservedCompatibilityConstants': remaining,
        'compatibility': 'Legacy mangled symbols, descriptors, callbacks, module entry and storage names retained.'}
    (args.out / 'build.json').write_text(json.dumps(metadata, indent=2)+'\n')
    print(json.dumps({k: metadata[k] for k in ['sdkVersion','archiveSha256','memberChanges','helperBuildId']}, indent=2))


if __name__ == '__main__':
    main()
