"""Replace embedded-executable output streams; preserve the shipped payloads."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar, compare_members

ROOT = Path(__file__).resolve().parents[1]


def function_body(ir, symbol):
    match = re.search(r'^define[^\n]*@' + re.escape(symbol) + r'\([^\n]*\{\n.*?\n}', ir, re.M | re.S)
    assert match, symbol
    body = match[0]
    entry = 1 if re.search(r'\(ptr noundef %0\)', body.splitlines()[0]) else 0
    body = re.sub(r'%(\d+)\b', r'%sdk\1', body)
    body = re.sub(r'^(\d+):[^\n]*', r'sdk\1:', body, flags=re.M)
    return match, body.replace('{\n', '{\nsdk' + str(entry) + ':\n', 1)


def publish_declaration(ir, context):
    label = context.encode() + b'\0'
    return ir + f'\n@maplesu.exec.context = private unnamed_addr constant [{len(label)} x i8] c"{context}\\00"\n' + \
        '\ndeclare i64 @maplesu_publish_executable(ptr, ptr, i64, ptr)\n'


def patch_stream(ir, symbol, start, end, join, payload, size, path, old_result, old_block, exception, context):
    # Name SSA values/blocks so deleting the stream does not renumber later IR.
    match, body = function_body(ir, symbol)
    first = body.index(f'\nsdk{start}:')
    last = body.index(f'\nsdk{end}:', first)
    region = body[first:last]
    assert 'basic_ofstream' in region and '5writeEPKcl' in region
    data = f'load ptr, ptr %sdk{payload}' if isinstance(payload, int) else None
    pointer = '%publish.data' if data else payload
    load = f'  %publish.data = {data}\n' if data else ''
    body = body[:first] + f'''\nsdk{start}:
{load}  %publish.result = call i64 @maplesu_publish_executable(ptr %sdk{path}, ptr {pointer}, i64 {size}, ptr @maplesu.exec.context)
  br label %sdk{join}
''' + body[last:]
    before = f'[ %sdk{old_result}, %sdk{old_block} ]'
    assert body.count(before) == 1
    body = body.replace(before, f'[ %publish.result, %sdk{start} ]')
    incoming = f'[ %sdk{exception[0]}, %sdk{exception[1]} ], '
    assert body.count(incoming) == 1
    body = body.replace(incoming, '')
    ir = ir[:match.start()] + body + ir[match.end():]
    return publish_declaration(ir, context)


def patch_resetprop(ir):
    match, body = function_body(ir, '_ZN7maplesu3sdk24unsafe_install_resetpropEv')
    first = body.index('  call void @llvm.lifetime.start.p0(i64 328, ptr nonnull %sdk1)', body.index('\nsdk50:'))
    last = body.index('\nsdk71:', first)
    assert 'basic_ofstream' in body[first:last] and '5writeEPKcl' in body[first:last]
    body = body[:first] + '''  %publish.result = call i64 @maplesu_publish_executable(ptr %sdk57, ptr @_ZN7maplesu3sdkL19resetprop_file_dataE, i64 400568, ptr @maplesu.exec.context)
  %publish.ok = icmp eq i64 %publish.result, 0
  br i1 %publish.ok, label %sdk71, label %sdk87
''' + body[last:]
    old = '[ %sdk68, %sdk67 ]'
    assert body.count(old) == 1
    body = body.replace(old, '[ %publish.result, %sdk50 ]')
    old = '[ %sdk86, %sdk85 ], [ %sdk70, %sdk69 ], [ %sdk63, %sdk62 ]'
    assert body.count(old) == 1
    body = body.replace(old, '[ %sdk86, %sdk85 ]')
    return publish_declaration(ir[:match.start()] + body + ir[match.end():], 'u:object_r:system_file:s0')


def keep_bootstrap_until_publish(ir):
    symbol = '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv'
    match = re.search(r'^define[^\n]*@' + symbol + r'\([^\n]*\{\n.*?\n}', ir, re.M | re.S)
    body = match[0]
    first = body.index('  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %sdk13)')
    last = body.index('\nsdk71:', first)
    assert '@rename(' in body[first:last] and 'delete_path' in body[first:last]
    body = body[:first] + '  br label %sdk71\n' + body[last:]
    old = '[ %sdk70, %sdk69 ], [ %sdk52, %sdk51 ], '
    assert body.count(old) == 1
    body = body.replace(old, '')
    return ir[:match.start()] + body + ir[match.end():]


def object_contract(blob):
    elf = ELFFile(io.BytesIO(blob))
    alloc = {s.name: (s['sh_flags'], s['sh_type'], s.data()) for s in elf.iter_sections() if s['sh_flags'] & 2}
    symbols = elf.get_section_by_name('.symtab')
    public = sorted((s.name, s['st_info']['bind'], s['st_info']['type'], s['st_other']['visibility'],
                     s['st_shndx'] == 'SHN_UNDEF') for s in symbols.iter_symbols() if s['st_info']['bind'] != 'STB_LOCAL')
    relocations = []
    for section in elf.iter_sections():
        if section['sh_type'] != 'SHT_RELA':
            continue
        for relocation in section.iter_relocations():
            symbol = symbols.get_symbol(relocation['r_info_sym'])
            name = symbol.name or elf.get_section(symbol['st_shndx']).name
            relocations.append((section.name, relocation['r_offset'], relocation['r_info_type'], name, relocation['r_addend']))
    return alloc, public, sorted(relocations)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    original = args.archive.read_bytes()
    manifest = json.loads((ROOT / 'runtime/ultra/upgrade/sdk-inputs.json').read_text())
    assert hashlib.sha256(original).hexdigest() == manifest['baselineArchiveSha256'], 'Use the frozen r12 baseline'
    before = parse_ar(str(args.archive))
    tools = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin'

    def run(name, *argv):
        result = subprocess.run([str(tools / (name + '.exe')), *map(str, argv)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    specs = [
        (48, '_ZN7maplesu3sdkL13write_su_execEPKc', 56, 73, 74, 3, 741912, 0, 70, 69, (72, 71), 'u:object_r:system_file:s0'),
        (50, '_ZN7maplesu3sdk27unsafe_install_webui_loaderEv', 141, 158, 161, 2, 766320, 88, 155, 154, (157, 156), 'u:object_r:system_file:s0'),
        (52, '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv', 131, 148, 151, 10, 1215088, 78, 145, 144, (147, 146), 'u:object_r:kernel:s0'),
    ]
    rebuilt, inputs = [], []
    payloads = {}
    for entry in manifest['inputs']:
        ordinal = entry['ordinal']
        source = ROOT / entry['path']
        assert hashlib.sha256(source.read_bytes()).hexdigest() == entry['sha256']
        member = before['members'][ordinal]
        assert member['name'] == entry['baselineMemberName'] and member['sha256'] == entry['baselineMemberSha256']
        blob = original[member['body_offset']:member['body_offset'] + member['size']]
        baseline = out / f'm{ordinal:03d}.baseline.ll'
        run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', source, '-o', baseline)
        baseline_obj = out / f'm{ordinal:03d}.baseline.o'
        run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', baseline, '-o', baseline_obj)
        native = baseline_obj.read_bytes()
        if blob.startswith(b'\x7fELF'):
            assert object_contract(blob) == object_contract(native), f'm{ordinal:03d} baseline code or ABI drift'
        current_data = ELFFile(io.BytesIO(native)).get_section_by_name('.data').data()
        ir = baseline.read_text()
        patched = out / f'm{ordinal:03d}.patched.ll'
        if ordinal == 49:
            updated = patch_resetprop(ir)
        else:
            spec = next(spec for spec in specs if spec[0] == ordinal)
            updated = patch_stream(ir, *spec[1:])
            if ordinal == 52:
                updated = keep_bootstrap_until_publish(updated)
        patched.write_text(updated)
        obj = out / member['name']
        run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', patched, '-o', obj)
        assert ELFFile(io.BytesIO(obj.read_bytes())).get_section_by_name('.data').data() == current_data
        rebuilt.append(obj)
        payloads[str(ordinal)] = hashlib.sha256(current_data).hexdigest()
        inputs.append(dict(ordinal=ordinal, source=entry['path'], sourceSha256=entry['sha256'], payloadSha256=payloads[str(ordinal)], baselineCodeAndAbiVerified=True))
    atomic = out / 'maplesu_executable_publish.o'
    run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fvisibility=hidden',
        '-I', ROOT / 'runtime/maplesu-sdk/include', '-c', ROOT / 'runtime/ultra/upgrade/executable_publish.cpp', '-o', atomic)
    combined = out / 'su-with-publisher.o'
    run('ld.lld', '-r', rebuilt[0], atomic, '-o', combined)
    rebuilt[0].write_bytes(combined.read_bytes())
    candidate = out / args.archive.name
    assert candidate.resolve() != args.archive.resolve()
    candidate.write_bytes(original)
    run('llvm-ar', 'rD', candidate, *rebuilt)
    run('llvm-ar', 'sD', candidate)
    diff = compare_members(before, parse_ar(str(candidate)))
    assert [m['ord'] for m in diff['changed']] == [48, 49, 50, 52]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    metadata = dict(baselineArchiveSha256=hashlib.sha256(original).hexdigest(),
        archiveSha256=hashlib.sha256(candidate.read_bytes()).hexdigest(), memberDiff=diff, inputs=inputs,
        sourceSha256=hashlib.sha256((ROOT / 'runtime/ultra/upgrade/executable_publish.cpp').read_bytes()).hexdigest(),
        embeddedExecutablesChanged=False, baselineCodeAndAbiVerified=True, payloadSha256=payloads, deviceAcceptance=False)
    (out / 'build.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
