"""Package the reviewed read repair and helper without changing published SDK inputs."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
sha = lambda data: hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--read-report', required=True, type=Path)
    parser.add_argument('--helper-entry', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'work') and not out.exists()
    production = ROOT / 'runtime/maplesu-sdk'
    release_bytes = (production / 'SDK-RELEASE.json').read_bytes()
    manifest = json.loads(release_bytes)
    archive = args.archive.resolve()
    original = archive.read_bytes()
    read = json.loads(args.read_report.read_bytes())
    assert read['passed'] and sha(original) == read['archiveSha256']
    assert read['baselineArchiveSha256'] == manifest['archive']['sha256']
    for name, expected in read['sources'].items():
        assert sha((ROOT / name).read_bytes()) == expected, name
    entry = json.loads((args.helper_entry / 'build.json').read_bytes())
    helper = (args.helper_entry / 'candidate-helper.elf').read_bytes()
    assert sha(helper) == entry['helperSha256']
    assert entry['baselineHelperSha256'] == manifest['helper']['sha256']
    assert entry['keySlotPreserved'] and entry['dynamicMetadataPreserved']
    assert entry['requestCredentialIsolationPreserved']
    required_sources = {
        'runtime/ultra/authorization/helper_kernel_read.cpp',
        'runtime/ultra/authorization/helper_kernel_read.S',
        'runtime/ultra/authorization/kernel_read_metadata.h',
        'scripts/update-ultra-helper-kernel-read.py',
    }
    assert required_sources <= entry['sources'].keys()
    for name, expected in entry['sources'].items():
        source = (ROOT / name).resolve()
        assert source.is_relative_to(ROOT) and sha(source.read_bytes()) == expected, name
    replay = entry['callbackReplay']
    replay_path = (ROOT / replay['path']).resolve()
    assert replay_path.is_relative_to(ROOT / 'work')
    assert sha(replay_path.read_bytes()) == replay['sha256']
    replay_report = json.loads(replay_path.read_bytes())
    assert replay_report['passed'] and replay_report['helperSha256'] == entry['helperSha256']
    assert replay_report['baselineHelperSha256'] == entry['baselineHelperSha256']
    assert len(helper) == entry['helperBytes']
    helper_elf = ELFFile(io.BytesIO(helper))
    assert list(helper_elf.get_section_by_name('.note.gnu.build-id').iter_notes())[0]['n_desc'] == entry['helperBuildId']
    patch, extension = entry['entryPatch'], entry['extension']
    assert len(bytes.fromhex(patch['baselineHex'])) == len(bytes.fromhex(patch['candidateHex'])) == 4
    assert helper[patch['offset']:patch['offset'] + 4].hex() == patch['candidateHex']
    blob = helper[extension['offset']:extension['offset'] + extension['bytes']]
    assert len(blob) == extension['bytes'] and sha(blob) == extension['sha256']
    assert any(segment['p_type'] == 'PT_LOAD' and segment['p_offset'] <= extension['offset'] and
               extension['offset'] + extension['bytes'] <= segment['p_offset'] + segment['p_filesz'] and
               extension['address'] == segment['p_vaddr'] + extension['offset'] - segment['p_offset']
               for segment in helper_elf.iter_segments())
    before = parse_ar(str(archive))

    def body(parsed, data, ordinal):
        member = parsed['members'][ordinal]
        return data[member['body_offset']:member['body_offset'] + member['size']]

    old_installer = body(before, original, 52)
    old_helper = ELFFile(io.BytesIO(old_installer)).get_section_by_name('.data').data()
    assert sha(old_helper) == manifest['helper']['sha256']
    assert old_helper == (production / 'helper/autorun_bootstrap').read_bytes()
    assert old_helper[patch['offset']:patch['offset'] + 4].hex() == patch['baselineHex']
    slot = manifest['helper']['keySlotOffset']
    assert helper[slot:slot + 4096] == old_helper[slot:slot + 4096]
    normalized = bytearray(helper)
    normalized[slot:slot + 4096] = bytes(4096)
    assert sha(normalized) == entry['helperNormalizedSha256']
    out.mkdir(parents=True)
    tool = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    commands = []

    def run(name, *arguments):
        command = [str(tool / (name + '.exe')), *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, encoding='utf-8', errors='replace')
        commands.append(dict(command=command, exitCode=result.returncode, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    spec = importlib.util.spec_from_file_location('sdk_upgrade', ROOT / 'scripts/repair-ultra-environment-upgrade.py')
    upgrade = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(upgrade)
    frozen = production.parent / 'ultra/upgrade/sdk-m052.bc'
    assert sha(frozen.read_bytes()) == '342b920914ad62f700398482f8bfd403344e54cf36f032a77c51d0c1e306d3c2'
    input_ir = out / 'm052.input.ll'
    run('clang', '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', frozen, '-o', input_ir)
    ir = upgrade.patch_stream(input_ir.read_text(), '_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv',
                              131, 148, 151, 10, 1215088, 78, 145, 144, (147, 146), 'u:object_r:kernel:s0')
    ir = upgrade.keep_bootstrap_until_publish(ir).replace('5.1.0', manifest['sdkVersion'])
    payload = re.compile(r'^(@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE = internal global )[^\n]+, align 8$', re.M)
    assert len(payload.findall(ir)) == 1

    def installer(blob, label):
        encoded = ''.join('\\%02X' % byte for byte in blob)
        text = payload.sub(lambda m: m[1] + f'[{len(blob)} x i8] c"' + encoded + '", align 8', ir)
        text = re.sub(r'\b1215088\b', str(len(blob)), text)
        source, target = out / (label + '.ll'), out / (label + '.o')
        source.write_text(text, encoding='utf-8', newline='\n')
        run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', source, '-o', target)
        return target

    baseline = installer(old_helper, 'm052.baseline')
    contract = upgrade.object_contract(old_installer)
    assert upgrade.object_contract(baseline.read_bytes()) == contract, 'Installer baseline drift'
    built_installer = installer(helper, 'm052.candidate')
    assert upgrade.object_contract(built_installer.read_bytes())[1:] == contract[1:]
    assert ELFFile(io.BytesIO(built_installer.read_bytes())).get_section_by_name('.data').data() == helper
    gate = manifest['moduleControl']
    control_source = ROOT / 'runtime/ultra/modules/module_control.cpp'
    assert sha(control_source.read_bytes()) == gate['sourceSha256']

    def control(blob, label):
        target = out / label
        target.mkdir()
        elf = ELFFile(io.BytesIO(blob))
        index, _ = max(((i, s) for i, s in enumerate(elf.iter_segments()) if s['p_type'] == 'PT_LOAD'),
                       key=lambda row: row[1]['p_vaddr'])
        ph = elf['e_phoff'] + index * elf['e_phentsize']
        gate_at, size, branch_at = gate['gateFileOffset'], gate['gateBytes'], 0xa6d68
        header = (f'#pragma once\n#define MAPLESU_GATE_FILE_OFFSET {gate_at}\n'
                  f'#define MAPLESU_GATE_BRANCH_OFFSET {branch_at}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n')
        for name, data in [('bytes', blob[gate_at:gate_at + size]), ('branch', blob[branch_at:branch_at + 4]),
                           ('phdr', blob[ph:ph + 56])]:
            header += 'static constexpr unsigned char maplesu_gate_' + name + '[] = {' + ','.join(map(str, data)) + '};\n'
        (target / 'module_gate_identity.h').write_text(header, encoding='utf-8', newline='\n')
        obj = target / 'maplesu_module_control.o'
        run('clang++', '--target=aarch64-linux-android21', '-std=c++17', '-Oz', '-fPIC', '-fexceptions',
            '-ffunction-sections', '-fdata-sections', '-I', production / 'include', '-I', target,
            '-c', control_source, '-o', obj)
        return obj

    old_control = control(old_helper, 'baseline')
    contract = upgrade.object_contract(body(before, original, 255))
    assert upgrade.object_contract(old_control.read_bytes()) == contract, 'Gate baseline drift'
    new_control = control(helper, 'candidate')
    assert upgrade.object_contract(new_control.read_bytes())[1:] == contract[1:]
    installer_path = out / before['members'][52]['name']
    installer_path.write_bytes(built_installer.read_bytes())
    candidate = out / 'lib/arm64-v8a/libkernel_module_kit_static.a'
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(original)
    run('llvm-ar', 'rD', candidate, installer_path, new_control)
    run('llvm-ar', 'sD', candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [row['ord'] for row in diff['changed']] == [52, 255]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    assert after['members'][23]['sha256'] == before['members'][23]['sha256']
    (out / 'helper').mkdir()
    (out / 'helper/autorun_bootstrap').write_bytes(helper)
    assert archive.read_bytes() == original
    assert (production / 'SDK-RELEASE.json').read_bytes() == release_bytes
    report = dict(passed=True, baselineArchiveSha256=sha(original), archiveSha256=sha(candidate.read_bytes()),
                  helperSha256=sha(helper), memberDiff=diff, installerBaselineReproduced=True,
                  gateBaselineReproduced=True, canonicalReadMemberPreserved=True, productionModified=False,
                  sources={Path(__file__).relative_to(ROOT).as_posix(): sha(Path(__file__).read_bytes())}, commands=commands)
    (out / 'packaging.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS helper installer and gate packaged; read member and unrelated SDK members preserved')


if __name__ == '__main__':
    main()
