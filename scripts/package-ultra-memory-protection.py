"""Package compile-verified permission-return repairs; device acceptance remains pending."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'work/panic-kernel-read-20261114'
PIN = '8dee1c71700ae5d97a744d46b08ada688d1c375ef43b79820ed716017450649d'
HELPER_PIN = '915c38312dad33bd905c80b21f3f712b2317fb96a2e5d2d8413101f24b0e50db'
sha = lambda data: hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', required=True, type=Path)
    parser.add_argument('--memory-entry', type=Path, default=WORK / 'memory-protection')
    parser.add_argument('--helper-entry', type=Path, default=WORK / 'helper-permissions')
    parser.add_argument('--out', type=Path, default=WORK / 'permission-packaged')
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(WORK) and not out.exists(), 'Use a fresh candidate output directory'
    production = ROOT / 'runtime/maplesu-sdk'
    release_bytes = (production / 'SDK-RELEASE.json').read_bytes()
    manifest = json.loads(release_bytes)
    archive = production / 'lib/arm64-v8a/libkernel_module_kit_static.a'
    original = archive.read_bytes()
    assert sha(original) == PIN == manifest['archive']['sha256']
    before = parse_ar(str(archive))

    def body(ordinal):
        member = before['members'][ordinal]
        return original[member['body_offset']:member['body_offset'] + member['size']]

    memory_dir, helper_dir = args.memory_entry.resolve(), args.helper_entry.resolve()
    assert memory_dir.is_relative_to(WORK) and helper_dir.is_relative_to(WORK)
    memory = json.loads((memory_dir / 'build.json').read_bytes())
    entry = json.loads((helper_dir / 'build.json').read_bytes())
    memory_object = memory_dir / 'module_base_kernel_mem.o'
    assert memory['passed'] and memory['archiveSha256'] == PIN and memory['memberOrdinal'] == 24
    assert memory['baselineReproducedExactly'] and memory['globalSymbolContractUnchanged']
    assert memory['changedCallSites'] == 3
    assert sha(memory_object.read_bytes()) == memory['candidateObjectSha256']
    assert (memory_dir / 'm024.baseline.o').read_bytes() == body(24)
    assert sha((memory_dir / 'm024.permissions.ll').read_bytes()) == memory['candidateIrSha256']
    assert sha((ROOT / 'scripts/update-ultra-memory-protection.py').read_bytes()) == memory['scriptSha256']
    helper = (helper_dir / 'candidate-helper.elf').read_bytes()
    old_helper = ELFFile(io.BytesIO(body(52))).get_section_by_name('.data').data()
    assert old_helper == (production / 'helper/autorun_bootstrap').read_bytes()
    assert sha(old_helper) == HELPER_PIN == entry['baselineHelperSha256'] == manifest['helper']['sha256']
    assert sha(helper) == entry['helperSha256'] and len(helper) == entry['helperBytes']
    for field in ('keySlotPreserved', 'originalSectionsWhitelistVerified', 'dynamicMetadataPreserved', 'originalUnwindMetadataPreserved'):
        assert entry[field], field
    for name, expected in entry['sources'].items():
        path = (ROOT / name).resolve()
        assert path.is_relative_to(ROOT) and sha(path.read_bytes()) == expected, name
    patch, extension = entry['entryPatch'], entry['extension']
    assert old_helper[patch['offset']:patch['offset'] + 4].hex() == patch['baselineHex']
    assert helper[patch['offset']:patch['offset'] + 4].hex() == patch['candidateHex']
    assert sha(helper[extension['offset']:extension['offset'] + extension['bytes']]) == extension['sha256']
    helper_elf = ELFFile(io.BytesIO(helper))
    assert list(helper_elf.get_section_by_name('.note.gnu.build-id').iter_notes())[0]['n_desc'] == entry['helperBuildId']
    slot = manifest['helper']['keySlotOffset']
    assert helper[slot:slot + 4096] == old_helper[slot:slot + 4096]
    normalized = bytearray(helper)
    normalized[slot:slot + 4096] = bytes(4096)
    assert sha(normalized) == entry['helperNormalizedSha256']
    spec = importlib.util.spec_from_file_location('sdk_upgrade', ROOT / 'scripts/repair-ultra-environment-upgrade.py')
    upgrade = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(upgrade)
    assert upgrade.object_contract(memory_object.read_bytes())[1] == upgrade.object_contract(body(24))[1]
    out.mkdir(parents=True)
    tool = args.ndk.resolve() / 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    commands = []

    def run(name, *arguments):
        command = [str(tool / (name + '.exe')), *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        commands.append(dict(command=command, exitCode=result.returncode, stderr=result.stderr))
        assert result.returncode == 0, result.stdout + result.stderr

    frozen = ROOT / 'runtime/ultra/upgrade/sdk-m052.bc'
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
    contract = upgrade.object_contract(body(52))
    assert upgrade.object_contract(baseline.read_bytes()) == contract, 'Installer baseline drift'
    new_installer = installer(helper, 'm052.candidate')
    assert upgrade.object_contract(new_installer.read_bytes())[1:] == contract[1:]
    assert ELFFile(io.BytesIO(new_installer.read_bytes())).get_section_by_name('.data').data() == helper
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

    baseline_control = control(old_helper, 'baseline')
    contract = upgrade.object_contract(body(255))
    assert upgrade.object_contract(baseline_control.read_bytes()) == contract, 'Control baseline drift'
    new_control = control(helper, 'candidate')
    assert upgrade.object_contract(new_control.read_bytes())[1:] == contract[1:]
    installer_path = out / before['members'][52]['name']
    installer_path.write_bytes(new_installer.read_bytes())
    candidate = out / 'lib/arm64-v8a/libkernel_module_kit_static.a'
    candidate.parent.mkdir(parents=True)
    candidate.write_bytes(original)
    run('llvm-ar', 'rD', candidate, memory_object, installer_path, new_control)
    run('llvm-ar', 'sD', candidate)
    diff = compare_members(before, parse_ar(str(candidate)))
    assert [row['ord'] for row in diff['changed']] == [24, 52, 255]
    assert not diff['added'] and not diff['removed'] and not diff['orderErrors']
    (out / 'helper').mkdir()
    (out / 'helper/autorun_bootstrap').write_bytes(helper)
    assert archive.read_bytes() == original and (production / 'SDK-RELEASE.json').read_bytes() == release_bytes
    sources = [Path(__file__).resolve(), frozen, control_source, ROOT / 'scripts/repair-ultra-environment-upgrade.py']
    sources += [ROOT / name for name in entry['sources']]
    sources += [ROOT / 'scripts/update-ultra-memory-protection.py']
    report = dict(passed=True, baselineArchiveSha256=PIN, archiveSha256=sha(candidate.read_bytes()),
        baselineHelperSha256=HELPER_PIN, helperSha256=sha(helper), helperBuildId=entry['helperBuildId'],
        helperNormalizedSha256=entry['helperNormalizedSha256'], memberDiff=diff,
        installerBaselineReproduced=True, gateBaselineReproduced=True, permissionAbiPreserved=True,
        validationScope=['compile', 'baseline-contract', 'global-abi', 'archive-member-diff', 'helper-section-whitelist'],
        deviceAcceptance=False, productionModified=False, commands=commands,
        sources={p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sources})
    (out / 'packaging.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS permission SDK candidate packaged; device acceptance pending')


if __name__ == '__main__':
    main()
