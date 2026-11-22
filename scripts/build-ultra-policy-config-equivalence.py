"""Prove a captured config variant before adding it to a payload's compatibility contract."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--target-config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    reference, output = args.reference.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to(reference) or reference.is_relative_to(output):
        parser.error('output must be a new directory separate from the reference')
    contract = json.loads((reference / 'kernel-compatibility.json').read_text())
    metadata = json.loads((reference / 'target-identity.json').read_text())
    kernel = reference.name
    if not re.fullmatch(r'android\d+-\d+\.\d+', kernel) or kernel == 'android17-6.18':
        parser.error('this compiler proof needs an installed DDK with its matching Kbuild tree')
    values = {}
    for line in args.target_config.read_text().splitlines():
        if not line.startswith('CONFIG_'):
            continue
        key, value = line.split('=', 1)
        if key in values:
            parser.error('duplicate target config: ' + key)
        values[key] = json.loads(value) if value.startswith('"') else value
    override = {k: values.get(k, 'n') for k, v in contract['config'].items() if v != values.get(k, 'n')}
    if not override:
        parser.error('no observed differences in the compiled config contract')
    if any(not re.fullmatch(r'n|y|m|\d+|0x[0-9a-fA-F]+', v) for v in override.values()):
        parser.error('a string config difference requires a separate compiler proof')
    output.mkdir(parents=True)
    target = output / kernel
    shutil.copytree(reference, target)
    profile_id = hashlib.sha256(json.dumps(override, sort_keys=True).encode()).hexdigest()[:12]
    header_name = 'config-equivalent-' + profile_id + '.h'
    payload_name = 'equivalent-policy-view-' + profile_id + '.so'
    layout_name = 'equivalent-layout-' + profile_id + '.json'
    source_inputs = [*reference.glob('*.c'), *reference.glob('*.h'), *reference.glob('*.S'), reference / 'Makefile']
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source_inputs}
    header = ''.join('#undef ' + k + '\n' + ('' if v == 'n' else '#define ' + k + ' ' +
                     ('1' if v == 'y' else v) + '\n') for k, v in sorted(override.items()))
    (target / header_name).write_text(header, encoding='utf-8', newline='\n')
    # Force only this isolated external module to rebuild. The kernel tree and
    # reference artifacts are read-only; their recorded compiler flags are reused.
    for p in target.glob('*.o'):
        p.unlink()
    script = '''set -eu
dir=/output/KERNEL
make -C /opt/ddk/kdir/KERNEL M="$dir" LLVM=1 ARCH=arm64 MAPLESU_POLICY_PIC=1 -j2 maplesu_policy_view.o
link_payload() {
  ld.lld -r -o "$dir/maplesu_policy_view.payload.o" --whole-archive "$dir/maplesu_policy_view.o" --no-whole-archive
  ld.lld -shared --entry=0 --strip-debug -Bsymbolic -z max-page-size=65536 -z force-bti -o "$dir/$1" "$dir/maplesu_policy_view.payload.o"
}
link_payload reproduced-policy-view.so
cmp "$dir/policy-view.so" "$dir/reproduced-policy-view.so"
make -C /opt/ddk/kdir/KERNEL M="$dir" LLVM=1 ARCH=arm64 -j2 maplesu_policy_layout.o
llvm-objcopy --decompress-debug-sections "$dir/abi_anchors.o" "$dir/abi-layout.o"
mkdir -p "$dir/equivalence-reference-commands"
cp "$dir"/.*.o.cmd "$dir/equivalence-reference-commands/"
make -C /opt/ddk/kdir/KERNEL M="$dir" LLVM=1 ARCH=arm64 MAPLESU_POLICY_PIC=1 KCFLAGS="-include $dir/config-equivalent.h" -j2 maplesu_policy_view.o
link_payload equivalent-policy-view.so
cmp "$dir/policy-view.so" "$dir/equivalent-policy-view.so"
make -C /opt/ddk/kdir/KERNEL M="$dir" LLVM=1 ARCH=arm64 KCFLAGS="-include $dir/config-equivalent.h" -j2 maplesu_policy_layout.o
llvm-objcopy --decompress-debug-sections "$dir/abi_anchors.o" "$dir/abi-layout.o"
cp "$dir/equivalence-reference-commands/".*.o.cmd "$dir/"
'''.replace('KERNEL', kernel).replace('config-equivalent.h', header_name).replace('equivalent-policy-view.so', payload_name)
    command = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--mount', f'type=bind,source={ROOT},target=/source,readonly',
        '--mount', f'type=bind,source={output},target=/output',
        'ghcr.io/ylarod/ddk-min:' + kernel + '-20260828', 'sh', '-c', script]
    result = subprocess.run(command, capture_output=True, timeout=120)
    (output / 'build.log').write_bytes(result.stdout + result.stderr)
    record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=False, config=override,
                  kernel=kernel, buildExitCode=result.returncode, deviceAccess=False, hookInstalled=False)
    (output / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError('compiler equivalence failed; inspect ' + str(output / 'build.log'))
    subprocess.run([sys.executable, ROOT / 'scripts/build-ultra-policy-layout.py',
        target / 'maplesu_policy_view.payload.o', target / 'abi-layout.o',
        '--output', target / layout_name], check=True)
    if json.loads((reference / 'compiled-layout.json').read_text()) != json.loads((target / layout_name).read_text()):
        raise RuntimeError('compiled consumed layout differs')
    if (reference / 'policy-view.so').read_bytes() != (target / payload_name).read_bytes():
        raise RuntimeError('compiled payload differs')
    assert before == {p.name: hashlib.sha256((target / p.name).read_bytes()).hexdigest() for p in source_inputs}
    proof_path = target / 'config-equivalence.json'
    proof = json.loads(proof_path.read_text()) if proof_path.exists() else dict(profiles=[])
    inputs = [*target.glob('*.c'), *target.glob('*.h'), *target.glob('*.S'), target / 'Makefile']
    proof['profiles'].append(dict(config=override, payload=payload_name, header=header_name,
        layout=layout_name, sourceSha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}))
    proof_path.write_text(json.dumps(proof, indent=2) + '\n')
    # The outer generator completes every required profile. This isolated proof
    # validates only its own result; completing other profiles here recursively
    # copies/rebuilds the same reference and can exhaust disk space.
    subprocess.run([sys.executable, ROOT / 'scripts/build-ultra-policy-compatibility.py',
                    target, '--no-complete-profiles'], check=True)
    record.update(passed=True, referenceReproduced=True, identicalPayload=True, identicalConsumedLayout=True,
                  payloadSha256=hashlib.sha256((target / 'policy-view.so').read_bytes()).hexdigest(),
                  referenceBuildIdPreserved=json.loads((target / 'target-identity.json').read_text())['buildId'] == metadata['buildId'])
    (output / 'verification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
