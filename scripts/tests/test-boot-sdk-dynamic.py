"""Exercise runtime SDK layout derivation against real BTF and corrupted ABIs."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from policy_btf_abi import Btf

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--payloads', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
focus = p.add_mutually_exclusive_group()
focus.add_argument('--seccomp-only', action='store_true', help='Run the focused seccomp.mode regression matrix')
focus.add_argument('--credential-graph-only', action='store_true', help='Run actual task.cred pointer graph cases')
a = p.parse_args()
output = a.output.resolve(); output.mkdir(parents=True, exist_ok=True)
sources = ['runtime/ultra/policy/kernel_layout.cpp', 'runtime/ultra/policy/kernel_layout.h',
    'module-policy/src/boot_sdk_layout.cpp', 'module-policy/src/boot_sdk_layout.h',
    'jailbreak-providers/root-loader/boot_sdk_abi.h', 'runtime/tests/boot_sdk_layout_probe.cpp',
    'scripts/tests/test-boot-sdk-dynamic.py', 'scripts/policy_btf_abi.py']
before = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources}
for name in sources:
    frozen = output/'source'/name
    frozen.parent.mkdir(parents=True, exist_ok=True)
    frozen.write_bytes((ROOT/name).read_bytes())
names = [('android14-6.1', 0), ('android15-6.6', 1), ('android16-6.12', 1), ('android17-6.18', 0)]
commands = ['c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer '
    '-I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_layout.cpp '
    '/source/module-policy/src/boot_sdk_layout.cpp /source/runtime/tests/boot_sdk_layout_probe.cpp -o /output/probe']
run = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--mount', f'type=bind,source={ROOT},target=/source,readonly',
    '--mount', f'type=bind,source={output},target=/output', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828']
build = subprocess.run(run + ['sh', '-c', commands[0]], capture_output=True, text=True, timeout=60)
(output/'build.log').write_text(build.stdout + build.stderr, encoding='utf-8')
assert not build.returncode, build.stderr

def seccomp_cases(raw, btf, environment):
    """Mutate real embedded seccomp types, not an unrelated type-name fixture."""
    owners = [t for t in btf.types[1:] if t[1] == 4 and btf.name(t[0]) == 'task_struct']
    containers, fields, outer_offsets = {}, [], set()
    for owner in owners:
        at = next(owner[5]+i*12 for i in range(owner[2])
                  if btf.name(btf.u32(owner[5]+i*12)) == 'seccomp')
        fields.append((owner, at))
        outer_offsets.add(btf.u32(at+8))
        index = btf.u32(at+4)
        while btf.types[index][1] in (8, 9, 10, 11, 18): index = btf.types[index][3]
        containers[index] = btf.types[index]
    assert len(outer_offsets) == 1
    outer = outer_offsets.pop()
    modes = [(owner, next(owner[5]+i*12 for i in range(owner[2])
             if btf.name(btf.u32(owner[5]+i*12)) == 'mode')) for owner in containers.values()]
    assert all(not owner[4] and btf.u32(at+8) == 0 for owner, at in modes)
    def changed(updates):
        result = bytearray(raw)
        for at, value in updates: struct.pack_into('<I', result, at, value)
        return result
    # Swap the two 4B scalars: mode+4 is a nonoverlapping, owner-contained layout.
    shifted = []
    for owner, at in modes:
        neighbour = next(owner[5]+i*12 for i in range(owner[2])
                         if btf.u32(owner[5]+i*12+8) == 32)
        shifted += [(at+8, 32), (neighbour+8, 0)]
    cases = [('seccomp-mode-shifted', changed(shifted), environment, outer//8+4),
             ('seccomp-mode-missing', changed([(at, 0) for _, at in modes]), 0, None),
             ('seccomp-mode-unaligned', changed([(at+8, 1) for _, at in modes]), 0, None),
             ('seccomp-mode-owner-overflow', changed([(at+8, owner[3]*8) for owner, at in modes]), 0, None),
             ('seccomp-task-owner-overflow', changed([(at+8, owner[3]*8) for owner, at in fields]), 0, None)]
    for width in (1, 2, 8):
        scalar = next(i for i, t in enumerate(btf.types[1:], 1)
                      if t[1] == 1 and t[3] == width and btf.u32(t[5]) & 0xffffff == width*8)
        cases.append(('seccomp-mode-width-'+str(width),
                      changed([(at+4, scalar) for _, at in modes]), 0, None))
    # An isolated embedded owner permits byte+1 without overlapping real siblings.
    sizes = {owner[3] for owner in containers.values()}
    assert len(sizes) == 1 and next(iter(sizes)) >= 8
    mode_name = btf.u32(modes[0][1])
    variants = [
        ('byte-offset', struct.pack('<IIII', 0, 1 << 24, 4, 32), 0, 8),
        ('effective-width', struct.pack('<IIII', 0, 1 << 24, 8, 8 << 16 | 32), 0, 0),
        ('modern-width', struct.pack('<IIII', 0, 1 << 24, 4, 32), 1 << 31, 32 << 24 | 8),
        ('enum-width', struct.pack('<IIIII', 0, 6 << 24 | 1, 4, mode_name, 0), 0, 8),
    ]
    header, type_offset, type_size, string_offset, _ = struct.unpack_from('<IIIII', raw, 4)
    for case, scalar, flags, offset in variants:
        extra = scalar + struct.pack('<IIIIII', 0, flags | 4 << 24 | 1, next(iter(sizes)),
                                     mode_name, len(btf.types), offset)
        data = changed([(at+4, len(btf.types)+1) for _, at in fields])
        data[header+type_offset+type_size:header+type_offset+type_size] = extra
        struct.pack_into('<I', data, 12, type_size+len(extra))
        struct.pack_into('<I', data, 16, string_offset+len(extra))
        cases.append(('seccomp-mode-'+case, data, environment, outer//8+1))
    return cases, outer//8
def credential_graph_cases(raw, btf, environment):
    """Append cred types with or without a real task.cred pointer to them."""
    task = next(t for t in btf.types[1:] if t[1] == 4 and t[2] and btf.name(t[0]) == 'task_struct')
    member = next(task[5]+i*12 for i in range(task[2]) if btf.name(btf.u32(task[5]+i*12)) == 'cred')
    def resolved(index):
        while btf.types[index][1] in (8, 9, 10, 11, 18): index = btf.types[index][3]
        return index
    pointer = btf.types[resolved(btf.u32(member+4))]
    assert pointer[1] == 2
    cred = btf.types[resolved(pointer[3])]
    assert cred[1] == 4 and btf.name(cred[0]) == 'cred'
    suid = next(cred[5]+i*12 for i in range(cred[2]) if btf.name(btf.u32(cred[5]+i*12)) == 'suid')
    scalar = next(i for i, t in enumerate(btf.types[1:], 1)
                  if t[1] == 1 and t[3] == 4 and btf.u32(t[5]) == 32)
    header, type_offset, type_size, string_offset, _ = struct.unpack_from('<IIIII', raw, 4)
    type_end = header + type_offset + type_size
    base = raw[cred[5]-12:cred[5]+cred[2]*12]
    cases = []
    for variant in ('layout', 'abi', 'empty', 'linked-same', 'linked-layout', 'linked-abi'):
        extra = bytearray(base)
        if variant == 'layout': struct.pack_into('<I', extra, 8, cred[3]+8)
        elif variant in ('abi', 'linked-abi'):
            struct.pack_into('<I', extra, suid-(cred[5]-12)+4, scalar)
        elif variant == 'empty': extra = bytearray(struct.pack('<III', cred[0], 4 << 24, cred[3]))
        elif variant == 'linked-layout':
            struct.pack_into('<I', extra, suid-(cred[5]-12)+8, btf.u32(suid+8)+32)
        if variant.startswith('linked-'):
            extra += struct.pack('<III', 0, 2 << 24, len(btf.types))
            copied_task = bytearray(raw[task[5]-12:task[5]+task[2]*12])
            struct.pack_into('<I', copied_task, member-(task[5]-12)+4, len(btf.types)+1)
            extra += copied_task
        changed = bytearray(raw)
        changed[type_end:type_end] = extra
        struct.pack_into('<I', changed, 12, type_size+len(extra))
        struct.pack_into('<I', changed, 16, string_offset+len(extra))
        rejected = variant in ('linked-layout', 'linked-abi')
        cases.append(('credential-graph-'+variant, changed, 2 if rejected else 0,
                      None if rejected else environment, None, None, None))
    return cases

def with_inner_allocator(raw, outer, valid):
    """Append a FUNC using the native prototype, or one changed parameter type."""
    btf = Btf(raw)
    indices = btf.functions[outer]
    assert len({btf.signature(index) for index in indices}) == 1
    prototype = btf.types[indices[0]][3]
    proto = btf.types[prototype]
    assert proto[1] == 13 and proto[2] == 9
    inner = "_" + outer
    header, type_offset, type_size, string_offset, string_size = struct.unpack_from('<IIIII', raw, 4)
    type_end = header + type_offset + type_size
    string_end = header + string_offset + string_size
    assert type_end <= header + string_offset <= string_end <= len(raw)
    changed = bytearray(raw)
    # Make the synthetic definition unique even when a reference already has one.
    for index in btf.functions.get(inner, []):
        struct.pack_into('<I', changed, btf.types[index][5] - 12, 0)
    extra = bytearray()
    if not valid:
        extra += raw[proto[5] - 12:proto[5] + proto[2] * 8]
        scalar = next(i for i, t in enumerate(btf.types[1:], 1) if t[1] == 1 and t[3] == 4)
        struct.pack_into('<I', extra, 12 + 8 * 8 + 4, scalar)
        prototype = len(btf.types)
    extra += struct.pack('<III', string_size, 12 << 24 | 1, prototype)
    encoded_name = inner.encode() + b'\0'
    changed[type_end:type_end] = extra
    changed[string_end + len(extra):string_end + len(extra)] = encoded_name
    struct.pack_into('<I', changed, 12, type_size + len(extra))
    struct.pack_into('<I', changed, 16, string_offset + len(extra))
    struct.pack_into('<I', changed, 20, string_size + len(encoded_name))
    actual = Btf(changed).function(inner)
    assert (actual == btf.function(outer)) == valid
    return changed

def with_user_sampler(raw, kind):
    """Qualify only the sampler FUNC; shared vmalloc prototypes stay intact."""
    btf = Btf(raw)
    allocator = 'vmalloc' if 'vmalloc' in btf.functions else 'vmalloc_noprof'
    name = allocator.replace('vmalloc', 'vmalloc_user', 1)
    source = btf.types[btf.types[btf.functions[allocator][0]][3]]
    assert source[1] == 13 and source[2] == 1
    header, type_offset, type_size, string_offset, string_size = struct.unpack_from('<IIIII', raw, 4)
    type_end = header + type_offset + type_size
    string_end = header + string_offset + string_size
    changed = bytearray(raw)
    for index in btf.functions.get(name, []):
        struct.pack_into('<I', changed, btf.types[index][5] - 12, 0)
    extra = bytearray()
    variants = [] if kind == 'missing' else (['valid', 'parameter'] if kind == 'ambiguous' else [kind])
    scalar = next(i for i, t in enumerate(btf.types[1:], 1) if t[1] == 1 and t[3] == 4)
    for number, variant in enumerate(variants):
        prototype = bytearray(raw[source[5] - 12:source[5] + source[2] * 8])
        if variant == 'parameter': struct.pack_into('<I', prototype, 16, scalar)
        if variant == 'return': struct.pack_into('<I', prototype, 8, scalar)
        extra += prototype
        extra += struct.pack('<III', string_size, 12 << 24 | 1, len(btf.types) + number * 2)
    encoded_name = name.encode() + b'\0'
    changed[type_end:type_end] = extra
    changed[string_end + len(extra):string_end + len(extra)] = encoded_name
    struct.pack_into('<I', changed, 12, type_size + len(extra))
    struct.pack_into('<I', changed, 16, string_offset + len(extra))
    struct.pack_into('<I', changed, 20, string_size + len(encoded_name))
    actual = Btf(changed)
    assert actual.function(allocator) == btf.function(allocator)
    if kind == 'valid': assert actual.function(name) == 'f*v(i8:64;)'
    return changed

worker = subprocess.Popen(run[:2] + ['-i'] + run[2:] + ['sh', '-c',
    'set -f; while IFS= read -r args; do set -- $args; /output/probe "$@"; code=$?; '
    'printf "__MAPLESU_PROBE_EXIT__:%s\\n" "$code"; done'],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def run_probe(arguments):
    assert 2 <= len(arguments) <= 6
    # Paths are generated /output/<kernel>-<case>.btf names; remaining arguments
    # are numeric probe options. Tabs preserve the existing shell argv exactly.
    assert all(not any(c.isspace() for c in item) for item in arguments[1:])
    worker.stdin.write(('\t'.join(arguments[1:])+'\n').encode()); worker.stdin.flush()
    lines = []
    while True:
        line = worker.stdout.readline().decode('utf-8', errors='replace')
        if not line: raise RuntimeError('Focused resolver container exited without a result')
        if line.startswith('__MAPLESU_PROBE_EXIT__:'):
            return subprocess.CompletedProcess(arguments, int(line.split(':', 1)[1]), ''.join(lines), '')
        lines.append(line)

rows = []
inputs = {}
for name, environment in names:
    raw = (a.payloads/name/'vmlinux.btf').read_bytes(); btf = Btf(raw)
    inputs[name] = dict(path=str((a.payloads/name/'vmlinux.btf').resolve()),
                        bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    def member(owner, field):
        matches = [t for t in btf.types[1:] if t[1] == 4 and btf.name(t[0]) == owner]
        assert matches
        return [next(t[5]+i*12 for i in range(t[2]) if btf.name(btf.u32(t[5]+i*12)) == field)
                for t in matches]
    def u32_at(at, value):
        changed = bytearray(raw)
        for position in at:
            struct.pack_into('<I', changed, position, value)
        return changed
    cred = member('task_struct', 'cred')
    parameters = {btf.types[btf.types[index][3]][5]+4 for index in btf.functions['get_task_cred']}
    scalar = next(i for i, t in enumerate(btf.types[1:], 1) if t[1] == 1 and t[3] == 4)
    wrong_pointer = next(i for i, t in enumerate(btf.types[1:], 1)
                         if t[1] == 2 and btf.signature(i) == '*v')
    usage = member('cred', 'usage')
    suid = member('cred', 'suid')
    original_offset = btf.u32(cred[0]+8)
    assert all(btf.u32(at+8) == original_offset for at in cred)
    allocator = 0 if 'vmalloc' in btf.functions else 1
    outer = '__vmalloc_node_range' + ('_noprof' if allocator else '')
    qualified_inner = with_inner_allocator(raw, outer, True)
    invalid_inner = with_inner_allocator(raw, outer, False)
    fixtures = [('reference', raw, 0, environment, None, None, None),
        ('shifted-layout', u32_at([at+8 for at in cred], original_offset+256), 0, environment, None, None, None),
        ('unaligned-pointer', u32_at([at+8 for at in cred], original_offset+1), 2, None, None, None, None),
        ('task-cred-type', u32_at([at+4 for at in cred], wrong_pointer), 2, None, None, None, None),
        ('uid-value-type', u32_at([at+4 for at in suid], scalar), 2, None, None, None, None),
        ('usage-value-type', u32_at([at+4 for at in usage], scalar), 2, None, None, None, None),
        ('native-helper-abi', u32_at(parameters, scalar), 2, None, None, None, None),
        ('truncated-btf', raw[:24], 2, None, None, None, None),
        ('inner-capability-disabled', qualified_inner, 0, environment, False, allocator, None),
        ('inner-capability-enabled', qualified_inner, 0, environment, True, allocator | 2, None),
        ('inner-abi-rejected', invalid_inner, 0, environment, True, allocator, None)]
    fixtures += credential_graph_cases(raw, btf, environment)
    if len(cred) > 1:
        fixtures.append(('ambiguous-layout', u32_at([cred[-1]+8], original_offset+256), 2, None, None, None, None))
    sampler = with_user_sampler(raw, 'valid')
    fixtures += [('user-capability-disabled', sampler, 0, environment, False, allocator, False),
        ('user-capability-enabled', sampler, 0, environment, False, allocator | 4, True),
        ('user-and-inner-capabilities', with_user_sampler(qualified_inner, 'valid'), 0, environment, True, allocator | 6, True),
        ('user-reference-abi', raw, 0, environment, False, allocator | 4, True)]
    for invalid in ('missing', 'parameter', 'return', 'ambiguous'):
        fixtures.append(('user-' + invalid, with_user_sampler(raw, invalid), 0, environment, False, allocator, True))
    seccomp, outer_seccomp = seccomp_cases(raw, btf, environment)
    seccomp_expected = {'reference': outer_seccomp} if environment else {}
    for case, data, env, expected_offset in seccomp:
        fixtures.append((case, data, 0, env, None, None, None))
        if env and expected_offset is not None: seccomp_expected[case] = expected_offset
    if a.seccomp_only:
        fixtures = [item for item in fixtures if item[0] == 'reference' or item[0].startswith('seccomp-')]
    if a.credential_graph_only:
        fixtures = [item for item in fixtures if item[0] == 'reference' or item[0].startswith('credential-graph-')]
    reference_wire = None
    for case, data, code, env, allow_inner, expected_allocator, allow_user in fixtures:
        path = output/(name+'-'+case+'.btf'); path.write_bytes(data)
        arguments = ['/output/probe', '/output/'+path.name]
        if allow_inner is not None:
            arguments += ['4096', str(int(allow_inner))]
        if allow_user is not None:
            arguments += [str(int(allow_user))]
        result = run_probe(arguments)
        passed = result.returncode == code and (env is None or 'environment='+str(env) in result.stdout)
        wire = result.stdout.split('wire=', 1)[1].split()[0] if 'wire=' in result.stdout else None
        if case == 'reference': reference_wire = wire
        if case.startswith('credential-graph-') and code == 0:
            passed &= reference_wire is not None and wire == reference_wire
        if expected_allocator is not None:
            passed &= 'allocatorNoprof='+str(expected_allocator) in result.stdout
        if case == 'shifted-layout':
            passed &= 'taskCred='+str(original_offset//8+32) in result.stdout
        if case in seccomp_expected:
            passed &= 'seccomp='+str(seccomp_expected[case]) in result.stdout
        rows.append(dict(kernel=name, case=case, passed=passed, exitCode=result.returncode,
            stdout=result.stdout.strip(), stderr=result.stderr.strip(), btfSha256=hashlib.sha256(data).hexdigest()))
        (output/'progress.json').write_text(json.dumps(dict(results=rows, sourceSha256=before,
            inputs=inputs, complete=False), indent=2)+'\n', encoding='utf-8')
        if not a.seccomp_only and not a.credential_graph_only and case in ('reference', 'inner-capability-enabled', 'user-capability-enabled', 'user-and-inner-capabilities'):
            for page in (16384, 65536):
                capability = [] if allow_inner is None else [str(int(allow_inner))]
                if allow_user is not None: capability += [str(int(allow_user))]
                result = run_probe(['/output/probe', '/output/' + path.name, str(page)] + capability)
                passed = result.returncode == 0
                expected = allocator if expected_allocator is None else expected_allocator
                passed &= 'allocatorNoprof=' + str(expected) in result.stdout
                rows.append(dict(kernel=name, case=case+'-page-'+str(page), passed=passed,
                    exitCode=result.returncode, stdout=result.stdout.strip(), stderr=result.stderr.strip()))
        # Each mutated BTF is reproducible from this script; keep hashes, not large copies.
        path.unlink()
if worker is not None:
    worker.stdin.close()
    assert worker.wait(timeout=30) == 0
report = dict(at=datetime.now(timezone.utc).isoformat(), passed=all(r['passed'] for r in rows),
    results=rows, sourceSha256=before, sourcesUnchanged=before=={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in sources},
    inputs=inputs, buildCommand=run + ['sh', '-c', commands[0]], seccompOnly=a.seccomp_only,
    credentialGraphOnly=a.credential_graph_only,
    deviceAccess=False, scope='Real BTF parser and layout resolver; allocator/AVC execution and device functionality are separate gates')
(output/'verification.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(dict(passed=report['passed'], cases=len(rows), failed=[r for r in rows if not r['passed']])))
raise SystemExit(0 if report['passed'] and report['sourcesUnchanged'] else 1)
