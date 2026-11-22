"""Build an isolated m024 candidate for complete, checked page ranges."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from ar_archive import parse_ar, sha256_file

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / 'work/panic-kernel-read-20261114/memory-protection/m024.permissions.ll'
INPUT_SHA = '5a251a192bcb868302182da8905391ee260406e09a17091140705a177fe10215'
MEMBER_SHA = '1449fde70c49d7e52c57be86ea2ff1f6ef8881d2ec07d1988d79f370a1bd1753'
PUBLIC = '_ZN13kernel_module25set_kernel_mem_protectionEmmNS_11KernMemProtE'
RO = '_ZN13kernel_moduleL24set_memory_ro_protectionEmm'
RANGE = 'maplesu_memory_protection_pages'
SOURCE = ROOT / 'runtime/ultra/boot/memory_protection_range.ll'


def replace_once(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new, 1)


def patch_range_ir(original):
    candidate = original
    for name, variants in [(PUBLIC, [('rw', 14, 15, 16, 17, 26, 37),
                                    ('x', 44, 45, 46, 47, 56, 64)]),
                           (RO, [('ro', 5, 6, 7, 8, 17, 25)])]:
        matches = list(re.finditer(r'^define[^\n]*@' + re.escape(name) +
                                  r'\([^\n]*\{\n.*?^}', candidate, re.M | re.S))
        assert len(matches) == 1, name
        match = matches[0]
        body = re.sub(r'%(\d+)\b', r'%v\1', match[0])
        body = re.sub(r'^(\d+):', r'v\1:', body, flags=re.M)
        body = body.replace('{\n', '{\nv' + ('3' if name == PUBLIC else '2') + ':\n', 1)
        for tag, block, address, page, wide, count, fail in variants:
            pattern = (r'  %v' + str(address) + r' = and i64 %v0, -4096\n.*?'
                       r'  %v' + str(count) + r' = and i64 %v\d+, 4294967295\n')
            replacement = f'''  %v{page} = tail call noundef i32 @_ZN13kernel_module13get_page_sizeEv() #29
  %v{wide} = zext i32 %v{page} to i64
  %maplesu.{tag}.mask = sub i64 0, %v{wide}
  %v{address} = and i64 %v0, %maplesu.{tag}.mask
  %v{count} = call fastcc i64 @{RANGE}(i64 %v0, i64 %v1, i64 %v{wide})
  %maplesu.{tag}.valid = icmp ne i64 %v{count}, 0
  br i1 %maplesu.{tag}.valid, label %maplesu.{tag}.ready, label %v{fail}

maplesu.{tag}.ready:
'''
            body, changed = re.subn(pattern, lambda _: replacement, body, flags=re.S)
            assert changed == 1, (name, tag)
            # The public entry has one failure phi per protection branch.
            phis = list(re.finditer(r'^  %v\d+ = phi i64[^\n]*$', body, re.M))
            target = next(p for p in phis if p.start() > body.index(f'v{fail}:'))
            body = body[:target.end()] + f', [ -20000, %v{block} ]' + body[target.end():]
        candidate = candidate[:match.start()] + body + candidate[match.end():]
    assert '@' + RANGE not in original
    at = candidate.index('\nattributes #0')
    return candidate[:at] + '\n' + SOURCE.read_text() + candidate[at:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=ROOT / 'work/panic-implementation-20261114/memory-range-candidate/build')
    args = parser.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'work') and not out.exists(), 'Use fresh work/ output'
    archive = ROOT / 'runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a'
    archive_sha = sha256_file(archive)
    member = parse_ar(str(archive))['members'][24]
    assert member['name'] == 'module_base_kernel_mem.o' and member['sha256'] == MEMBER_SHA
    assert sha256_file(INPUT) == INPUT_SHA
    out.mkdir(parents=True)
    baseline, source, target = (out / n for n in ('m024.baseline.o', 'm024.range.ll', 'module_base_kernel_mem.o'))
    source.write_text(patch_range_ir(INPUT.read_text()), encoding='utf-8', newline='\n')
    compiler = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
    for src, obj in ((INPUT, baseline), (source, target)):
        result = subprocess.run([str(compiler), '--target=aarch64-linux-android21', '-Oz', '-fPIC',
                                 '-c', str(src), '-o', str(obj)], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert sha256_file(baseline) == MEMBER_SHA, 'Existing permission candidate must reproduce'
    spec = importlib.util.spec_from_file_location('sdk_upgrade', ROOT / 'scripts/repair-ultra-environment-upgrade.py')
    contracts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contracts)
    assert contracts.object_contract(baseline.read_bytes())[1] == contracts.object_contract(target.read_bytes())[1]
    assert sha256_file(archive) == archive_sha
    report = dict(passed=True, scope='m024 page range only; existing permission return fix retained',
                  baselineReproducedExactly=True, globalSymbolContractUnchanged=True,
                  baselineObjectSha256=MEMBER_SHA, candidateObjectSha256=sha256_file(target),
                  candidateIrSha256=sha256_file(source), inputIrSha256=INPUT_SHA,
                  sourceSha256=sha256_file(Path(__file__)), rangeSourceSha256=sha256_file(SOURCE), archiveSha256=archive_sha,
                  pageSizes=[4096, 16384, 65536], maxPageCount=2147483647,
                  productionModified=False, embeddedHelperUpdated=False, deviceVerification=False)
    (out / 'build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
