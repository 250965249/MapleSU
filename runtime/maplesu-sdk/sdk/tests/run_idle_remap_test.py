from pathlib import Path
import argparse, hashlib, json, subprocess

DEFAULT_ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument('--root', type=Path, default=DEFAULT_ROOT)
p.add_argument('--source', type=Path)
p.add_argument('--out', required=True, type=Path)
a = p.parse_args()
ROOT = a.root.resolve()
source = (a.source or ROOT / 'runtime/maplesu-sdk/sdk/src/module_base/module_base_kernel_idle_mem.cpp').resolve()
text = source.read_text(encoding='utf-8-sig')
begin = text.index('static ' + ('KModErr' if 'static KModErr flush_all_tlb(' in text else 'void') + ' flush_all_tlb(')
end = text.index('\nnamespace kernel_module {', begin)
function = text[begin:end]
a.out.mkdir(parents=True, exist_ok=True)
cpp = a.out / 'idle_remap.cpp'
cpp.write_text((HERE / 'idle_remap_fixture.cpp').read_text().replace('// EXACT_REMAP_FUNCTION', function), encoding='utf-8')
compiler = sorted((ROOT / '.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
exe = a.out / 'idle_remap.exe'
argv = [str(compiler), '-std=c++20', '-O1', '-static', '-I' + str(ROOT / 'runtime/maplesu-sdk/include'), str(cpp), '-o', str(exe)]
build = subprocess.run(argv, capture_output=True, text=True)
(a.out / 'compile.log').write_text(build.stdout + build.stderr)
if build.returncode: raise SystemExit(build.stderr)
run = subprocess.run([str(exe)], capture_output=True, text=True)
unwind = [subprocess.run([str(exe), flag], capture_output=True, text=True)
    for flag in ('--free-unwind', '--protect-unwind')]
output = run.stdout + run.stderr + ''.join(item.stdout + item.stderr for item in unwind)
exit_code = 1 if any(item.returncode for item in [run, *unwind]) else 0
(a.out / 'run.log').write_text(output)
result = dict(source=str(source), sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(), command=argv,
    exitCode=exit_code, output=output, subprocessExits=[item.returncode for item in [run, *unwind]],
    scope='exact production remap function; kernel allocation, permission, synchronous apply and cleanup exception seams; no device execution')
(a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
print(output)
raise SystemExit(exit_code)
