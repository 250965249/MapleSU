"""Execute the production loader on Android with isolated su/script fixtures."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument('--adb', default=native_toolchain.adb_tool())
p.add_argument('--serial', default=os.environ.get('ANDROID_SERIAL'), required=not os.environ.get('ANDROID_SERIAL'))
p.add_argument('--ndk', default=str(native_toolchain.provider_ndk()))
p.add_argument('--out', type=Path, required=True)
p.add_argument('--docker', action='store_true', help='Run the same native cases under an ordinary Linux UID')
p.add_argument('--legacy-read-check', action='store_true', help='Reintroduce only the pre-root access check to prove the regression')
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
a.out.mkdir(parents=True, exist_ok=True)
remote = '/data/local/tmp/maplesu-parasite-loader-regression'
adb = [a.adb, '-s', a.serial]

def run(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace', **kw)

def shell(command, timeout=15):
    return run(*adb, 'shell', command, timeout=timeout)

def push(path, target):
    r = run(*adb, 'push', str(path), target, timeout=30)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)

source = (root / 'runtime/src/parasite/parasite_loader.cpp').read_text(encoding='utf-8')
source = source.replace('/data/adb/maplesu/recovery/parasite-start.sh', remote + '/denied/start.sh')
start = source.index('constexpr const char* kSuCandidates[] = {')
end = source.index('};', start) + 2
source = source[:start] + f'constexpr const char* kSuCandidates[] = {{"{remote}/fake-channel.sh"}};' + source[end:]
source = source.replace('__attribute__((constructor))', '')
source = source.replace('constexpr int kCommandTimeoutMs = 30000;', 'constexpr int kCommandTimeoutMs = 300;')
if a.legacy_read_check:
    source = source.replace('void* start_thread(void*) {', f'void* start_thread(void*) {{\n if (access("{remote}/denied/start.sh", R_OK) != 0) return nullptr;')
source += r'''
int main(int argc, char** argv) {
    if (argc != 2) return 10;
    if (strcmp(argv[1], "unreadable") == 0) { start_thread(nullptr); return 0; }
    char out[256]; int error = 0;
    const char* command[] = {"/data/local/tmp/maplesu-parasite-loader-regression/fake-channel.sh", nullptr};
    if (strcmp(argv[1], "exec_errno") == 0) command[0] = "/nonexistent-maplesu-su";
    int status = run_capture(command, out, sizeof(out), &error);
    if (strcmp(argv[1], "exec_errno") == 0) return status == 127 && error == ENOENT ? 0 : 11;
    if (strcmp(argv[1], "hang") == 0 || strcmp(argv[1], "closed_pipe") == 0 || strcmp(argv[1], "inherited_pipe") == 0) return status == 124 ? 0 : 12;
    return status == 0 ? 0 : 13;
}
'''
if a.docker:
    source = source.replace('#include <android/log.h>', '#define ANDROID_LOG_WARN 5\nint __android_log_print(int, const char*, const char*, ...) { return 0; }')
    (a.out / 'loader.cpp').write_text(source, encoding='utf-8')
    harness = r'''
import os, pathlib, subprocess
r=pathlib.Path('/data/local/tmp/maplesu-parasite-loader-regression')
r.mkdir(parents=True, exist_ok=True); r.chmod(0o777)
(r/'denied').mkdir(); (r/'denied/start.sh').touch(); (r/'denied').chmod(0o700)
c='/opt/ddk/clang/clang-r510928'
subprocess.run([c+'/bin/clang++','-stdlib=libc++','-std=c++17','-Wall','-Wextra','-Werror',
 '-Wl,-rpath,'+c+'/lib/x86_64-unknown-linux-gnu','/fixture/loader.cpp','-o',str(r/'test')],check=True)
results=[]
for case,body in [('unreadable','touch '+str(r/'attempted')+'\n'),('hang','sleep 30\n'),
 ('closed_pipe','exec 1>&- 2>&-; sleep 30\n'),('inherited_pipe','sleep 30 &\nexit 0\n'),
 ('overflow','i=0; while [ "$i" -lt 2000 ]; do echo 012345678901234567890123456789; i=$((i+1)); done\n'),('exec_errno','exit 0\n')]:
 (r/'attempted').unlink(missing_ok=True)
 script=r/'fake-channel.sh'; script.write_text('#!/bin/sh\n'+body); script.chmod(0o755)
 try:
  result=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups',str(r/'test'),case],timeout=3)
  ok=result.returncode==0 and (case!='unreadable' or (r/'attempted').exists())
  detail='exit='+str(result.returncode)
 except subprocess.TimeoutExpired:
  ok=False; detail='timed out'
 results.append(('PASS' if ok else 'FAIL')+' '+case+' '+detail)
report='\n'.join(results)+'\n'; pathlib.Path('/fixture/loader-host.txt').write_text(report); print(report,end='')
raise SystemExit(any(x.startswith('FAIL') for x in results))
'''
    (a.out / 'run.py').write_text(harness, encoding='utf-8')
    result = run('docker', 'run', '--rm', '--network', 'none', '--mount',
        f'type=bind,source={a.out.resolve()},target=/fixture', '--entrypoint', 'python3',
        'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '/fixture/run.py', timeout=90)
    print(result.stdout + result.stderr, end='')
    raise SystemExit(result.returncode)
with tempfile.TemporaryDirectory(prefix='maplesu-loader-') as temporary:
    tmp = Path(temporary)
    cpp = tmp / 'loader.cpp'
    cpp.write_text(source, encoding='utf-8')
    exe = tmp / 'loader-test'
    clang = Path(a.ndk) / 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android26-clang++.cmd'
    r = run(str(clang), '-std=c++17', '-Wall', '-Wextra', '-Werror', str(cpp), '-llog', '-o', str(exe), timeout=60)
    if r.returncode:
        raise RuntimeError(r.stdout + r.stderr)
    shell(f'mkdir -p {remote}').check_returncode()
    push(exe, remote + '/loader-test')
    shell(f'chmod 755 {remote}/loader-test').check_returncode()
    # A normal host UID cannot traverse the recovery directory. The su fixture only records invocation.
    shell(f"su -c 'mkdir -p {remote}/denied; touch {remote}/denied/start.sh; chmod 700 {remote}/denied'").check_returncode()
    results = []
    try:
        for case, body in [
            ('unreadable', f'touch {remote}/attempted\nexit 0\n'),
            ('hang', 'sleep 30\n'),
            ('closed_pipe', 'exec 1>&- 2>&-; sleep 30\n'),
            ('inherited_pipe', 'sleep 30 &\nexit 0\n'),
            ('overflow', 'i=0; while [ "$i" -lt 2000 ]; do echo 012345678901234567890123456789; i=$((i+1)); done\n'),
            ('exec_errno', 'exit 0\n'),
        ]:
            script = tmp / 'su'
            script.write_text('#!/system/bin/sh\n' + body, encoding='utf-8', newline='\n')
            push(script, remote + '/fake-channel.sh')
            shell(f'chmod 755 {remote}/fake-channel.sh; rm -f {remote}/attempted').check_returncode()
            r = shell(f'/system/bin/timeout -k 1 3 {remote}/loader-test {case}')
            ok = r.returncode == 0
            if case == 'unreadable':
                ok = ok and shell(f'test -f {remote}/attempted').returncode == 0
            results.append(f'{"PASS" if ok else "FAIL"} {case} exit={r.returncode}')
    finally:
        shell(f"su -c 'rm -rf {remote}'").check_returncode()
    report = '\n'.join(results) + '\n'
    (a.out / 'loader-device.txt').write_text(report, encoding='utf-8')
    print(report, end='')
    raise SystemExit(any(x.startswith('FAIL') for x in results))
