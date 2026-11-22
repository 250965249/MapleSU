"""Replay generated production boot/start/stop scripts in a disposable Linux filesystem."""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

p = argparse.ArgumentParser()
p.add_argument('--out', type=Path, required=True)
p.add_argument('--legacy-pid-check', action='store_true')
p.add_argument('--device', action='store_true')
p.add_argument('--adb', default=native_toolchain.adb_tool())
p.add_argument('--serial', default=os.environ.get('ANDROID_SERIAL'))
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
a.out.mkdir(parents=True, exist_ok=True)
classes = root / '.tmp/opgce-build/_manager/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes'
stdlib = next((Path.home()/'.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.4.20').glob('*/*.jar'))
emitter = r'''
import java.nio.file.*;
import dev.maplesu.manager.litehidden.*;
public class EmitParasiteScripts {
 public static void main(String[] args) throws Exception {
  var out=Path.of(args[0]);
  Files.writeString(out.resolve("start.sh"),ParasiteScripts.INSTANCE.daemonStart(ParasitePaths.APK));
  Files.writeString(out.resolve("stop.sh"),ParasiteScripts.INSTANCE.daemonStop());
  Files.writeString(out.resolve("boot.sh"),UltraRecoveryBoot.INSTANCE.content());
  Files.writeString(out.resolve("normal-install.sh"),NormalRecoveryBoot.INSTANCE.installScript());
  Files.writeString(out.resolve("normal-remove.sh"),NormalRecoveryBoot.INSTANCE.removeScript());
 }
}
'''
with tempfile.TemporaryDirectory(prefix='maplesu-startup-') as temporary:
    tmp = Path(temporary)
    src = tmp / 'EmitParasiteScripts.java'
    src.write_text(emitter, encoding='utf-8')
    cp = os.pathsep.join(map(str, [classes, stdlib]))
    subprocess.run([str(native_toolchain.jdk_tool('javac')), '-cp', cp, '-d', str(tmp), str(src)], check=True)
    subprocess.run([str(native_toolchain.jdk_tool('java')), '-cp', str(tmp)+os.pathsep+cp, 'EmitParasiteScripts', str(a.out.resolve())], check=True)
if a.legacy_pid_check:
    start = a.out/'start.sh'
    text = start.read_text(encoding='utf-8')
    text = text.replace('  if is_daemon "$P"; then', '  if kill -0 "$P" 2>/dev/null; then echo "PARASITE_ALIVE pid=$P"; exit 0; fi\n  if is_daemon "$P"; then', 1)
    start.write_text(text, encoding='utf-8')
if a.device:
    if not a.serial:
        p.error('--device needs --serial or ANDROID_SERIAL')
    remote = '/data/local/tmp/maplesu-parasite-startup-regression'
    adb = [a.adb, '-s', a.serial]
    for name in ['start.sh', 'stop.sh', 'boot.sh']:
        body = (a.out/name).read_text(encoding='utf-8')
        body = body.replace('/data/adb/maplesu/recovery', remote+'/recovery').replace('/data/adb/maplesu/ultra-identity', remote+'/identity').replace('/data/adb/maplesu/lite_hidden', remote+'/lite_hidden')
        body = body.replace('/system/bin/app_process', remote+'/fake-app-process.sh').replace('sleep 2', 'sleep 0.01')
        (a.out/('device-'+name)).write_text(body, encoding='utf-8', newline='\n')
    runner = r'''
set -u
R=REMOTE
failures=0
check() { if [ "$2" = 0 ]; then echo "PASS $1"; else echo "FAIL $1"; failures=$((failures+1)); fi; }
mkdir -p "$R/recovery" "$R/identity"
touch "$R/recovery/manager.apk"
printf 'webuiPort=61467\nworkMode=LITE\ntoken=fixture-token-only\n' > "$R/recovery/webui.conf"
cat > "$R/fake-app-process.sh" <<'FIXTURE'
#!/system/bin/sh
case "$*" in *--await-ready*) n=0; while [ ! -f REMOTE/launched ] && [ "$n" -lt 20 ]; do n=$((n+1)); sleep 0.01; done; exit 1;; esac
touch REMOTE/launched
exit 1
FIXTURE
chmod 755 "$R/fake-app-process.sh"
nohup /system/bin/sleep 120 </dev/null >/dev/null 2>&1 & OTHER=$!
trap 'kill "$OTHER" 2>/dev/null' EXIT
echo "$OTHER" > "$R/recovery/liteweb.pid"
/system/bin/sh "$R/start.sh" > "$R/start-result" 2>&1; RC=$?
[ "$RC" != 0 ] && [ -f "$R/launched" ]; check reboot_reused_pid_requires_launch "$?"
kill -0 "$OTHER"; check reused_pid_never_signalled "$?"
rm -f "$R/launched"
touch "$R/recovery/webui.paused"
/system/bin/sh "$R/start.sh" > "$R/start-result" 2>&1; RC=$?
[ "$RC" != 0 ] && [ ! -e "$R/launched" ]; check paused_start_rejected "$?"
rm -f "$R/recovery/webui.paused"
/system/bin/sh "$R/stop.sh" > "$R/stop-result" 2>&1
kill -0 "$OTHER"; check stop_never_signals_foreign_pid "$?"
printf '1\n' > "$R/lite_hidden"
cat > "$R/recovery/parasite-start.sh" <<'FIXTURE'
#!/system/bin/sh
echo start >> REMOTE/boot-count
exit 0
FIXTURE
/system/bin/sh "$R/boot.sh"; sleep 0.2
[ -f "$R/boot-count" ]; check ultra_boot_starts_recovery "$?"
rm -f "$R/boot-count"; touch "$R/recovery/webui.paused"
/system/bin/sh "$R/boot.sh"; sleep 0.2
[ ! -e "$R/boot-count" ]; check boot_respects_pause "$?"
rm -f "$R/recovery/webui.paused"
printf '0\n' > "$R/lite_hidden"
printf 'pending:01234567-89ab-cdef-0123-456789abcdef\n' > "$R/recovery/manager-restore.ticket"
/system/bin/sh "$R/boot.sh"; sleep 0.2
[ -f "$R/boot-count" ]; check pending_confirmation_survives_reboot "$?"
rm -f "$R/boot-count"; touch "$R/identity/disabled"
/system/bin/sh "$R/boot.sh"; sleep 0.2
[ ! -e "$R/boot-count" ]; check disabled_environment_keeps_stopped "$?"
exit "$failures"
'''.replace('REMOTE', remote)
    (a.out/'device-run.sh').write_text(runner, encoding='utf-8', newline='\n')
    def device(*args):
        return subprocess.run([*adb,*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=45)
    device('shell',f'mkdir -p {remote}').check_returncode()
    try:
        for name in ['start.sh','stop.sh','boot.sh','run.sh']:
            device('push',str(a.out/('device-'+name)),remote+'/'+name).check_returncode()
            device('shell',f'/system/bin/sh -n {remote}/{name}').check_returncode()
        result=device('shell',f"su -c '/system/bin/sh {remote}/run.sh'")
        (a.out/'startup-device.txt').write_text(result.stdout+result.stderr,encoding='utf-8')
        print(result.stdout+result.stderr,end='')
    finally:
        device('shell',f"su -c 'rm -rf {remote}'").check_returncode()
    raise SystemExit(result.returncode)
harness = r'''
from pathlib import Path
import os, subprocess, time
root=Path('/tmp/maplesu-startup'); root.mkdir(); r=root/'recovery'; r.mkdir()
system=root/'system'; system.mkdir(); fixture=Path('/fixture')
def adapt(name):
 text=(fixture/name).read_text().replace('/data/adb/maplesu/recovery',str(r)).replace('/data/adb/maplesu/ultra-identity',str(root/'identity')).replace('/data/adb/maplesu/lite_hidden',str(root/'lite_hidden'))
 for cmd in ['sh','timeout','app_process']:
  text=text.replace('/system/bin/'+cmd,str(system/cmd))
 return text
for name in ['start.sh','stop.sh','boot.sh']:
 (root/name).write_text(adapt(name))
(system/'sh').symlink_to('/bin/sh'); (system/'timeout').symlink_to('/usr/bin/timeout')
channel=system/'app_process'
channel.write_text('#!/bin/sh\ncase "$*" in *--await-ready*) n=0; while [ ! -f '+str(root/'launched')+' ] && [ "$n" -lt 20 ]; do n=$((n+1)); sleep 0.01; done; exit "${PROBE_EXIT:-1}";; esac\ntouch '+str(root/'launched')+'\nexit 1\n'); channel.chmod(0o755)
(r/'manager.apk').touch(); (r/'webui.conf').write_text('webuiPort=18427\nworkMode=LITE\ntoken=fixture-token-only\n')
results=[]
def check(name,ok):
 results.append(('PASS' if ok else 'FAIL')+' '+name)
def execute(name='start.sh',env=None):
 return subprocess.run(['/bin/sh',str(root/name)],capture_output=True,text=True,timeout=15,env=env)
def reset():
 for file in ['launched','recovery/webui.paused','recovery/liteweb.pid','boot-count','identity/disabled','recovery/manager-restore.ticket']:
  (root/file).unlink(missing_ok=True)
other=subprocess.Popen(['sleep','120'])
try:
 (r/'liteweb.pid').write_text(str(other.pid)+'\n')
 result=execute()
 check('reboot_reused_pid_requires_http_and_launch',result.returncode!=0 and (root/'launched').exists() and 'PARASITE_ALIVE' not in result.stdout)
 check('reused_pid_never_killed',other.poll() is None)
 reset(); (r/'liteweb.pid').write_text('1\n'); result=execute()
 check('pid_one_never_treated_as_daemon',result.returncode!=0 and (root/'launched').exists())
 reset(); (r/'webui.paused').touch(); result=execute()
 check('host_start_respects_explicit_pause',result.returncode!=0 and not (root/'launched').exists())
 reset(); result=execute(env={**os.environ,'PROBE_EXIT':'0'})
 check('http_without_owned_pid_is_not_success',result.returncode!=0)
 reset(); result=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','/bin/sh',str(root/'start.sh')],capture_output=True,text=True)
 check('nonroot_daemon_start_rejected',result.returncode!=0 and 'ROOT_REQUIRED' in result.stdout and not (root/'launched').exists())
 reset(); (r/'liteweb.pid').write_text(str(other.pid)+'\n'); result=execute('stop.sh')
 check('stop_does_not_signal_reused_pid',other.poll() is None)
finally:
 other.terminate(); other.wait()
(root/'identity').mkdir(); (root/'lite_hidden').write_text('1\n')
startup=r/'parasite-start.sh'
startup.write_text('#!/bin/sh\necho start >> '+str(root/'boot-count')+'\nexit 0\n')
boot=(root/'boot.sh').read_text().replace('sleep 2','sleep 0.01')+'\nwait\n'
(root/'boot.sh').write_text(boot)
def boot_case(name,prepare,want):
 reset(); (root/'lite_hidden').write_text('1\n'); (r/'webui.conf').write_text('workMode=LITE\n'); prepare()
 result=execute('boot.sh'); count=len((root/'boot-count').read_text().splitlines()) if (root/'boot-count').exists() else 0
 check(name,count==want)
boot_case('ultra_boot_starts_independent_daemon',lambda:None,1)
boot_case('normal_mode_not_started_by_ultra',lambda:(r/'webui.conf').write_text('workMode=KSU\n'),0)
boot_case('unhidden_not_restarted',lambda:(root/'lite_hidden').write_text('0\n'),0)
boot_case('boot_respects_pause',lambda:(r/'webui.paused').touch(),0)
boot_case('disabled_environment_not_restarted',lambda:(root/'identity/disabled').touch(),0)
def pending():
 (root/'lite_hidden').write_text('0\n')
 (r/'manager-restore.ticket').write_text('pending:01234567-89ab-cdef-0123-456789abcdef\n')
boot_case('pending_manager_confirmation_keeps_recovery_after_reboot',pending,1)
startup.write_text('#!/bin/sh\necho start >> '+str(root/'boot-count')+'\n[ "$(wc -l < '+str(root/'boot-count')+')" -ge 3 ]\n')
boot_case('boot_retries_transient_start_failures',lambda:None,3)
startup.write_text('#!/bin/sh\necho start >> '+str(root/'boot-count')+'\necho 0 > '+str(root/'lite_hidden')+'\nexit 1\n')
boot_case('retry_rechecks_hidden_state',lambda:None,1)
report='\n'.join(results)+'\n'; (fixture/'startup-host.txt').write_text(report); print(report,end='')
raise SystemExit(any(x.startswith('FAIL') for x in results))
'''
(a.out/'run.py').write_text(harness, encoding='utf-8')
result = subprocess.run(['docker','run','--rm','--network','none','--mount',
    f'type=bind,source={a.out.resolve()},target=/fixture','--entrypoint','python3','python:3.12-slim','/fixture/run.py'],
    capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
print(result.stdout+result.stderr,end='')
raise SystemExit(result.returncode)
