"""Execute the production Kotlin deployment script with unreadable app cache.

Only the Android cp permission boundary is injected; deployment, hashes,
permissions, publication and receipt checks run in a disposable Linux container.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, default=Path('manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery.kt'))
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
source = args.source.read_text(encoding='utf-8-sig')
method = source[source.index('    private fun deployScript('):source.rindex('\n}')]
quote = re.search(r'^    private fun quote\(.*$', source, re.M)[0]
config = json.loads((root / 'work/panic-fix-20261105/jvm.json').read_text())
cache = out / 'input-cache'
cache.mkdir(exist_ok=True)
(cache / 'identity.json').write_text('{"payload":"sealed-value","text":"a\'b $HOME $(id)"}\n', newline='\n')
(cache / 'start.sh').write_text('#!/system/bin/sh\nprintf \'%s\\n\' "a\'b $HOME"\n', newline='\n')
apk_hash = hashlib.sha256(b'fixture-apk').hexdigest()
bridge_hash = hashlib.sha256(b'fixture-bridge').hexdigest()
config_hash = hashlib.sha256((cache / 'identity.json').read_bytes()).hexdigest()
start_hash = hashlib.sha256((cache / 'start.sh').read_bytes()).hexdigest()
harness = '''import java.io.File
private object UltraIdentityBroker { const val DIRECTORY = "/data/adb/maplesu/ultra-identity" }
object RenderIdentityDeploy {
    private const val READY = "MAPLESU_IDENTITY_READY"
''' + quote + '\n' + method + '''
    @JvmStatic fun main(args: Array<String>) {
        File(args[0]).writeText(deployScript(File("/fixture/apk"), "APK_HASH",
            File(args[1]), File(args[2]), File("/fixture/bridge"), "BRIDGE_HASH"))
    }
}
'''.replace('APK_HASH', apk_hash).replace('BRIDGE_HASH', bridge_hash)
src = out / 'RenderIdentityDeploy.kt'
src.write_text(harness, encoding='utf-8')
jar = out / 'renderer.jar'
subprocess.run([config['java'], '-cp', config['compilerClasspath'], 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
    '-no-stdlib', '-no-reflect', '-classpath', config['dependencies'], '-jvm-target', '17', '-d', str(jar), str(src)], check=True)
deploy = out / 'deploy.sh'
subprocess.run([config['java'], '-cp', str(jar) + ';' + config['dependencies'], 'RenderIdentityDeploy',
    str(deploy), str(cache / 'identity.json'), str(cache / 'start.sh')], check=True)
# java.io.File normalizes the container fixture paths on the Windows renderer.
deploy.write_bytes(deploy.read_text().replace('\\fixture\\', '/fixture/').encode('utf-8'))
relative = deploy.relative_to(root).as_posix()
script = f'''set -eu
mkdir -p /fixture
printf %s fixture-apk > /fixture/apk
printf %s fixture-bridge > /fixture/bridge
cp() {{
 case "$1" in *input-cache*) echo 'cp: app cache: Permission denied' >&2; return 1;; esac
 if [ "$DEPLOY_SCENARIO" = apk-denied ] && [ "$1" = /fixture/apk ]; then echo 'cp: apk: Permission denied' >&2; return 1; fi
 command cp "$@"
}}
if [ "$DEPLOY_SCENARIO" = bad-bridge ]; then printf %s corrupt > /fixture/bridge; fi
if [ "$DEPLOY_SCENARIO" = directory-symlink ]; then mkdir -p /data/adb; ln -s /fixture /data/adb/maplesu; fi
# SDK discards shell status: production must supply an explicit failure receipt.
set +e
( . /repo/{relative} ) > /fixture/receipt 2>&1
status=$?
set -e
cat /fixture/receipt
case "$DEPLOY_SCENARIO" in
 apk-denied) expected=APK:1;;
 bad-bridge) expected=BRIDGE:4;;
 directory-symlink) expected=DIRECTORY:3;;
 *) expected=;;
esac
if [ -n "$expected" ]; then
 test "$status" -ne 0
 grep -qx "MAPLESU_IDENTITY_DEPLOY_ERROR:$expected" /fixture/receipt
 ! grep -q MAPLESU_IDENTITY_READY /fixture/receipt
 test ! -e /data/adb/maplesu/ultra-identity/identity.json
 test ! -e /data/adb/maplesu/ultra-identity/libmaplesu_ultra_bridge.so.tmp
 echo "PASS_IDENTITY_FAILURE_$DEPLOY_SCENARIO"
 exit 0
fi
test "$status" = 0
test "$(cat /fixture/receipt)" = MAPLESU_IDENTITY_READY
test "$(sha256sum /data/adb/maplesu/ultra-identity/identity.json | cut -d ' ' -f 1)" = '{config_hash}'
test "$(sha256sum /data/adb/maplesu/ultra-identity/start.sh | cut -d ' ' -f 1)" = '{start_hash}'
test "$(stat -c %a /data/adb/maplesu/ultra-identity/start.sh)" = 700
test "$(stat -c %a /data/adb/maplesu/ultra-identity/identity.json)" = 600
( . /repo/{relative} ) > /fixture/receipt 2>&1
test "$(cat /fixture/receipt)" = MAPLESU_IDENTITY_READY
echo PASS_IDENTITY_DEPLOY_WITH_PRIVATE_CACHE
'''
logs = []
failed = False
for scenario in ['private-cache', 'apk-denied', 'bad-bridge', 'directory-symlink']:
    result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
        f'type=bind,source={root},target=/repo', '-e', f'DEPLOY_SCENARIO={scenario}', '--entrypoint', 'sh',
        'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True)
    logs.append(f'{scenario}: exit={result.returncode}\n' + result.stdout + result.stderr)
    failed |= result.returncode != 0
log = '\n'.join(logs)
(out / 'identity-deployment.log').write_text(log, encoding='utf-8')
print(log)
raise SystemExit(int(failed))
