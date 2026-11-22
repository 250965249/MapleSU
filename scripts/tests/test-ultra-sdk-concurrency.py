"""Exercise SDK call admission and real archived fork/callback code with mocked kernel I/O."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from verify_sdk_member_diff import parse_ar

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--ndk', type=Path, required=True)
parser.add_argument('--jni-receipts', action='store_true', help='Also compile the production bridge and check its JSON error receipts.')
parser.add_argument('--process-failures', action='store_true', help='Inject fork/pipe/wait failures into the real SDK transport.')
parser.add_argument('--baseline', action='store_true', help='Reproduce the archived process-wide key collision without call scopes.')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
build = args.build.resolve()
build.mkdir(parents=True, exist_ok=True)
sdk = repo / 'runtime/maplesu-sdk'
archive = sdk / 'lib/arm64-v8a/libkernel_module_kit_static.a'
data = archive.read_bytes()
manifest = json.loads((sdk / 'SDK-RELEASE.json').read_text())
assert hashlib.sha256(data).hexdigest() == manifest['archive']['sha256']
members = parse_ar(str(archive))['members']
tool = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
inputs = []
for name, output in [('module_current_identity.o', 'identity'), ('maplesu_fork_helper.o', 'transport'), ('maplesu_su_auth.o', 'authorization')]:
    member = next(item for item in members if item['name'] == name)
    blob = data[member['body_offset']:member['body_offset'] + member['size']]
    assert blob.startswith(b'BC\xc0\xde'), name
    source = build / (output + '.bc')
    source.write_bytes(blob)
    original = build / (output + '.ll')
    subprocess.run([str(tool), '--target=aarch64-linux-android21', '-S', '-emit-llvm', '-x', 'ir', str(source), '-o', str(original)], check=True, capture_output=True)
    ir = original.read_text()
    ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
    ir = re.sub(r'target datalayout = .*\n', '', ir)
    ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
    ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
    ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
    ir = ir.replace('@__errno(', '@__errno_location(')
    (build / (output + '.host.ll')).write_text(ir)
    inputs.append({'member': name, 'sha256': hashlib.sha256(blob).hexdigest()})

# Keep the Kotlin/native read allowlists equal; all unlisted entries remain exclusive.
kotlin = (repo / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraRuntimeClient.kt').read_text(encoding='utf-8')
native = (repo / 'runtime/ultra/bridge/sdk_call_scope.cpp').read_text(encoding='utf-8')
java_reads = set(re.findall(r'"([a-z_]+)"', kotlin.split('private val PARALLEL_READS = setOf(')[1].split(')')[0]))
cpp_reads = set(re.findall(r'"([a-z_]+)"', native.split('return SdkCallAccess::Local;')[1].split('return SdkCallAccess::Read;')[0]))
assert java_reads == cpp_reads and len(java_reads) == 11 and 'read_installed_helper' in java_reads, (java_reads, cpp_reads)
script = '''set -eu
ulimit -c 0
cd /case
C=/opt/ddk/clang/clang-r510928
for name in identity transport authorization; do
 $C/bin/clang++ -c -ffunction-sections -fdata-sections $name.host.ll -o $name.host.o
done
$C/bin/clang++ -std=c++17 -ffunction-sections -fdata-sections -stdlib=libc++ -pthread -Wall -Wextra -Werror -fexceptions \
 -DMAPLESU_TEST_CALL_SCOPE -I/repo/runtime/ultra/bridge -I/repo/runtime/maplesu-sdk/include \
 -Wl,--gc-sections -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
 -Wl,--wrap=__set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW \
 -Wl,--wrap=__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW \
 /repo/runtime/tests/pro_sdk_parallelism_test.cpp /repo/runtime/ultra/bridge/sdk_call_scope.cpp \
 identity.host.o transport.host.o authorization.host.o -o sdk-parallelism.test
./sdk-parallelism.test
'''
if not args.baseline:
    script = script.replace('-Wl,--gc-sections', '-Wl,--wrap=fork -Wl,--wrap=pipe2 -Wl,--wrap=close -Wl,--wrap=waitpid -Wl,--gc-sections')
if args.jni_receipts:
    assert args.process_failures and not args.baseline
    import shutil
    headers = build / 'host-include'
    (headers / 'sys').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include/jni.h', headers / 'jni.h')
    (headers / 'sys/system_properties.h').write_text('#pragma once\n#define PROP_VALUE_MAX 92\nextern "C" int __system_property_get(const char*, char*);\n')
    script = script.replace('-std=c++17', '-std=c++20 -DMAPLESU_TEST_JNI_RECEIPTS -I/case/host-include -isystem /repo/runtime/ultra/third_party/cJSON -isystem /repo/runtime/ultra/third_party/include')
    script = script.replace('-I/repo/runtime/maplesu-sdk/include', '-isystem /repo/runtime/maplesu-sdk/include')
    script = script.replace('identity.host.o transport.host.o authorization.host.o -o', '/repo/runtime/ultra/third_party/cJSON/cJSON.cpp identity.host.o transport.host.o authorization.host.o -o')
if args.process_failures:
    script = script.replace('/repo/runtime/tests/pro_sdk_parallelism_test.cpp', '/repo/runtime/tests/pro_sdk_process_failure_test.cpp')
    if not args.baseline:
        script = script.replace('-DMAPLESU_TEST_CALL_SCOPE', '-DMAPLESU_TEST_CALL_SCOPE -DMAPLESU_TEST_PROCESS_FAILURE_FIX')
    script = script.replace('./sdk-parallelism.test', 'status=0\nfor mode in fork pipe1 pipe2 eintr concurrent inherited-pipes child-unwind exclusive-fork exclusive-pipe1 exclusive-pipe2 exclusive-eintr; do\n timeout 12s ./sdk-parallelism.test $mode || status=1\ndone\nexit $status')
if args.baseline and not args.process_failures:
    script = script.replace('-DMAPLESU_TEST_CALL_SCOPE', '')
    script = re.sub(r'-Wl,--wrap=__[^\s]+', '', script)
    script = script.replace('/repo/runtime/ultra/bridge/sdk_call_scope.cpp', '')
    script = script.replace('sdk-parallelism.test', 'sdk-parallelism-baseline.test')
if args.jni_receipts:
    script = script.replace('for mode in fork ', 'for mode in environment-channel fork ')
started = time.monotonic()
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount', f'type=bind,source={repo},target=/repo,readonly', '--mount', f'type=bind,source={build},target=/case', '--entrypoint', 'sh', 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
output = result.stdout + result.stderr
name = ('sdk-process-receipts' if args.jni_receipts else 'sdk-process-failures' if args.process_failures else 'sdk-parallelism') + ('-baseline' if args.baseline else '')
(build / (name + '.log')).write_text(output)
(build / (name + '.json')).write_text(json.dumps({'exitCode': result.returncode, 'elapsedSeconds': round(time.monotonic() - started, 3), 'archiveSha256': manifest['archive']['sha256'], 'inputs': inputs, 'parallelReads': sorted(java_reads), 'output': output}, indent=2))
print(output)
raise SystemExit(result.returncode)
