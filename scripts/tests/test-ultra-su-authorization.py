"""Execute SDK IR paths on the host; kernel/storage/PackageManager are fixtures.

Input: output directory of repair-ultra-su-authorization.py. This is not a device
kernel test: only the ABI namespace/target and the three I/O boundaries change.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--image', default='ghcr.io/ylarod/ddk-min:android15-6.6-20260828')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
build = args.build.resolve()
metadata = json.loads((build / 'build.json').read_text())
assert hashlib.sha256((build / 'libkernel_module_kit_static.a').read_bytes()).hexdigest() == metadata['archiveSha256']
for filename, key in [('su_allowlist_writer.cpp', 'sourceSha256'), ('su_auth_transaction.cpp', 'transactionSha256'),
                      ('su_retention_store.cpp', 'retentionSourceSha256')]:
    assert hashlib.sha256((repo / 'runtime/ultra/authorization' / filename).read_bytes()).hexdigest() == metadata[key]

for name, filename in [('baseline', 'm081.original.ll'), ('patched', 'm081.patched.ll')]:
    ir = (build / filename).read_text()
    writer = re.search(r'define internal fastcc (?:noundef )?i64 @([^ (]*write_allowlist[^ (]*)', ir)[1]
    mapper = re.search(r'define (?:linkonce_odr )?hidden void @([^ (]*read_pkg_uids_from_packages_list[^ (]*)', ir)[1]
    ir = re.sub(r'^@llvm.global_ctors = .*\n', '', ir, flags=re.M)
    start = re.search(r'define (?:linkonce_odr )?hidden void @' + re.escape(mapper) + r'\(', ir).start()
    end = ir.index('\n}\n', start) + 3
    ir = ir[:start] + f'declare void @{mapper}(ptr sret(%"class.std::__ndk1::unordered_map"), ptr, ptr)\n' + ir[end:]
    ir = re.sub(r'"target-[^"]+"="[^"]*"', '', ir)
    ir = re.sub(r'target datalayout = .*\n', '', ir)
    ir = re.sub(r'target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', ir)
    ir += f'\ndefine i64 @test_write(ptr %packages) {{\n %result = call fastcc i64 @{writer}(ptr %packages)\n ret i64 %result\n}}\n'
    add = '_ZN15default_modules18module_su_redirect16add_su_allowlistEPKc'
    if '@' + add + '(' not in ir:
        ir += f'\ndeclare i64 @{add}(ptr)\n'
    ir += f'\ndefine i64 @test_add(ptr %package) {{\n %result = call i64 @{add}(ptr %package)\n ret i64 %result\n}}\n'
    for name_suffix, public in [('remove', '19remove_su_allowlistEPKc'), ('clear', '18clear_su_allowlistEv')]:
        symbol = '_ZN15default_modules18module_su_redirect' + public
        parameters, arguments = ('ptr %package', 'ptr %package') if name_suffix == 'remove' else ('', '')
        if '@' + symbol + '(' not in ir:
            ir += f'\ndeclare i64 @{symbol}({"ptr" if parameters else ""})\n'
        ir += f'\ndefine i64 @test_{name_suffix}({parameters}) {{\n %result = call i64 @{symbol}({arguments})\n ret i64 %result\n}}\n'
    ir = ir.replace('6__ndk1', '3__1').replace('__ndk1', '__1').replace('9mbstate_t', '11__mbstate_t')
    (build / (name + '.host.ll')).write_text(ir)

script = f'''
set -eu
mkdir -p /data/adb
cd /case
C=/opt/ddk/clang/clang-r510928
for n in baseline patched; do
  $C/bin/clang++ -c -ffunction-sections -fdata-sections $n.host.ll -o $n.host.o
  extra=
  if [ $n = patched ]; then
    extra="/repo/runtime/ultra/authorization/su_allowlist_writer.cpp /repo/runtime/ultra/authorization/su_auth_transaction.cpp"
  fi
  $C/bin/clang++ -stdlib=libc++ -std=c++17 -I/repo/runtime/maplesu-sdk/include \
    -Wl,--gc-sections -Wl,--wrap=popen -Wl,--wrap=pclose -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \
    /repo/runtime/tests/pro_su_allowlist_test.cpp $n.host.o $extra -o $n.test
  failed=0
  for t in grant missing_uid all_missing alloc write publish corrupt read clear duplicate \
    fallback bad_fallback failed_fallback stale boot_missing refresh_missing persist revoke revoke_persist clear_sdk clear_persist; do
    ./$n.test $t || failed=1
  done >$n-results.log
  if [ $n = patched ]; then
    for t in refresh_existing refresh_empty refresh_fallback refresh_unresolved refresh_boot_unresolved refresh_readfail \
      refresh_partial_pm_failure refresh_boot_partial_pm_failure refresh_partial_fallback refresh_partial_uninstalled; do
      ./$n.test $t || failed=1
    done >>$n-results.log
  fi
  cat $n-results.log
  if [ $n = patched ]; then test $failed = 0; else test $failed = 1; fi
done
$C/bin/clang++ -stdlib=libc++ -std=c++17 -Wall -Wextra -Werror -I/repo/runtime/maplesu-sdk/include \
  -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu /repo/runtime/tests/pro_su_auth_transaction_test.cpp \
  /repo/runtime/ultra/authorization/su_auth_transaction.cpp -o /tmp/transaction.test
/tmp/transaction.test
'''
result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--mount',
    f'type=bind,source={repo},target=/repo,readonly', '--mount',
    f'type=bind,source={build},target=/case', '--entrypoint', 'sh', args.image, '-c', script],
    capture_output=True, text=True)
(build / 'native-regression.log').write_text(result.stdout + result.stderr)
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
