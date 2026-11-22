"""Local transport/adapter regression with real control ioctl and native fixtures."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
args=p.parse_args();args.output.mkdir(parents=True,exist_ok=True)
flags='-Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer'
transport='-DMAPLESU_POLICY_HOOK_HOST_TEST -I/source/jailbreak-providers/root-loader/tests'
commands=['ulimit -c 0',
 f'cc -std=gnu11 {flags} {transport} -c /source/jailbreak-providers/root-loader/module/maplesu_policy_hook.c -o /output/control.o',
 f'cc -std=gnu11 {flags} {transport} -c /source/jailbreak-providers/root-loader/module/policy_hook_dispatch.c -o /output/dispatch.o',
 f'cc -std=gnu11 {flags} {transport} -DMAPLESU_POLICY_HOOK_TRANSPORT_LIBRARY -Dmain=policy_test_transport_regression -c /source/jailbreak-providers/root-loader/tests/policy_hook_transport_test.c -o /output/native-fixture.o',
 f'c++ -std=c++20 {flags} -c /source/runtime/ultra/policy/kernel_payload_hook.cpp -o /output/adapter.o',
 f'c++ -std=c++20 {flags} -I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_payload.cpp /source/runtime/ultra/policy/module_policy_config.cpp /source/module-policy/src/policy_hook_loader.cpp /source/runtime/tests/policy_hook_adapter_test.cpp /output/control.o /output/dispatch.o /output/native-fixture.o /output/adapter.o -pthread -Wl,--wrap=open,--wrap=close,--wrap=fstat,--wrap=lstat,--wrap=ioctl,--wrap=prctl -o /output/adapter-test',
 '/output/adapter-test',
 '/output/adapter-test resident',
 f'cc -std=gnu11 {flags} {transport} -DMAPLESU_POLICY_HOOK_EMBEDDED /source/jailbreak-providers/root-loader/module/maplesu_policy_hook.c /source/jailbreak-providers/root-loader/module/policy_hook_dispatch.c /source/jailbreak-providers/root-loader/tests/policy_hook_transport_test.c -pthread -o /output/embedded-test',
 '/output/embedded-test',
 f'cc -std=gnu11 {flags} {transport} /source/jailbreak-providers/root-loader/module/policy_hook_dispatch.c /source/jailbreak-providers/root-loader/tests/policy_hook_dispatch_test.c -o /output/dispatch-test',
 '/output/dispatch-test']
inputs=['jailbreak-providers/root-loader/policy_hook_abi.h','jailbreak-providers/root-loader/module/maplesu_policy_hook.c','jailbreak-providers/root-loader/module/policy_hook_dispatch.c','jailbreak-providers/root-loader/tests/policy_hook_transport_test.c','jailbreak-providers/root-loader/tests/policy_hook_dispatch_test.c','jailbreak-providers/root-loader/tests/policy_hook_layout.h','runtime/ultra/policy/kernel_payload_hook.cpp','runtime/ultra/policy/kernel_payload_hook.h','runtime/ultra/policy/module_policy_config.cpp','runtime/ultra/policy/module_policy_config.h','module-policy/src/main.cpp','module-policy/src/policy_hook_loader.cpp','runtime/tests/policy_hook_adapter_test.cpp','scripts/tests/test-hook-policy-backend.py']
before={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in inputs}
command=['docker','run','--rm','--pull','never','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',f'type=bind,source={ROOT},target=/source,readonly','--mount',f'type=bind,source={args.output.resolve()},target=/output','--entrypoint','/bin/sh','ghcr.io/ylarod/ddk-min:android16-6.12-20260828','-c',' && '.join(commands)]
r=subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
after={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in inputs}
report=dict(generatedAt=datetime.now(timezone.utc).isoformat(),passed=r.returncode==0 and before==after,exitCode=r.returncode,inputStable=before==after,sourceSha256=before,command=command,stdout=r.stdout,stderr=r.stderr,deviceAccess=False,fullPolicyHidingAcceptance=False)
(args.output/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
print(r.stdout,end='');print(r.stderr,end='')
raise SystemExit(0 if report['passed'] else 1)
