"""Verify consent preserves ABI qualification using actual candidate payloads."""
import argparse
from datetime import datetime,timezone
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--payloads',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();payloads=a.payloads.resolve()
names=['android12-5.10','android13-5.15','android14-6.1','android15-6.6','android16-6.12','android17-6.18']
sources=[ROOT/path for path in ['runtime/ultra/policy/kernel_layout.cpp','runtime/ultra/policy/kernel_payload.cpp',
 'runtime/ultra/policy/kernel_payload_loader.cpp','runtime/ultra/policy/kernel_layout.h','runtime/ultra/policy/kernel_payload.h',
 'runtime/ultra/policy/kernel_payload_loader.h','runtime/ultra/policy/policy_layout_slots.h',
 'runtime/tests/kernel_payload_io_fixture.h','runtime/tests/kernel_dynamic_consent_test.cpp']]+[Path(__file__).resolve()]
inputs=sources+[payloads/name/file for name in names for file in ['policy-view.so','compiled-layout.h']]
before={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
commands=[]
for name in names:
 commands.extend(['c++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer '
  '-I/source/runtime/ultra/policy -I/payloads/'+name+' '
  '/source/runtime/ultra/policy/kernel_layout.cpp /source/runtime/ultra/policy/kernel_payload.cpp '
  '/source/runtime/ultra/policy/kernel_payload_loader.cpp /source/runtime/tests/kernel_dynamic_consent_test.cpp '
  '-o /tmp/consent-test','/tmp/consent-test /payloads/'+name+'/policy-view.so '+name.split('-',1)[1]])
command=['docker','run','--rm','--pull','never','--network','none','--cap-drop','ALL','--security-opt','no-new-privileges',
 '--mount',f'type=bind,source={ROOT},target=/source,readonly','--mount',f'type=bind,source={payloads},target=/payloads,readonly',
 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828','sh','-c',' && '.join(commands)]
r=subprocess.run(command,capture_output=True,text=True,timeout=240)
record=dict(recordedAt=datetime.now(timezone.utc).isoformat(),passed=r.returncode==0,exitCode=r.returncode,stdout=r.stdout,stderr=r.stderr,
 sourceSha256={path.relative_to(ROOT).as_posix():before[str(path)] for path in sources},
 payloadSha256={name:before[str(payloads/name/'policy-view.so')] for name in names},
 sourcesUnchanged=before=={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs},
 deviceAccess=False,kernelIoSimulated=True,referenceAttemptNotDynamicTargetProof=True)
a.output.write_text(json.dumps(record,indent=2)+'\n')
print(r.stdout or r.stderr);print('Receipt:',a.output)
raise SystemExit(0 if record['passed'] and record['sourcesUnchanged'] else 1)
