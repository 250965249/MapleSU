"""Exercise persisted consent, boot latching and cancellation without a device."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
sources = ['runtime/ultra/policy/module_policy_config.cpp', 'runtime/ultra/policy/module_policy_config.h',
           'runtime/ultra/policy/kernel_policy_gate.cpp', 'runtime/ultra/policy/kernel_policy_gate.h',
           'runtime/ultra/policy/environment_policy.cpp', 'module-policy/tests/module_policy_config_tests.cpp',
           'runtime/tests/kernel_policy_gate_test.cpp', 'runtime/tests/kernel_policy_passthrough_test.cpp',
           'runtime/tests/environment_policy_test.cpp']
sources += ['runtime/tests/policy_gate_fixture/kernel_module_kit_umbrella.h',
            'runtime/tests/environment_policy_fallback_test.cpp', 'zygisk/native/module_policy_mode.cpp']
digests = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources}
flags = ('c++ -std=c++20 -UNDEBUG -Wall -Wextra -Werror -fsanitize=address,undefined '
         '-fno-omit-frame-pointer -I/source/runtime/tests/policy_gate_fixture '
         '-I/source/runtime/ultra/policy -I/source/runtime/maplesu-sdk/include ')
commands = [flags + '/source/runtime/ultra/policy/module_policy_config.cpp '
            '/source/module-policy/tests/module_policy_config_tests.cpp -o /output/config && /output/config']
for enabled in (False, True):
    for name in ('kernel_policy_gate_test', 'kernel_policy_passthrough_test'):
        commands.append(flags + ('-DMAPLESU_POLICY_HIDE_PAYLOAD=1 ' if enabled else '') +
            '/source/runtime/ultra/policy/kernel_policy_gate.cpp /source/runtime/tests/' + name +
            '.cpp /source/runtime/ultra/policy/module_policy_config.cpp -o /output/gate && /output/gate')
commands.append(flags + '/source/runtime/ultra/policy/environment_policy.cpp '
    '/source/runtime/tests/environment_policy_test.cpp -Wl,--wrap=getuid -Wl,--wrap=geteuid '
    '-o /output/entry && /output/entry')
commands.append(flags + '-DMAPLESU_POLICY_HIDE_PAYLOAD=1 -I/source/zygisk/native '
    '/source/runtime/ultra/policy/environment_policy.cpp /source/runtime/ultra/policy/kernel_policy_gate.cpp '
    '/source/runtime/ultra/policy/module_policy_config.cpp /source/zygisk/native/module_policy_mode.cpp '
    '/source/runtime/tests/environment_policy_fallback_test.cpp -Wl,--wrap=open '
    '-o /output/fallback && /output/fallback')
with tempfile.TemporaryDirectory(prefix='maplesu-policy-requests-') as output:
    result = subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--mount',
        f'type=bind,source={ROOT},target=/source,readonly', '--mount', f'type=bind,source={output},target=/output',
        'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', 'sh', '-c', ' && '.join(commands)],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180)
record = dict(recordedAt=datetime.now(timezone.utc).isoformat(), passed=result.returncode == 0,
    exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr, sourceSha256=digests,
    sanitizers=['ASan', 'UBSan'], deviceAccess=False,
    inputsUnchanged=digests == {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in sources},
    scope='Actual root-owned settings persistence and mode gate; kernel and SDK boundaries are fixtures')
args.output.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
print(json.dumps(record, indent=2))
raise SystemExit(0 if record['passed'] and record['inputsUnchanged'] else 1)
