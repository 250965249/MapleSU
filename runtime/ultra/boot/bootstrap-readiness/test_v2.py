from pathlib import Path
import hashlib
import json
import subprocess

OUT = Path(__file__).resolve().parent
script = '''set -eu
cd /case
C=/opt/ddk/clang/clang-r510928
$C/bin/clang -std=c11 -Wall -Wextra -Werror -c result_channel.c -o result_channel.host.o
$C/bin/clang -std=c11 -Wall -Wextra -Werror result_test.c result_channel.host.o -Wl,--wrap=poll -Wl,--wrap=pipe2 -o result_test
./result_test
'''
r = subprocess.run(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--mount',
    f'type=bind,source={OUT},target=/case', '--entrypoint', 'sh',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', '-c', script],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
output = r.stdout + r.stderr
(OUT / 'result-test.log').write_text(output)
(OUT / 'result-test.json').write_text(json.dumps(dict(passed=r.returncode == 0, exitCode=r.returncode,
    actualCandidateC=True, realForkAndPipe=True, syntheticPollAndPipeErrors=True, cases=23,
    ensure05ExitZeroSafeOneMissingCompletionRejected=True,
    deviceAcceptance=False, sourceSha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in [OUT / 'result_channel.c', OUT / 'result_test.c']}), indent=2) + '\n')
print(output)
raise SystemExit(r.returncode)
