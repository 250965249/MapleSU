"""Run native index source with host RCU/hash/uaccess seams, not a device test."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1] / 'kprobe_text_owner.inc')
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
out = args.out.resolve(); out.mkdir(parents=True, exist_ok=True)
raw = args.source.read_bytes(); text = raw.decode('utf-8-sig')
start = text.index('/* Immutable companion indexes')
end = text.index('/* One resident provider', start)
body = text[start:end]
# Only adapt the native address-domain predicate to the host pointer domain.
assert body.count('0xffff000000000000ULL') == 1
body = body.replace('0xffff000000000000ULL', '0x1000ULL')
fixture = Path(__file__).with_name('legacy_uid_index_fixture.c.in').read_text(encoding='utf-8')
(out / 'test.c').write_text(fixture.replace('/* ACTUAL_INDEX_FUNCTIONS */', body), encoding='utf-8')
image = 'sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2'
argv = ['docker', 'run', '--rm', '--network', 'none', '--mount',
        f'type=bind,source={out},target=/out', '--entrypoint', 'sh', image, '-c',
        '/opt/ddk/clang/clang-r510928/bin/clang -std=gnu11 -O1 -pthread -Wall -Wextra -Werror '
        '-fsanitize=address,undefined -fno-omit-frame-pointer /out/test.c -o /out/test '
        '&& timeout 45 /out/test']
run = subprocess.run(argv, capture_output=True, text=True, timeout=90)
result = dict(passed=run.returncode == 0, source=str(args.source.resolve()),
    sourceSha256=hashlib.sha256(raw).hexdigest(), functionSha256=hashlib.sha256(body.encode()).hexdigest(),
    argv=argv, exitCode=run.returncode, stdout=run.stdout, stderr=run.stderr,
    boundaries=['actual index functions; one host address-domain predicate adaptation',
                'explicit host hash/RCU/uaccess/reference seams', 'no target timing or hardware qualification'])
(out / 'RESULT.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(run.stdout, run.stderr[-5000:])
raise SystemExit(run.returncode)
