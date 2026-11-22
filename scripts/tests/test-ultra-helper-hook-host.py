"""Compile and run the checked helper publication policy on a native host."""
import argparse
from pathlib import Path
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
root=Path(__file__).resolve().parents[2]
out=a.out.resolve();out.mkdir(parents=True,exist_ok=True)
script='''set -eu
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -std=c++17 -stdlib=libc++ -Wall -Wextra -Werror \\
 -I/repo/runtime/maplesu-sdk/include -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \\
 /repo/runtime/tests/pro_helper_hook_test.cpp -o /case/hook-policy.test
/case/hook-policy.test
'''
r=subprocess.run(['docker','run','--rm','--network','none','--mount',
 f'type=bind,source={root},target=/repo,readonly','--mount',
 f'type=bind,source={out},target=/case','--entrypoint','sh',
 'ghcr.io/ylarod/ddk-min:android15-6.6-20260828','-c',script],capture_output=True,text=True)
(out/'hook-policy-regression.log').write_text(r.stdout+r.stderr,encoding='utf-8')
print(r.stdout+r.stderr)
raise SystemExit(r.returncode)
