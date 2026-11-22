"""Compile the production SDK receipt/activation functions with kernel I/O seams."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/selinux-reliability-20261116/hook-receipt'
OUT.mkdir(parents=True, exist_ok=True)
source = (ROOT / 'runtime/maplesu-sdk/sdk/src/module/module_selinux.cpp').read_text(encoding='utf-8')
start = source.index('struct SelinuxHookReceipt {')
end = source.index('\n}  // namespace', start)
(OUT / 'selinux_hooks_under_test.inc').write_text(source[start:end], encoding='utf-8')
result = subprocess.run([
    'docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
    '--mount', f'type=bind,source={ROOT},target=/source,readonly',
    '--mount', f'type=bind,source={OUT},target=/output',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', 'sh', '-ec',
    'c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined '
    '-I/source/runtime/maplesu-sdk/include -I/output '
    '/source/runtime/tests/selinux_hook_receipt_test.cpp -o /output/receipt-test && /output/receipt-test',
], capture_output=True, text=True)
(OUT / 'result.log').write_text(result.stdout + result.stderr, encoding='utf-8')
print(result.stdout + result.stderr)
raise SystemExit(result.returncode)
