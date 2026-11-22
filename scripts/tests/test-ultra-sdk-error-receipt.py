"""Run real authorization transaction + bridge JSON mapping with host I/O fixtures."""
import argparse
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--image', default='ghcr.io/ylarod/ddk-min:android15-6.6-20260828')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
script = '''set -eu
g++ -std=c++17 -Wall -Wextra -Werror \\
  -I/repo/runtime/maplesu-sdk/include -I/repo/runtime/ultra/bridge \\
  -I/repo/runtime/ultra/authorization \\
  -I/repo/runtime/ultra/third_party/cJSON \\
  /repo/runtime/tests/ultra_sdk_error_receipt_test.cpp \\
  /repo/runtime/ultra/authorization/su_auth_transaction.cpp \\
  /repo/runtime/ultra/third_party/cJSON/cJSON.cpp -o /tmp/receipt.test
/tmp/receipt.test
'''
result = subprocess.run([
    'docker', 'run', '--rm', '--pull=never', '--network', 'none',
    '--tmpfs', '/data:exec', '--tmpfs', '/tmp:exec',
    '--mount', f'type=bind,source={repo},target=/repo,readonly',
    '--entrypoint', '/bin/sh', args.image, '-c', script,
], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
print(result.stdout + result.stderr, end='')
raise SystemExit(result.returncode)
