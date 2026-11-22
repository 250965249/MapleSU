"""Load the production su-PATH constructor in isolated processes."""
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys

if len(sys.argv) == 3:
    libc = ctypes.CDLL(None)
    libc.getenv.restype = ctypes.c_char_p
    before = os.environ.get('PATH')
    ctypes.CDLL(sys.argv[1])
    actual = libc.getenv(b'PATH').decode()
    assert actual == sys.argv[2], (before, actual, sys.argv[2])
    raise SystemExit(0)

root = Path.cwd()
source = Path('/repo/runtime/ultra/parasite/su_env_loader.c')
lib = root / 'su-env-host.so'
subprocess.run(['/opt/ddk/clang/clang-r510928/bin/clang', '-shared', '-fPIC', '-Wall', '-Wextra',
                '-Werror', str(source), '-o', str(lib)], check=True)
data = lib.read_bytes()
marker = b'MAPLESU_SU_ENV_DIRECTORY_SLOT_5_1_0'
assert data.count(marker) == 1
offset = data.index(marker)
results = []
for name, directory, before, expected in [
    ('unset PATH', '/fixture/su', None, '/fixture/su:'),
    ('empty PATH', '/fixture/su', '', '/fixture/su:'),
    ('prepend directory', '/fixture/su', '/system/bin', '/fixture/su:/system/bin'),
    ('exact entry idempotent', '/fixture/su', '/system/bin:/fixture/su:/bin', '/system/bin:/fixture/su:/bin'),
    ('prefix is not exact entry', '/fixture/su', '/fixture/su-other:/bin', '/fixture/su:/fixture/su-other:/bin'),
    ('space preserved', '/fixture/su dir', '/bin', '/fixture/su dir:/bin'),
    ('invalid config ignored', 'relative', '/bin', '/bin'),
    ('colon config ignored', '/fixture/su:bad', '/bin', '/bin'),
]:
    patched = bytearray(data)
    patched[offset:offset + 1024] = directory.encode().ljust(1024, b'\0')
    path = root / ('su-env-' + str(len(results)) + '.so')
    path.write_bytes(patched)
    env = dict(os.environ)
    if before is None:
        env.pop('PATH', None)
    else:
        env['PATH'] = before
    subprocess.run([sys.executable, __file__, str(path), expected], env=env, check=True)
    print('PASS ' + name)
    results.append(name)
(root / 'su-env-regression.json').write_text(json.dumps({'checks': results, 'passed': True}, indent=2) + '\n')
