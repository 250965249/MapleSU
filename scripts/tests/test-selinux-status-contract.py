"""Check production status/access paths on both sides of the sample's 6.10 branch."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/selinux-reliability-20261116/contract'
OUT.mkdir(parents=True, exist_ok=True)
queries = (ROOT / 'runtime/ultra/policy/kernel/ksu_queries.c').read_text(encoding='utf-8')
# Keep the actual transaction handler; inject only kernel permission/SID/AV APIs.
access = queries[queries.index('static ssize_t view_access('):
                 queries.index('ssize_t maplesu_policy_view_context(')]
(OUT / 'selinux_access_under_test.inc').write_text(access, encoding='utf-8')
for version in ('0x060600', '0x060c00'):
    commands = []
    for test in ('policy_view_boot', 'policy_status_inheritance', 'policy_reload', 'selinux_status_contract'):
        commands += [
            'cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined '
            f'-DLINUX_VERSION_CODE={version} -DMAPLESU_POLICY_BOOT_HOST_TEST '
            '-I/source/runtime/ultra/policy/kernel -I/source/runtime/tests/policy_view_fixture '
            '/source/runtime/ultra/policy/kernel/policy_view.c '
            '/source/runtime/ultra/policy/kernel/policy_status.c '
            '/source/runtime/ultra/policy/kernel/policy_notifications.c '
            '/source/runtime/ultra/policy/kernel/policy_reload.c '
            f'/source/runtime/tests/{test}_test.c -o /output/{test}-{version}',
            f'/output/{test}-{version}',
        ]
    commands += [
        'cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined -I/output '
        f'/source/runtime/tests/selinux_access_contract_test.c -o /output/access-{version}',
        f'/output/access-{version}',
    ]
    command = [
        'docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
        '--mount', f'type=bind,source={ROOT},target=/source,readonly',
        '--mount', f'type=bind,source={OUT},target=/output',
        'ghcr.io/ylarod/ddk-min:android15-6.6-20260828', 'sh', '-ec',
        ' && '.join(commands),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    (OUT / f'{version}.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    print(version, result.stdout, result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
