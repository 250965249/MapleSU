"""Capture declaration-only config evidence using the matching retained DDK."""
import argparse
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def generate(directory):
    directory = directory.resolve()
    if not re.fullmatch(r'android\d+-\d+\.\d+', directory.name) or directory.name == 'android17-6.18':
        raise ValueError('A matching DDK is required for declaration evidence')
    command = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--mount', f'type=bind,source={ROOT},target=/source,readonly',
        '--mount', f'type=bind,source={directory},target=/output/{directory.name}',
        'ghcr.io/ylarod/ddk-min:' + directory.name + '-20260828',
        'python3', '/source/scripts/policy_config_declarations.py', '/output/' + directory.name]
    subprocess.run(command, check=True, timeout=60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    generate(parser.parse_args().directory)
