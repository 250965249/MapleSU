"""Run the actual SDK live-BTF field graph boundary cases without rebuilding the SDK."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CASES = ['live-field-basic', 'live-field-zero', 'live-field-owner-end',
         'live-field-owner-overflow', 'live-field-wide-owner', 'live-field-int-offset',
         'live-field-int-zero', 'live-field-int-invalid', 'live-field-array',
         'live-field-array-overflow', 'live-field-array-cycle', 'live-field-modifier-long',
         'live-field-modifier-cycle', 'live-field-modern', 'live-field-modern-bits',
         'live-field-modern-overflow', 'live-field-anonymous', 'live-field-anonymous-empty', 'live-field-union',
         'live-field-nested-owner', 'live-field-nested-read', 'live-field-nested-duplicate',
         'live-field-path', 'live-field-anonymous-cycle', 'live-field-duplicate',
         'live-field-many', 'live-field-missing', 'live-field-missing-type',
         'live-field-empty-owner', 'live-field-type-range', 'live-field-members-range',
         'live-field-find-truncated']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--ndk', action='store_true', help='Compile the actual resolver Android TU once after host cases')
    args = parser.parse_args()
    # Keep the prior string cases in the same host build: they consume the same
    # type fixture now that the field's type and width are actually resolved.
    sys.dont_write_bytecode = True
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location('live_btf_names', Path(__file__).with_name('test-live-btf-name-bounds.py'))
    names = module_from_spec(spec)
    spec.loader.exec_module(names)
    command = [sys.executable, str(ROOT / 'runtime/maplesu-sdk/sdk/tools/tests/kernel_layout/run.py'),
               '--out', str(args.out.resolve()), '--sanitize']
    for case in CASES + names.CASES:
        command += ['--case', case]
    result = subprocess.run(command, cwd=ROOT).returncode
    if result or not args.ndk:
        return result
    return names.compile_ndk(args.out.resolve() / 'ndk')


if __name__ == '__main__':
    raise SystemExit(main())
