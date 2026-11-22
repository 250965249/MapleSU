"""Check the legacy parasite ABI in the Ultra archive or linked bridge."""
import argparse
import json
from pathlib import Path
import subprocess

SYMBOLS = [
    '_ZN11kernel_root29parasite_precheck_app_with_cbEPKcS1_PFvS1_NS_15AppDynlibStatusEE',
    '_ZN11kernel_root20parasite_implant_appEPKcS1_S1_',
    '_ZN11kernel_root23parasite_implant_su_envEPKcS1_S1_S1_',
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=Path, required=True)
    parser.add_argument('--ndk', type=Path, required=True)
    parser.add_argument('--dynamic', action='store_true')
    args = parser.parse_args()
    nm = args.ndk / 'toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-nm.exe'
    command = [str(nm), '--defined-only', '--extern-only']
    if args.dynamic:
        command.append('--dynamic')
    result = subprocess.run(command + [str(args.file)], capture_output=True, text=True, check=True)
    defined = {line.split()[-1] for line in result.stdout.splitlines() if line.split()}
    report = {symbol: symbol in defined for symbol in SYMBOLS}
    print(json.dumps(report, indent=2))
    return 0 if all(report.values()) else 1

if __name__ == '__main__':
    raise SystemExit(main())
