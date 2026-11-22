#!/usr/bin/env python3
"""Host-test exact pure parser/helper source; all generated outputs go to --out."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
SDK = HERE.parents[2]
ROOT = SDK.parents[2]
SOURCE = SDK / 'src/module/module_append_package_parser.cpp'
BINDER = ROOT / 'jailbreak-providers/root-loader/module/boot_sdk_protocol.h'
IMAGE = 'sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e'


def function(text, signature):
    start = text.index(signature)
    opening = text.index('{', start)
    depth = 1
    at = opening + 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[start:at]


def extract_parser(text):
    # Compile original helper text and the public function, without unrelated TUs.
    headers = '\n'.join(line for line in text.splitlines() if re.match(r'#include <', line))
    start = text.index('namespace {')
    end = text.index('namespace kernel_module {')
    helpers = text[start:end]
    parser = function(text, 'void parser_root_key_info(')
    return headers + '\n' + helpers + '\nnamespace kernel_module {\n' + parser + '\n}\n'


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--out', type=Path, required=True)
    cli.add_argument('--source', type=Path, default=SOURCE)
    cli.add_argument('--expect-red', action='store_true')
    args = cli.parse_args()
    out = args.out.resolve()
    if out.drive.upper() != 'C:':
        raise SystemExit('--out must be on C:; generated objects stay off the workspace volume')
    out.mkdir(parents=True, exist_ok=True)
    source_text = args.source.read_text(encoding='utf-8-sig')
    binder_text = BINDER.read_text(encoding='utf-8-sig')
    (out / 'source_snapshot.cpp').write_text(source_text, encoding='utf-8')
    (out / 'actual_parser.cpp').write_text(extract_parser(source_text), encoding='utf-8')
    (out / 'actual_bind_key.cpp').write_text(function(binder_text, 'static int msu_sdk_bind_key(') + '\n', encoding='utf-8')
    commands = []

    def run(name, argv):
        done = subprocess.run([str(part) for part in argv], capture_output=True,
                              text=True, encoding='utf-8', errors='replace')
        (out / (name + '.log')).write_text(done.stdout + done.stderr, encoding='utf-8')
        commands.append({'name': name, 'argv': [str(part) for part in argv], 'exit': done.returncode})
        if done.returncode:
            raise RuntimeError(name + ': ' + done.stderr[-2000:])
        return done

    docker = ['docker.exe', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
              '--tmpfs', '/tmp:rw,size=64m',
              '--mount', f'type=bind,source={HERE},target=/tests,readonly',
              '--mount', f'type=bind,source={out},target=/work', '-w', '/work',
              '--entrypoint', '/bin/sh', IMAGE]
    run('compiler-version', [*docker, '-c', 'exec g++ --version'])
    run('compile', [*docker, '-c', 'exec "$@"', 'sh', 'g++', '-std=c++20', '-O1', '-g',
                   '-Wall', '-Wextra', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                   '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-I/work',
                   '/tests/fixture.cpp', '-o', '/work/parser-test'])
    listing = run('list', [*docker, '-c', 'exec ./parser-test --list'])
    names = listing.stdout.splitlines()
    if not names or any(not re.fullmatch(r'[a-z0-9_-]+', name) for name in names):
        raise RuntimeError('unexpected case names')
    script = '\n'.join(
        f'ASAN_OPTIONS=detect_leaks=0:symbolize=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 '
        f'./parser-test {name} > {name}.log 2>&1\nprintf "%s\\n" "$?" > {name}.exit'
        for name in names)
    run('cases', [*docker, '-c', script])
    results = []
    for name in names:
        log = (out / (name + '.log')).read_text(encoding='utf-8')
        rows = [json.loads(line) for line in log.splitlines() if line.startswith('{')]
        results.append({'name': name, 'exit': int((out / (name + '.exit')).read_text()),
                        'rows': rows, 'asan': 'ERROR: AddressSanitizer:' in log,
                        'ubsan': 'runtime error:' in log})
    failed = sum(row['exit'] != 0 for row in results)
    receipt = {'passed': failed == 0, 'testedCodeHadFailures': failed != 0,
               'expectedRed': args.expect_red, 'failures': failed,
               'image': IMAGE, 'productionOutputsWritten': False, 'deviceAccess': False,
               'boundaries': 'exact parser/helpers and exact pure msu_sdk_bind_key only; no external stubs',
               'inputs': [{'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                          for path in [args.source.resolve(), BINDER, HERE / 'fixture.cpp', Path(__file__).resolve()]],
               'extractedSources': [{'path': str(out / name), 'sha256': hashlib.sha256((out / name).read_bytes()).hexdigest()}
                                    for name in ['actual_parser.cpp', 'actual_bind_key.cpp']],
               'results': results, 'commands': commands}
    (out / 'RESULTS.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': failed == 0, 'cases': len(results), 'failures': failed, 'out': str(out)}))
    return 0 if (failed > 0 if args.expect_red else failed == 0) else 1


if __name__ == '__main__':
    raise SystemExit(main())
