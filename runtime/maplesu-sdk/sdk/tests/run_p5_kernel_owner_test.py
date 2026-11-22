#!/usr/bin/env python3
"""Exercise exact kernel provider code with allocator/task/list API seams.

This executes the real fixed64 pool, overflow, admission, ref and task-exit
functions. Kernel locks/scheduler/grace periods are outside this host fixture.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

SDK = Path(__file__).resolve().parents[1]
REPO = SDK.parents[2]


def extract(source, signature, struct=False):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end + int(struct)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    kernel = REPO / 'runtime/ultra/identity/kernel/manager_management.c'
    source = kernel.read_text(encoding='utf-8')
    # Only fields used by these functions are retained in the publication stub;
    # the owner itself and every executed provider function are exact source.
    owner = extract(source, 'struct msu_private_return_owner {', True)
    publication = '''struct msu_publication {
 u64 id,payload;u32 references,private_return_count;int private_return_error;
 u64 private_return_failures;list_head private_return_owners;
 msu_private_return_owner* private_return_pool;unsigned cleanup;
 bool reserved,ever_exposed,enabled,quarantined,retire_requested,payload_released;
};'''
    signatures = ['static void msu_private_return_fault(',
        'static struct msu_private_return_owner *msu_private_owner_acquire(',
        'static void msu_private_owner_release(', 'u64 msu_publication_enter(',
        'void msu_publication_leave(', 'static u64 msu_private_return_owner_acquire(',
        'static void msu_private_return_owner_release(', 'static int msu_private_return_status(',
        'static void msu_private_return_owner_task_exit(',
        'static u64 msu_private_return_caller_x28(', 'static u64 msu_private_return_caller_lr(',
        'static u64 msu_private_return_payload(']
    functions = '\n\n'.join(extract(source, signature) for signature in signatures)
    # The kernel is LP64 C; this host compiler is LLP64 C++. Preserve pointer
    # width and add the C implicit void* conversion without changing branches.
    host_functions = functions.replace('(void *)(unsigned long)',
        '(struct msu_private_return_owner *)(uintptr_t)').replace('(unsigned long)', '(uintptr_t)')
    fixture = SDK / 'tests/p5_kernel_owner_fixture.cpp'
    harness = fixture.read_text(encoding='utf-8').replace('// EXACT_STRUCTS',
        'struct msu_publication;\n' + owner + '\n' + publication).replace('// EXACT_FUNCTIONS', host_functions)
    cpp = out / 'kernel_owner.cpp'
    cpp.write_text(harness, encoding='utf-8')
    cxx = sorted((REPO / '.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    exe = out / 'kernel_owner.exe'
    command = [str(cxx), '-std=c++17', '-O1', str(cpp), '-static', '-o', str(exe)]
    build = subprocess.run(command, capture_output=True, text=True)
    (out / 'compile.log').write_text(build.stdout + build.stderr, encoding='utf-8')
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    (out / 'run.log').write_text(run.stdout + run.stderr, encoding='utf-8')
    assert run.returncode == 0, run.stdout + run.stderr
    report = dict(passed=True, source=str(kernel), sourceSha256=hashlib.sha256(kernel.read_bytes()).hexdigest(),
        extractedSha256=hashlib.sha256((owner + functions).encode()).hexdigest(), command=command,
        hostAdaptations=['LP64 unsigned long pointer casts use uintptr_t on LLP64',
            'C implicit void* to owner conversion made explicit for C++'],
        scope='exact kernel provider functions; allocator/task/list API seams; no kernel concurrency/grace/device execution',
        output=run.stdout)
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
