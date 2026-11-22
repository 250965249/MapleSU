#!/usr/bin/env python3
"""Exercise actual PREPARE/cancel reuse, keeping resource/VM/text calls as seams."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
from run_p5_kernel_owner_test import extract

SDK=Path(__file__).resolve().parents[1]
REPO=SDK.parents[2]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    path=REPO/'runtime/ultra/identity/kernel/manager_management.c';source=path.read_text(encoding='utf-8')
    structs=extract(source,'struct msu_private_return_owner {',True)+'\n'+extract(source,'struct msu_publication {',True)
    functions='\n'.join(extract(source,signature) for signature in ['static int msu_publication_entry_check(',
        'static int msu_publication_prepare_snapshot(',
        'static int msu_publication_release_unexposed(struct msu_publication *publication, u32 *effects)\n{'])
    host=functions.replace('(unsigned long)','(uintptr_t)').replace('_Static_assert','static_assert')
    # C permits implicit void* assignment; host is C++ on LLP64.
    host=host.replace('publication->private_return_pool = kcalloc(',
        'publication->private_return_pool = (struct msu_private_return_owner*)kcalloc(')
    host=host.replace('publication->control = control;','publication->control = (maplesu_publication_control_v3*)control;')
    fixture=SDK/'tests/p5_kernel_prepare_fixture.cpp';cpp=out/'kernel_prepare.cpp'
    cpp.write_text(fixture.read_text(encoding='utf-8').replace('// EXACT_STRUCTS',structs).replace('// EXACT_FUNCTIONS',host),encoding='utf-8')
    cxx=sorted((REPO/'.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    exe=out/'kernel_prepare.exe';command=[str(cxx),'-std=c++20','-O1','-I'+str(REPO/'runtime/ultra/authorization'),str(cpp),'-static','-o',str(exe)]
    build=subprocess.run(command,capture_output=True,text=True);(out/'compile.log').write_text(build.stdout+build.stderr,encoding='utf-8');assert not build.returncode,build.stderr
    run=subprocess.run([str(exe)],capture_output=True,text=True);(out/'run.log').write_text(run.stdout+run.stderr,encoding='utf-8');assert not run.returncode,run.stdout+run.stderr
    report=dict(passed=True,source=str(path),sourceSha256=hashlib.sha256(path.read_bytes()).hexdigest(),extractedSha256=hashlib.sha256((structs+functions).encode()).hexdigest(),command=command,output=run.stdout,
        hostAdaptations=['LP64 pointer casts use uintptr_t on LLP64','C implicit void* conversions explicit','_Static_assert spelling'],
        scope='actual PREPARE/cancel bodies; resource/VM/text/mutex scheduling seams; no live kernel concurrency')
    (out/'results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report));return 0


if __name__=='__main__':sys.exit(main())
