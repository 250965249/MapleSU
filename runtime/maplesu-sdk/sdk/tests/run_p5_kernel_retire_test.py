#!/usr/bin/env python3
"""Run the production retirement function against causal text/grace/free seams."""
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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    source=REPO/'runtime/ultra/identity/kernel/manager_management.c'
    function=extract(source.read_text(encoding='utf-8'),'static int msu_publication_retire(')
    fixture=SDK/'tests/p5_kernel_retire_fixture.cpp'
    cpp=out/'kernel_retire.cpp';cpp.write_text(fixture.read_text(encoding='utf-8').replace('// EXACT_FUNCTION',function),encoding='utf-8')
    cxx=sorted((REPO/'.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    exe=out/'kernel_retire.exe'
    command=[str(cxx),'-std=c++17','-O1','-I'+str(REPO/'runtime/ultra/authorization'),str(cpp),'-static','-o',str(exe)]
    build=subprocess.run(command,capture_output=True,text=True);(out/'compile.log').write_text(build.stdout+build.stderr,encoding='utf-8')
    assert build.returncode==0,build.stderr
    run=subprocess.run([str(exe)],capture_output=True,text=True);(out/'run.log').write_text(run.stdout+run.stderr,encoding='utf-8')
    assert run.returncode==0,run.stdout+run.stderr
    report=dict(passed=True,source=str(source),sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        extractedSha256=hashlib.sha256(function.encode()).hexdigest(),command=command,output=run.stdout,
        scope='production retire function; text/grace/allocator seams; no real SMP/grace or native-kernel execution')
    (out/'results.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report));return 0


if __name__=='__main__':sys.exit(main())
