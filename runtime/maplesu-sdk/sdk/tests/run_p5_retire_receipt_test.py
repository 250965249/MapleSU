#!/usr/bin/env python3
"""Execute exact production request validators for P5 retirement receipts."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys

SDK = Path(__file__).resolve().parents[1]
REPO = SDK.parents[2]


def extract_function(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    path = SDK / 'src/kernel_request/module_base_kernel_request.cpp'
    source = path.read_text(encoding='utf-8')
    error_validator = extract_function(source, 'bool management_error_shape(')
    case_start = source.index('case MAPLESU_REQUEST_PUBLICATION_PUBLISH:',
        source.index('KModErr management_exchange('))
    case_end = source.index('\n        }\n        }', case_start) + len('\n        }')
    success_case = source[case_start:case_end]
    harness = '''#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include "request_protocol.h"
bool maplesu_request_helper_mode(){return false;}
''' + error_validator + '''
bool success(uint32_t command,const maplesu_management_v3& operation,const maplesu_response_owner_v3& response){
 bool valid=false;switch(command){
''' + success_case + '''
 }return valid;
}
int main(){
 maplesu_management_v3 operation{};operation.handle=17;
 const uint32_t released=MAPLESU_EFFECT_RELEASED;
 const uint32_t text=MAPLESU_EFFECT_TEXT_ATTEMPTED|MAPLESU_EFFECT_WRITTEN;
 const uint32_t retained=MAPLESU_EFFECT_PUBLICATION_RETAINED|MAPLESU_EFFECT_GATE_PINNED;
 const uint32_t shared=MAPLESU_EFFECT_REFERENCE_DROPPED|MAPLESU_EFFECT_SHARED_RETAINED;
 unsigned checks=0;
 auto check=[&](const char* name,uint32_t effects,uint64_t result,bool expected,bool error=false,uint64_t handle=17,uint32_t command=MAPLESU_REQUEST_PUBLICATION_RETIRE){
  maplesu_response_owner_v3 response{};response.metadata_address=handle;response.metadata_length=effects;response.result=result;
  const bool actual=error?management_error_shape(command,operation,response):success(command,operation,response);
  if(actual!=expected){std::cerr<<name<<" expected="<<expected<<" actual="<<actual<<"\\n";return false;}
  ++checks;return true;
 };
 bool ok=true;
 ok&=check("final-free",released,0,true);
 ok&=check("final-free-restored-text",released|text,4,true);
 ok&=check("final-free-shared-ref",released|shared,0,true);
 ok&=check("legacy-retained",released|retained,0,true);
 ok&=check("legacy-retained-text",released|retained|text,4,true);
 ok&=check("success-pending-rejected",released|MAPLESU_EFFECT_PENDING,0,false);
 ok&=check("success-no-release-rejected",text,4,false);
 ok&=check("partial-retained-rejected",released|MAPLESU_EFFECT_GATE_PINNED,0,false);
 ok&=check("partial-text-rejected",released|MAPLESU_EFFECT_WRITTEN,4,false);
 ok&=check("partial-text-attempted-rejected",released|MAPLESU_EFFECT_TEXT_ATTEMPTED,4,false);
 ok&=check("text-zero-result-rejected",released|text,0,false);
 ok&=check("shared-without-drop-rejected",released|MAPLESU_EFFECT_SHARED_RETAINED,0,false);
 ok&=check("stale-handle-rejected",released,0,false,false,18);
 ok&=check("pending-retirement",retained|MAPLESU_EFFECT_PENDING,0,true,true);
 ok&=check("pending-after-partial-free",released|MAPLESU_EFFECT_PENDING,0,true,true);
 ok&=check("quarantined-pending",retained|MAPLESU_EFFECT_QUARANTINED|MAPLESU_EFFECT_PENDING,0,true,true);
 ok&=check("quarantine-without-pending",retained|MAPLESU_EFFECT_QUARANTINED,0,false,true);
 ok&=check("pending-shared",released|shared|MAPLESU_EFFECT_PENDING,0,true,true);
 ok&=check("error-shared-without-drop",released|MAPLESU_EFFECT_SHARED_RETAINED,0,false,true);
 ok&=check("error-written-without-attempt",released|MAPLESU_EFFECT_WRITTEN,4,false,true);
 ok&=check("error-wrong-handle",released|MAPLESU_EFFECT_PENDING,0,false,true,18);
 const uint32_t disable=MAPLESU_REQUEST_PUBLICATION_DISABLE;
 ok&=check("disable-already-released",released,0,true,false,17,disable);
 ok&=check("disable-live-retained",retained,0,true,false,17,disable);
 ok&=check("disable-already-released-result4",released,4,false,false,17,disable);
 ok&=check("disable-partial-release-success",released|MAPLESU_EFFECT_PENDING,0,false,false,17,disable);
 ok&=check("disable-released-error-pending",released|MAPLESU_EFFECT_PENDING,0,true,true,17,disable);
 ok&=check("disable-released-error-quarantine",released|MAPLESU_EFFECT_PENDING|MAPLESU_EFFECT_QUARANTINED,0,true,true,17,disable);
 ok&=check("disable-error-quarantine-no-pending",released|MAPLESU_EFFECT_QUARANTINED,0,false,true,17,disable);
 ok&=check("disable-error-released-written",released|text,4,false,true,17,disable);
 const uint32_t publish=MAPLESU_REQUEST_PUBLICATION_PUBLISH;
 const uint32_t published=MAPLESU_EFFECT_PUBLICATION_PUBLISHED|MAPLESU_EFFECT_PUBLICATION_RETAINED;
 ok&=check("publish-native-logical",published,0,true,false,17,publish);
 ok&=check("publish-physical-text",published|text,4,true,false,17,publish);
 ok&=check("publish-no-published-effect",MAPLESU_EFFECT_PUBLICATION_RETAINED,0,false,false,17,publish);
 ok&=check("publish-wrong-result4",published,4,false,false,17,publish);
 ok&=check("publish-wrong-result0-text",published|text,0,false,false,17,publish);
 ok&=check("publish-logical-pending-error",published|MAPLESU_EFFECT_PENDING,0,true,true,17,publish);
 ok&=check("publish-physical-pending-error",published|text|MAPLESU_EFFECT_PENDING,4,true,true,17,publish);
 ok&=check("publish-error-without-pending",published,0,false,true,17,publish);
 ok&=check("publish-error-incomplete-text",published|MAPLESU_EFFECT_WRITTEN|MAPLESU_EFFECT_PENDING,4,false,true,17,publish);
 std::cout<<"checks="<<checks<<" passed="<<ok<<"\\n";return !ok;
}
'''
    cpp = out / 'retire_receipt.cpp'
    cpp.write_text(harness, encoding='utf-8')
    cxx = sorted((REPO / '.research/toolchains').glob('llvm-mingw-*/bin/x86_64-w64-mingw32-clang++.exe'))[-1]
    exe = out / 'retire_receipt.exe'
    command = [str(cxx), '-std=c++17', '-O1', '-I' + str(REPO / 'runtime/ultra/authorization'),
        str(cpp), '-static', '-o', str(exe)]
    build = subprocess.run(command, capture_output=True, text=True)
    (out / 'compile.log').write_text(build.stdout + build.stderr, encoding='utf-8')
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    (out / 'run.log').write_text(run.stdout + run.stderr, encoding='utf-8')
    assert run.returncode == 0, run.stdout + run.stderr
    report = dict(passed=True, checks=38, source=str(path),
        sourceSha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        extractedSha256=hashlib.sha256((error_validator + success_case).encode()).hexdigest(),
        scope='exact production request validator extraction; no real gateway or kernel execution',
        command=command, output=run.stdout)
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
