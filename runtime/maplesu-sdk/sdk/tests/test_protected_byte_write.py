"""Exercise the actual protected-write API with an in-memory transport seam."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess

SDK = Path(__file__).resolve().parents[1]
ROOT = SDK.parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path, required=True)
parser.add_argument('--before', type=Path)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
source = SDK / 'src/kernel_mem/module_base_kernel_mem.cpp'

PREFIX = r'''
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <new>
#include <vector>
#include "module_err_def.h"
#include "module_base_kernel_mem.h"
#include "request_protocol.h"
constexpr uint64_t base = UINT64_C(0xffff000000001000);
constexpr bool is_kernel_address(uint64_t p) { return p >= UINT64_C(0xffff000000000000); }
std::array<uint8_t,64> memory;
bool owner, corrupt;
int reads, writes;
KModErr read_error, write_error;
namespace kernel_module {
bool maplesu_request_owner_mode() { return owner; }
KModErr request_kernel_read_mem(uint64_t p, void* out, uint32_t n) {
    ++reads;
    if (read_error != KModErr::OK) return read_error;
    if (p < base || p-base+n > memory.size()) return KModErr::ERR_MODULE_PARAM;
    std::memcpy(out, memory.data()+p-base, n); return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t p, void* out, uint32_t n) {
    return request_kernel_read_mem(p,out,n);
}
KModErr request_kernel_write_mem(uint64_t p, const void* data, uint32_t n) {
    ++writes;
    if (write_error != KModErr::OK) return write_error;
    if (p < base || p-base+n > memory.size()) return KModErr::ERR_MODULE_PARAM;
    std::memcpy(memory.data()+p-base,data,n);
    if (corrupt) memory[p-base+n-1] ^= 1;
    return KModErr::OK;
}
KModErr patch_kernel_static_code(uint64_t p, const void* data, uint32_t n) {
    if ((p|n)&3) return KModErr::ERR_MODULE_PARAM;
    return request_kernel_write_mem(p,data,n);
}
KModErr maplesu_request_owner_write_text(uint64_t p, const void* data, uint32_t n) {
    return patch_kernel_static_code(p,data,n);
}
'''
SUFFIX = r'''
}
int checks, failures;
void check(bool ok, const char* label) {
    ++checks; if (!ok) { ++failures; std::printf("FAIL %s\n",label); }
}
void reset() {
    for (unsigned i=0;i<memory.size();++i) memory[i]=static_cast<uint8_t>(0xa0+i);
    reads=writes=0; corrupt=false; read_error=write_error=KModErr::OK;
}
int main() {
    using namespace kernel_module;
    std::array<uint8_t,32> payload{};
    for (unsigned i=0;i<payload.size();++i) payload[i]=static_cast<uint8_t>(i+1);
    payload[17]=0; // Exact original m073 path length, including its NUL.
    for (bool mode : {false,true}) for (auto prot : {KernMemProt::KMP_RO,KernMemProt::KMP_X}) {
        owner=mode;
        for (unsigned n=1;n<=31;++n) {
            reset(); auto before=memory;
            check(write_kernel_mem(base,payload.data(),n,prot)==KModErr::OK,"protected byte write");
            check(std::memcmp(memory.data(),payload.data(),n)==0,"all bytes and NUL");
            check(std::memcmp(memory.data()+n,before.data()+n,memory.size()-n)==0,"neighbor preservation");
            check(writes==1,"single complete-word submission");
            check(reads==((n&3)?2:0),"tail snapshot and readback only when needed");
            reset(); before=memory;
            check(fill00_kernel_mem(base,n,prot)==KModErr::OK,"protected byte fill");
            bool zero=true; for(unsigned i=0;i<n;++i) zero &= memory[i]==0;
            check(zero && std::memcmp(memory.data()+n,before.data()+n,memory.size()-n)==0,"fill range");
        }
        reset(); auto original=memory; read_error=KModErr::ERR_MODULE_TEST_CHANNEL;
        check(write_kernel_mem(base,payload.data(),18,prot)==read_error && writes==0 && memory==original,"read error before mutation");
        reset(); original=memory; write_error=KModErr::ERR_MODULE_ASM;
        check(write_kernel_mem(base,payload.data(),18,prot)==write_error && reads==1 && memory==original,"write failure propagated");
        reset(); corrupt=true;
        check(write_kernel_mem(base,payload.data(),18,prot)==KModErr::ERR_MODULE_ASM,"readback mismatch fails");
        reset();
        check(write_kernel_mem(base+2,payload.data(),18,prot)==KModErr::ERR_MODULE_ADDR_NOT_ALGIN4 && !writes && !reads,"address alignment retained");
        check(write_kernel_mem(UINT64_MAX-3,payload.data(),5,prot)==KModErr::ERR_MODULE_PARAM && !writes && !reads,"range overflow retained");
        check(write_kernel_mem(base,payload.data(),UINT32_MAX,prot)==KModErr::ERR_MODULE_PARAM && !writes && !reads,"padded length overflow");
        check(write_kernel_mem(base,nullptr,18,prot)==KModErr::ERR_MODULE_PARAM && !writes && !reads,"null buffer");
        check(write_kernel_mem(base,payload.data(),0,prot)==KModErr::ERR_MODULE_PARAM && !writes && !reads,"zero length");
    }
    owner=false; reset();
    check(write_kernel_mem(base+1,payload.data(),18,KernMemProt::KMP_RW)==KModErr::OK && writes==1 && !reads,"RW byte contract");
    reset();
    check(write_kernel_mem(base,payload.data(),18,static_cast<KernMemProt>(3))==KModErr::ERR_MODULE_PARAM && !writes && !reads,"invalid protection");
    owner=true; reset();
    check(write_kernel_mem(base,payload.data(),MAPLESU_MANAGEMENT_MAX_BYTES+1,KernMemProt::KMP_X)==KModErr::ERR_MODULE_PARAM && !writes && !reads,"owner bound");
    std::printf("checks=%d failures=%d\n",checks,failures); return failures?1:0;
}
'''

compiler = shutil.which('g++') or 'C:/msys64/ucrt64/bin/g++.exe'
env = os.environ.copy()
env['PATH'] = str(Path(compiler).parent) + os.pathsep + env.get('PATH', '')
results = []
for label, path in ([('before', args.before)] if args.before else []) + [('current', source)]:
    text = path.read_text(encoding='utf-8-sig')
    start = text.index('static KModErr validate_kernel_write_range(')
    end = text.index('KModErr read_kernel_mem_atomic32(', start)
    unit = args.out / (label + '.cpp')
    unit.write_text(PREFIX + text[start:end] + SUFFIX, encoding='utf-8')
    exe = args.out / (label + '.exe')
    command = [compiler, '-std=c++20', '-O1', '-Wall', '-Wextra', '-static',
               '-I', str(SDK.parent / 'include'), '-I', str(ROOT / 'runtime/ultra/authorization'),
               str(unit), '-o', str(exe)]
    built = subprocess.run(command, capture_output=True, env=env, timeout=60)
    (args.out / (label + '-compile.log')).write_bytes(built.stdout + built.stderr)
    if built.returncode:
        raise RuntimeError(built.stderr.decode(errors='replace'))
    ran = subprocess.run([str(exe)], capture_output=True, env=env, timeout=20)
    (args.out / (label + '.log')).write_bytes(ran.stdout + ran.stderr)
    results.append(dict(label=label, source=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        compileCommand=command, exit=ran.returncode,
                        summary=ran.stdout.decode().splitlines()[-1]))
passed = results[-1]['exit'] == 0 and (not args.before or results[0]['exit'] != 0)
report = dict(passed=passed, results=results, deviceAcceptance=False,
              scope='Exact production API functions; memory and instruction-patch transport are seams')
(args.out / 'REGRESSION.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, indent=2))
raise SystemExit(0 if passed else 1)
