"""Test the research C++ AVC tail; production member 73 uses reference native bitcode."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'work/maplesu-selinux-20261116/implementation-avc'
OUT.mkdir(parents=True, exist_ok=True)
SOURCE = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else ROOT / 'runtime/maplesu-sdk/sdk/src/patch/patch_avc_denied.cpp'
source = SOURCE.read_text(encoding='utf-8')
start = source.index('    aarch64_my_exec_emitter(emit_0, stage_result);')
end = source.index('\n}\n\nKModErr PatchAvcDenied::disable_autorun_bootstrap_path()', start)
tail = source[start:end]
start = source.index('static bool my_is_kernel_version_less(')
end = source.index('\n}', start) + 2
version_gate = source[start:end]
(OUT / 'installation.inc').write_text(tail, encoding='utf-8')
(OUT / 'version.inc').write_text(version_gate, encoding='utf-8')
fixture = r"""
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
enum class KModErr : int64_t { OK=0, ERR_MODULE_AVC_DENIED_PATCH=-19 };
static std::string version;
static bool present, search_present;
static int installer_result, install_calls;
static std::vector<std::string> lookups;
static std::string myfind_kernel_version() { return version; }
static std::vector<int> myparse_version(const char* v) {
    std::vector<int> parts; std::stringstream stream(v); std::string item;
    while (std::getline(stream,item,'.')) parts.push_back(std::stoi(item));
    while (parts.size()<3) parts.push_back(0); return parts;
}
#include "version.inc"
namespace kernel_module {
KModErr get_append_package_kallsyms_kaddr(uint64_t&) { return KModErr::OK; }
KModErr kallsyms_lookup_name(const char* name, uint64_t& out) {
    lookups.emplace_back(name);
    out = std::strcmp(name,"strstr") == 0 ? (search_present ? 0x500000 : 0) : (present ? 0x400000 : 0);
    return out ? KModErr::OK : static_cast<KModErr>(-31);
}
}
static void aarch64_my_exec_emitter(int, uint64_t& out) {
    out=0; std::memcpy(&out,"5.6.0",6);
}
struct PatchAvcDenied {
    uint64_t m_avc_denied_addr_;
    KModErr patch_kernel_before_hook(uint64_t addr, void*) {
        ++install_calls;
        if (!addr) return static_cast<KModErr>(-91);
        return static_cast<KModErr>(installer_result);
    }
    KModErr run() {
        uint64_t stage_result=0; void* handler_a=nullptr;
        int emit_0=0,emit_1=1,emit_2=2,emit_3=3,emit_4=4,emit_5=5,emit_6=6;
        int emit_7=7,emit_8=8,emit_9=9,emit_10=10,emit_11=11,emit_12=12;
        int emit_13=13,emit_14=14,emit_15=15,emit_16=16,emit_17=17;
        int emit_18=18,emit_19=19,emit_20=20;
#include "installation.inc"
    }
};
int main() {
    for (const char* release : {"4.9.337","5.6.0","6.6.99",""}) {
        for (int scenario=0; scenario<4; ++scenario) {
            version=release; present=scenario!=1; search_present=scenario!=2;
            install_calls=0; installer_result=scenario==3 ? -77 : 77; lookups.clear();
            PatchAvcDenied patch{0x100000};
            auto result=patch.run();
            std::cout << (version.empty()?"unknown":version) << " " << scenario << " " << int64_t(result) << " " << install_calls;
            for (const auto& name : lookups) std::cout << " " << name;
            std::cout << "\n";
        }
        version=release; present=search_present=true; install_calls=0; installer_result=77; lookups.clear();
        PatchAvcDenied patch{0}; auto result=patch.run();
        std::cout << (version.empty()?"unknown":version) << " 4 " << int64_t(result) << " " << install_calls;
        for (const auto& name : lookups) std::cout << " " << name;
        std::cout << "\n";
    }
}
"""
(OUT / 'installation.cpp').write_text(fixture, encoding='utf-8')
build = subprocess.run([
    'docker','run','--rm','--pull','never','--network','none',
    '--mount',f'type=bind,source={OUT},target=/output',
    'ghcr.io/ylarod/ddk-min:android15-6.6-20260828','sh','-ec',
    'c++ -std=c++17 -Wall -Wextra /output/installation.cpp -o /output/installation && /output/installation',
],capture_output=True,text=True,encoding='utf-8',errors='replace')
tag = 'before-result' if SOURCE != ROOT / 'runtime/maplesu-sdk/sdk/src/patch/patch_avc_denied.cpp' else 'result'
(OUT / f'{tag}.log').write_text(build.stdout+build.stderr,encoding='utf-8')
if build.returncode:
    raise SystemExit(build.stdout+build.stderr)
checks=[]
for line in build.stdout.splitlines():
    release,scenario,result,calls,*lookups=line.split()
    scenario,result,calls=int(scenario),int(result),int(calls)
    expected_calls = 0 if scenario in (1,4) else 1
    expected_result = 0 if not expected_calls else (-77 if scenario==3 else 77)
    expected_symbol = 'saved_command_line' if release=='4.9.337' else 'saved_boot_config'
    checks.append(dict(release=release,scenario=scenario,result=result,calls=calls,lookups=lookups,
                       passed=result==expected_result and calls==expected_calls and lookups==[expected_symbol,'strstr']))
receipt=dict(sourceSha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),checks=checks,
             scope='research C++ installation tail only; dynamic emitters substituted',
             productionMemberExecuted=False,
             passed=len(checks)==20 and all(check['passed'] for check in checks))
(OUT / f'{tag}.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')
if not receipt['passed']:
    raise SystemExit(f'FAIL {sum(check["passed"] for check in checks)}/{len(checks)} AVC installation scenarios; see {tag}.json')
print(f'PASS research AVC installation tail: {len(checks)} scenarios; original production bitcode not executed')
