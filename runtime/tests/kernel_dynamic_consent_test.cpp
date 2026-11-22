#include "kernel_payload_loader.h"
#include "kernel_payload_io_fixture.h"
#include "compiled-layout.h"
#include "policy_layout_slots.h"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
using namespace maplesu::module_policy;
int main(int argc,char** argv) {
    assert(argc==3);
    std::ifstream input(argv[1],std::ios::binary);assert(input);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
    auto expected=parse_policy_payload(bytes,4096);
    assert(bind_policy_payload_layout(expected,compiled_layout(),{}));
    const auto at=expected.exports.at("maplesu_policy_layout");
    KernelPolicyBundle bundle{bytes,"fixture-build",4096,false,"caches_clean_inval_pou",{},compiled_layout};
    bundle.kernel_series=argv[2];
    const auto release=std::string(argv[2])+".123-fixture";
    unsigned tests=0;
    for(const bool consent:{false,true}) {
        Io io;
        io.inspect_prepare=[&](const Io& state) {
            assert(state.memory.size()>=at+sizeof(maplesu_policy_layout_table));
            assert(!memcmp(state.memory.data()+at,expected.image.data()+at,sizeof(maplesu_policy_layout_table)));
            assert(!state.hooks&&!state.activation_enabled);++tests;
        };
        assert(install_policy_view(bundle,"fixture-build",4096,{},io,release,"",consent)==3);
        assert(io.activation_enabled&&io.hooks==std::size(hook_names));++tests;
    }
    auto fails_before_kernel=[&](Io& io,const char* build,bool consent) {
        bool failed=false;
        try { install_policy_view(bundle,build,4096,{},io,release,"",consent); }
        catch(const std::runtime_error&) { failed=true; }
        assert(failed&&!io.allocations&&!io.hooks&&!io.activation_enabled);++tests;
    };
    for(const auto build:{"other-build",""}) for(const bool consent:{false,true}) {
        Io io;fails_before_kernel(io,build,consent);
    }
    {Io io;io.missing="policydb_read";fails_before_kernel(io,"fixture-build",true);}
    {Io io;io.prepare_error=true;bool failed=false;
     try { install_policy_view(bundle,"fixture-build",4096,{},io,release,"",true); }
     catch(const std::runtime_error&) { failed=true; }
     assert(failed&&io.prepared&&!io.hooks&&!io.activation_enabled&&!io.releases);++tests;}
    printf("PASS %u consent qualification cases (exact image reference binding; other/missing build rejected without BTF despite consent; missing import/prepare failure; kernel I/O fixture)\n",tests);
}
