#include "kernel_layout.h"
#include "jailbreak_status_layout.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <iterator>
using namespace maplesu::module_policy;
namespace {
void word(std::vector<uint8_t>&v,uint32_t n){for(unsigned i=0;i<4;++i)v.push_back(uint8_t(n>>(i*8)));}
struct Fixture {
    std::vector<uint8_t> types,strings{0};
    uint32_t str(const char*s){auto n=uint32_t(strings.size());do{strings.push_back(*s);}while(*s++);return n;}
    void record(const char*n,uint32_t k,uint32_t v,uint32_t c=0,bool bits=false){
        word(types,str(n));word(types,k<<24|c|(bits?0x80000000:0));word(types,v);
    }
    void member(const char*n,uint32_t t,uint32_t o){word(types,str(n));word(types,t);word(types,o);}
    void integer(){record("u32",1,4);word(types,32);}
    void policy(uint32_t size,uint32_t offset){record("policy",4,size,1);member("sid",1,offset);}
    std::vector<uint8_t> bytes(){std::vector<uint8_t> out;word(out,0x0001eb9f);word(out,24);word(out,0);
        word(out,uint32_t(types.size()));word(out,uint32_t(types.size()));word(out,uint32_t(strings.size()));
        out.insert(out.end(),types.begin(),types.end());out.insert(out.end(),strings.begin(),strings.end());return out;}
};
unsigned tests;
template<class F> void fails(F f,const char*part){bool failed=false;try{f();}catch(const std::runtime_error&e){
    failed=std::string(e.what()).find(part)!=std::string::npos;}assert(failed);++tests;}
void generic_tests(){
    for(auto offset:{0u,32u,64u,128u}){
        Fixture f;f.integer();f.policy(32,offset);auto d=describe_kernel_layout(f.bytes(),{{"policy",{"sid"}}});
        assert(d.types.size()==1&&d.types[0].size==32&&d.types[0].fields[0].bit_offset==offset&&d.types[0].fields[0].bit_size==32);++tests;
    }
    {Fixture f;f.integer();f.policy(32,64);f.policy(32,64);
        auto d=describe_kernel_layout(f.bytes(),{{"policy",{"sid"}}});assert(d.types[0].fields[0].bit_offset==64);++tests;
        f.policy(32,128);fails([&]{describe_kernel_layout(f.bytes(),{{"policy",{"sid"}}});},"AMBIGUOUS");}
    {Fixture f;f.integer();f.policy(4,32);fails([&]{describe_kernel_layout(f.bytes(),{{"policy",{"sid"}}});},"MEMBER_BOUNDS");}
    {Fixture f;f.integer();f.record("",5,4,1);f.member("sid",1,0);f.record("policy",4,16,1);f.member("",2,64);
        auto d=describe_kernel_layout(f.bytes(),{{"policy",{"sid"}}});assert(d.types[0].fields[0].bit_offset==64);++tests;}
    {Fixture f;f.integer();f.record("policy",4,4,1,true);f.member("sid",1,5u<<24|7);
        auto d=describe_kernel_layout(f.bytes(),{{"policy",{"sid"}}});assert(d.types[0].fields[0].bit_offset==7&&d.types[0].fields[0].bit_size==5);++tests;}
    {Fixture f;f.integer();f.policy(16,0);f.record("",13,0);f.record("entry",12,3);
        auto d=describe_kernel_layout(f.bytes(),{{"policy",{}}},{"entry"});assert(d.functions[0].signature=="fv()");++tests;
        f.record("",13,1);f.record("entry",12,5);fails([&]{describe_kernel_layout(f.bytes(),{{"policy",{}}},{"entry"});},"ABI_AMBIGUOUS");}
    {Fixture f;f.integer();f.policy(16,0);fails([&]{describe_kernel_layout(f.bytes(),{{"missing",{}}});},"MISSING");
        fails([&]{describe_kernel_layout(f.bytes(),{{"policy",{"missing"}}});},"MEMBER");
        fails([&]{describe_kernel_layout(f.bytes(),{{"policy",{}}},{"missing"});},"ABI_MISSING");}
}
void anchor_tests(){
    msu_selinux_anchors a{};a.page_function=0x100000;a.enforce_function=0x110000;a.mutex_lock=0x120000;
    for(auto off:{24u,40u,72u}){
        const unsigned code[]={0xd503233f,0xf800865e,0xa9bd7bfd,0xf9000bf5,0xa9024ff4,
            0x910003fd,0x91000013|(off<<10),0xaa0003f4,0xaa1303e0};
        memset(a.page_code,0,sizeof(a.page_code));memset(a.enforce_code,0,sizeof(a.enforce_code));
        memcpy(a.page_code,code,sizeof(code));memcpy(a.enforce_code,code,sizeof(code));
        a.enforce_code[7]=0x2a0103f4; // Native setenforce saves its 32-bit second argument.
        a.page_code[9]=0x94000000u|uint32_t((a.mutex_lock-a.page_function-36)/4);
        a.enforce_code[9]=0x94000000u|uint32_t((a.mutex_lock-a.enforce_function-36)/4);
        auto d=resolve_jailbreak_status_anchors(a,4096);assert(d.status_lock==off&&d.status_page_abi==1&&!d.state_size&&!d.mutex_size);++tests;
        for(auto page:{16384u,65536u}){auto e=resolve_jailbreak_status_anchors(a,page);assert(e.page_bytes==page);++tests;}
        fails([&]{resolve_jailbreak_status_anchors(a,8192);},"ANCHORS_UNRESOLVED");
    }
    {msu_selinux_anchors global{};
        global.page_function=0x100000;global.enforce_function=0x110000;global.mutex_lock=0x120000;
#if MSU_STATUS_VERSION >= 3
        global.state=0x200600;
#endif
        for(unsigned i=0;i<2;++i){auto code=i?global.enforce_code:global.page_code;
            auto pc=i?global.enforce_function:global.page_function;auto delta=(0x200000-pc)/4096;
            code[0]=0x90000013u|uint32_t((delta&3)<<29)|uint32_t((delta>>2)<<5);
            code[1]=0x91000273u|(0x600u<<10);code[2]=0x91006260u;
            code[3]=0x94000000u|uint32_t((global.mutex_lock-pc-12)/4);}
        auto d=resolve_jailbreak_status_anchors(global,4096);assert(d.status_lock==24&&d.status_page_abi==0);++tests;
    }
    a.page_code[6]^=8u<<10;fails([&]{resolve_jailbreak_status_anchors(a,4096);},"ANCHORS_UNRESOLVED");
    a.page_code[6]^=8u<<10;a.enforce_code[9]^=1;fails([&]{resolve_jailbreak_status_anchors(a,4096);},"ANCHORS_UNRESOLVED");
    a.enforce_code[9]^=1;a.page_code[1]=0xd61f0000;fails([&]{resolve_jailbreak_status_anchors(a,4096);},"ANCHORS_UNRESOLVED");
}
}
int main(int argc,char**argv){
    if(argc==1){generic_tests();anchor_tests();printf("PASS %u dynamic-layout / live-anchor cases\n",tests);return 0;}
    std::ifstream input(argv[1],std::ios::binary);std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
    assert(input.good()||input.eof());
    for(auto page:{4096u,16384u,65536u}){
        msu_selinux_layout d;
        if(argc>2&&!strcmp(argv[2],"anchors")){
            assert(bytes.size()==sizeof(msu_selinux_anchors));msu_selinux_anchors a;memcpy(&a,bytes.data(),sizeof(a));
            d=resolve_jailbreak_status_anchors(a,page);
        }else d=resolve_jailbreak_status_layout(bytes,page);
        printf("PASS source=%u state=%u lock=%u mutex=%u page=%u arguments=%u\n",
            d.source,d.state_size,d.status_lock,d.mutex_size,d.page_bytes,d.status_page_abi);
    }
}
