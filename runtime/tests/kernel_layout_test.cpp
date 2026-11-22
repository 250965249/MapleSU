#include "kernel_layout.h"
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <utility>
using namespace maplesu::module_policy;
namespace {
void word(std::vector<uint8_t>& v,uint32_t x) {for(unsigned i=0;i<4;++i)v.push_back(uint8_t(x>>(i*8)));}
void patch(std::vector<uint8_t>& v,size_t at,uint32_t x) {for(unsigned i=0;i<4;++i)v[at+i]=uint8_t(x>>(i*8));}
struct Fixture {
    std::vector<uint8_t> types,strings{0};
    uint32_t str(const char* s) {auto n=uint32_t(strings.size());do{strings.push_back(*s);}while(*s++);return n;}
    void record(const char* name,uint32_t kind,uint32_t value,uint32_t n=0,bool bits=false) {
        word(types,str(name));word(types,kind<<24|n|(bits?0x80000000:0));word(types,value);
    }
    std::vector<uint8_t> bytes() {
        std::vector<uint8_t> v;word(v,0x0001eb9f);word(v,24);word(v,0);word(v,uint32_t(types.size()));
        word(v,uint32_t(types.size()));word(v,uint32_t(strings.size()));
        v.insert(v.end(),types.begin(),types.end());v.insert(v.end(),strings.begin(),strings.end());return v;
    }
    void integer(){record("u32",1,4);word(types,32);}
    void structure(){record("policy",4,8,2);word(types,str("sid"));word(types,1);word(types,0);
        word(types,str("flags"));word(types,1);word(types,32);}
};
Fixture integer_field(uint32_t encoding,uint32_t offset,bool modern=false,uint32_t storage=4,uint32_t owner=32) {
    Fixture f;f.record("integer",1,storage);word(f.types,encoding);
    f.record("policy",4,owner,1,modern);word(f.types,f.str("value"));word(f.types,1);word(f.types,offset);
    return f;
}
unsigned tests;
void success(const std::vector<uint8_t>& data,std::vector<LayoutType> wanted) {
    verify_kernel_layout(data,wanted);++tests;
}
void failure(const std::vector<uint8_t>& data,std::vector<LayoutType> wanted,const char* part) {
    bool failed=false;try{verify_kernel_layout(data,wanted);}catch(const std::runtime_error& e){
        failed=std::string(e.what()).find(part)!=std::string::npos;}
    assert(failed);++tests;
}
Fixture credential_fixture() {
    Fixture f;f.integer();
    f.record("cred",4,64,1);word(f.types,f.str("suid"));word(f.types,1);word(f.types,0);
    f.record("cred",4,32,3);
    for(auto member:{std::pair{"suid",64U},std::pair{"sgid",96U},std::pair{"euid",160U}}){
        word(f.types,f.str(member.first));word(f.types,1);word(f.types,member.second);}
    f.record("",10,3);f.record("",2,4);f.record("cred_pointer",8,5);
    f.record("seccomp",4,16,1);word(f.types,f.str("mode"));word(f.types,1);word(f.types,64);
    f.record("task_struct",4,80,2);
    word(f.types,f.str("cred"));word(f.types,6);word(f.types,128);
    word(f.types,f.str("seccomp"));word(f.types,7);word(f.types,384);
    return f;
}
void credential_failure(const Fixture& fixture,const char* part) {
    auto copy=fixture;bool failed=false;
    try{describe_task_credential_layout(copy.bytes(),{"cred"},{"suid","sgid","euid"});}
    catch(const std::runtime_error& e){failed=std::string(e.what()).find(part)!=std::string::npos;}
    assert(failed);++tests;
}
void credential_abi_failure(const Fixture& fixture,const char* part) {
    auto copy=fixture;bool failed=false;
    std::vector<KernelFunctionAbi> abis{{"sentinel","unchanged"}};
    try{describe_task_credential_layout(copy.bytes(),{"cred"},{"suid","sgid","euid"},abis);}
    catch(const std::runtime_error& e){failed=std::string(e.what()).find(part)!=std::string::npos;}
    assert(failed && abis.size()==1 && abis[0].name=="sentinel" && abis[0].signature=="unchanged");++tests;
}
}
int main(){
    Fixture f;f.integer();f.structure();auto good=f.bytes();
    std::vector<LayoutType> wanted{{"policy",8,{{"sid",0,32},{"flags",32,32}}}};
    success(good,wanted);
    success(good,{{"policy",0,{{"sid",0,32}}}});
    failure(good,{},"EMPTY_CONTRACT");
    {bool failed=false;try{describe_kernel_layout(good,{});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("EMPTY_CONTRACT")!=std::string::npos;}
        assert(failed);++tests;}
    failure(good,{{"policy",0,{}}},"EMPTY_TYPE");
    failure(good,{{"absent",8,{}}},"MISSING");
    failure(good,{{"policy",4,{}}},"SIZE");
    failure(good,{{"policy",8,{{"offset",0,32}}}},"MEMBER");
    failure(good,{{"policy",8,{{"sid",32,32}}}},"OFFSET");
    failure(good,{{"policy",8,{{"sid",0,16}}}},"OFFSET");
    for(unsigned i=0;i<good.size();++i){auto cut=good;cut.resize(i);failure(cut,wanted,"LAYOUT_");}
    for(auto at:{size_t(0),size_t(2),size_t(3)}){auto v=good;v[at]^=0xff;failure(v,wanted,"HEADER");}
    for(auto at:{size_t(4),size_t(8),size_t(12),size_t(16),size_t(20)}){
        auto v=good;patch(v,at,0xffffffff);failure(v,wanted,"BOUNDS");}
    {auto v=good;patch(v,16,0);failure(v,wanted,"SECTIONS");}
    {auto v=good;patch(v,28,31<<24);failure(v,wanted,"KIND");}
    {auto v=good;patch(v,24,0xffffffff);failure(v,wanted,"STRING");}
    {auto v=good;patch(v,24+16+12+4,999);failure(v,wanted,"TYPE_ID");}
    {Fixture b;b.integer();b.record("policy",4,4,1,true);word(b.types,b.str("flag"));word(b.types,1);word(b.types,3U<<24|7);
        success(b.bytes(),{{"policy",4,{{"flag",7,3}}}});
        failure(b.bytes(),{{"policy",4,{{"flag",7,1}}}},"OFFSET");}
    for(auto row:{std::pair{3U,0U},std::pair{(2U<<16)|4U,100U},std::pair{(8U<<16)|8U,15U}}){
        auto b=integer_field(row.first,row.second);
        success(b.bytes(),{{"policy",32,{{"value",row.second+((row.first>>16)&255),row.first&255}}}});
    }
    {auto b=integer_field(128,32,false,16);success(b.bytes(),{{"policy",32,{{"value",32,128}}}});}
    {auto b=integer_field((4U<<24)|1U,0);success(b.bytes(),{{"policy",32,{{"value",0,1}}}});}
    {auto b=integer_field(16,24,true);success(b.bytes(),{{"policy",32,{{"value",24,16}}}});}
    {auto b=integer_field(32,200,true);success(b.bytes(),{{"policy",32,{{"value",200,32}}}});}
    {auto b=integer_field(32,32U<<24|200,true);success(b.bytes(),{{"policy",32,{{"value",200,32}}}});}
    {Fixture b;b.record("integer",1,4);word(b.types,2U<<16|4);
        b.record("alias",8,1);b.record("",10,2);b.record("policy",4,32,1);
        word(b.types,b.str("value"));word(b.types,3);word(b.types,100);
        success(b.bytes(),{{"policy",32,{{"value",102,4}}}});}
    {Fixture b;b.record("integer",1,4);word(b.types,2U<<16|4);
        b.record("",4,16,1);word(b.types,b.str("value"));word(b.types,1);word(b.types,100);
        b.record("policy",4,32,1);word(b.types,0);word(b.types,2);word(b.types,32);
        success(b.bytes(),{{"policy",32,{{"value",134,4}}}});}
    {Fixture b;b.record("integer",1,4);word(b.types,2U<<16|4);
        b.record("nested",4,16,1);word(b.types,b.str("value"));word(b.types,1);word(b.types,100);
        b.record("policy",4,32,1);word(b.types,b.str("child"));word(b.types,2);word(b.types,32);
        success(b.bytes(),{{"policy",32,{{"child.value",134,4}}}});}
    for(auto encoding:{0U,129U,2U<<16|31U,125U<<16|4U}){
        auto b=integer_field(encoding,0);failure(b.bytes(),{{"policy",32,{{"value",0,32}}}},"MEMBER_INT");}
    for(auto encoding:{2U<<16|4U,3U}){
        auto b=integer_field(encoding,3U<<24|7,true);
        failure(b.bytes(),{{"policy",32,{{"value",7,3}}}},"MEMBER_INT");}
    {auto b=integer_field(32,64U<<24,true);
        failure(b.bytes(),{{"policy",32,{{"value",0,64}}}},"MEMBER_BITS");}
    {auto b=integer_field(2U<<16|4U,123,false,4,16);
        failure(b.bytes(),{{"policy",16,{{"value",125,4}}}},"MEMBER_BOUNDS");}
    {auto b=integer_field(2U<<16|4U,0xfffffffeU,false,4,0xffffffffU);bool failed=false;
        try{describe_kernel_layout(b.bytes(),{{"policy",{"value"}}});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("MEMBER_OFFSET")!=std::string::npos;}
        assert(failed);++tests;}
    {Fixture a;a.integer();a.record("",5,4,1);word(a.types,a.str("sid"));word(a.types,1);word(a.types,0);
        a.record("policy",4,8,1);word(a.types,0);word(a.types,2);word(a.types,32);
        success(a.bytes(),{{"policy",8,{{"sid",32,32}}}});}
    {Fixture d;d.integer();d.structure();d.record("unused",4,8);d.record("unused",4,16);
        success(d.bytes(),wanted);d.record("policy",4,16);failure(d.bytes(),wanted,"SIZE");}
    {Fixture c;c.record("loop",8,1);c.record("policy",4,8,1);word(c.types,c.str("sid"));word(c.types,1);word(c.types,0);
        failure(c.bytes(),{{"policy",8,{{"sid",0,32}}}},"TYPE_CYCLE");}
    {Fixture a;a.integer();a.structure();a.record("",10,0);a.record("",2,3);
        a.record("",13,0,2);word(a.types,0);word(a.types,4);word(a.types,0);word(a.types,0);
        a.record("entry",12,5);auto data=a.bytes();
        verify_kernel_layout(data,wanted,{{"entry","fv(*v;v;)"}});++tests;
        auto functions=describe_kernel_layout(data,{}, {"entry"});
        assert(functions.types.empty() && functions.functions.size()==1 &&
            functions.functions[0].name=="entry" && functions.functions[0].signature=="fv(*v;v;)");++tests;
        bool failed=false;try{verify_kernel_layout(data,wanted,{{"entry","fi4:32(*v;v;)"}});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("ABI_MISMATCH")!=std::string::npos;}
        assert(failed);++tests;
        failed=false;try{verify_kernel_layout(data,wanted,{{"missing","fv()"}});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("ABI_MISSING")!=std::string::npos;}
        assert(failed);++tests;
        a.record("",13,1);a.record("entry",12,7);failed=false;
        try{verify_kernel_layout(a.bytes(),wanted,{{"entry","fv(*v;v;)"}});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("ABI_MISMATCH")!=std::string::npos;}
        assert(failed);++tests;
    }
    {
        Fixture d;d.integer();d.record("policy",4,24,2);
        word(d.types,d.str("sid"));word(d.types,1);word(d.types,128);
        word(d.types,d.str("flags"));word(d.types,1);word(d.types,32);
        auto actual=resolve_kernel_layout(d.bytes(),wanted,{{"policy","sid"}}, {"policy"});
        assert(actual.size()==1 && actual[0].size==24 && actual[0].fields[0].bit_offset==128);++tests;
        failure(d.bytes(),wanted,"SIZE");
        bool failed=false;try{resolve_kernel_layout(d.bytes(),wanted,{}, {"policy"});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("OFFSET")!=std::string::npos;}
        assert(failed);++tests;
        failed=false;try{resolve_kernel_layout(d.bytes(),wanted,{{"policy","missing"}}, {"policy"});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("RELOCATION_CONTRACT")!=std::string::npos;}
        assert(failed);++tests;
        failed=false;try{resolve_kernel_layout(d.bytes(),wanted,{{"policy","sid"}}, {"absent"});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("RESIZE_CONTRACT")!=std::string::npos;}
        assert(failed);++tests;
        auto wrong=wanted;wrong[0].fields[0].bit_size=64;
        failed=false;try{resolve_kernel_layout(d.bytes(),wrong,{{"policy","sid"}}, {"policy"});}
        catch(const std::runtime_error& e){failed=std::string(e.what()).find("RELOCATION_WIDTH")!=std::string::npos;}
        assert(failed);++tests;
    }
    {Fixture a;a.integer();
        a.record("",4,4,1);word(a.types,a.str("sid"));word(a.types,1);word(a.types,0);
        a.record("",5,4,1);word(a.types,a.str("sid"));word(a.types,1);word(a.types,0);
        a.record("policy",4,8,2);word(a.types,0);word(a.types,2);word(a.types,0);
        word(a.types,0);word(a.types,3);word(a.types,32);
        failure(a.bytes(),{{"policy",8,{{"sid",0,32}}}},"MEMBER_AMBIGUOUS");}
    {Fixture n;n.integer();
        n.record("seccomp",4,16,1);word(n.types,n.str("mode"));word(n.types,1);word(n.types,64);
        n.record("task_struct",4,64,1);word(n.types,n.str("seccomp"));word(n.types,2);word(n.types,128);
        success(n.bytes(),{{"task_struct",64,{{"seccomp.mode",192,32}}}});}
    {Fixture a;a.integer();
        a.record("",4,16,1);word(a.types,a.str("sid"));word(a.types,1);word(a.types,0);
        a.record("policy",4,8,1);word(a.types,0);word(a.types,2);word(a.types,0);
        failure(a.bytes(),{{"policy",8,{{"sid",0,32}}}},"MEMBER_BOUNDS");}
    {auto f=credential_fixture();
        auto layout=describe_task_credential_layout(f.bytes(),{"cred","seccomp.mode"},{"suid","sgid","euid"});
        assert(layout.types.size()==2 && layout.types[0].size==80 && layout.types[1].size==32);
        assert(layout.types[0].fields[0].bit_offset==128 && layout.types[0].fields[0].bit_size==64);
        assert(layout.types[0].fields[1].name=="seccomp.mode" && layout.types[0].fields[1].bit_offset==448);
        assert(layout.types[1].fields[0].bit_offset==64 && layout.types[1].fields[2].bit_offset==160);++tests;
        std::vector<KernelFunctionAbi> abis{{"sentinel","replace"}};
        auto linked=describe_task_credential_layout(f.bytes(),{"cred","seccomp.mode"},{"suid","sgid","euid"},abis);
        assert(linked.types[0].size==80 && linked.types[1].size==32 && abis.size()==5);
        assert(abis[0].name=="task_struct.cred" && abis[0].signature=="*scred");
        assert(abis[1].name=="task_struct.seccomp.mode" && abis[1].signature=="i4:32");
        assert(abis[2].name=="cred.suid" && abis[2].signature=="i4:32");
        assert(abis[3].name=="cred.sgid" && abis[4].name=="cred.euid");++tests;
        linked=describe_task_credential_layout(f.bytes(),{},{},abis);
        assert(linked.types[0].size==80 && linked.types[1].size==32 && abis.empty());++tests;
        const auto signature=describe_kernel_fields(f.bytes(),{{"task_struct",{"seccomp.mode"}}});
        assert(signature.size()==1 && signature[0].signature=="i4:32");++tests;
        f.record("task_struct",4,80,2);
        word(f.types,f.str("cred"));word(f.types,6);word(f.types,128);
        word(f.types,f.str("seccomp"));word(f.types,7);word(f.types,384);
        layout=describe_task_credential_layout(f.bytes(),{"cred","seccomp.mode"},{"suid"});
        assert(layout.types[1].size==32 && layout.types[1].fields[0].bit_offset==64);++tests;
        f.record("task_struct",4,0);
        layout=describe_task_credential_layout(f.bytes(),{"cred"},{"suid"});
        assert(layout.types[0].size==80);++tests;
    }
    {auto f=credential_fixture();
        f.record("cred",4,32,3);
        for(auto member:{std::pair{"suid",0U},std::pair{"sgid",32U},std::pair{"euid",64U}}){
            word(f.types,f.str(member.first));word(f.types,1);word(f.types,member.second);}
        f.record("",2,9);f.record("task_struct",4,80,1);
        word(f.types,f.str("cred"));word(f.types,10);word(f.types,128);
        credential_failure(f,"AMBIGUOUS:cred");}
    {auto f=credential_fixture();f.record("cred",4,32,3);
        for(auto member:{std::pair{"suid",64U},std::pair{"sgid",96U},std::pair{"euid",160U}}){
            word(f.types,f.str(member.first));word(f.types,1);word(f.types,member.second);}
        f.record("",2,9);f.record("task_struct",4,80,1);
        word(f.types,f.str("cred"));word(f.types,10);word(f.types,128);
        const auto layout=describe_task_credential_layout(f.bytes(),{"cred"},{"suid","sgid","euid"});
        assert(layout.types[1].size==32 && layout.types[1].fields[2].bit_offset==160);++tests;
        std::vector<KernelFunctionAbi> abis;
        const auto linked=describe_task_credential_layout(f.bytes(),{"cred"},{"suid","sgid","euid"},abis);
        assert(linked.types[1].size==32 && abis.size()==4 && abis[1].signature=="i4:32");++tests;}
    {auto f=credential_fixture();f.record("signed32",1,4);word(f.types,1U<<24|32);
        f.record("cred",4,32,3);
        for(auto member:{std::pair{"suid",64U},std::pair{"sgid",96U},std::pair{"euid",160U}}){
            word(f.types,f.str(member.first));word(f.types,member.first==std::string("suid")?9:1);word(f.types,member.second);}
        f.record("",2,10);f.record("task_struct",4,80,1);
        word(f.types,f.str("cred"));word(f.types,11);word(f.types,128);
        const auto layout=describe_task_credential_layout(f.bytes(),{"cred"},{"suid","sgid","euid"});
        assert(layout.types[1].fields[0].bit_size==32);++tests;
        credential_abi_failure(f,"ABI_AMBIGUOUS:cred.suid");}
    {auto f=credential_fixture();f.record("task_struct",4,88,1);
        word(f.types,f.str("cred"));word(f.types,6);word(f.types,128);
        credential_failure(f,"AMBIGUOUS:task_struct");}
    {auto f=credential_fixture();f.record("task_struct",4,80,1);
        word(f.types,f.str("cred"));word(f.types,3);word(f.types,128);
        credential_failure(f,"CRED_POINTER");credential_abi_failure(f,"CRED_POINTER");}
    {auto f=credential_fixture();f.record("other",4,32);f.record("",2,9);
        f.record("task_struct",4,80,1);word(f.types,f.str("cred"));word(f.types,10);word(f.types,128);
        credential_failure(f,"CRED_POINTER");}
    {auto f=credential_fixture();f.record("",2,0);
        f.record("task_struct",4,80,1);word(f.types,f.str("cred"));word(f.types,9);word(f.types,128);
        credential_failure(f,"CRED_POINTER");}
    {auto f=credential_fixture();f.record("task_struct",4,80,1);
        word(f.types,f.str("cred"));word(f.types,6);word(f.types,132);
        credential_failure(f,"CRED_POINTER");}
    {auto f=credential_fixture();f.record("cred",4,32);f.record("",2,9);
        f.record("task_struct",4,80,1);word(f.types,f.str("cred"));word(f.types,10);word(f.types,128);
        credential_failure(f,"MEMBER:cred.suid");}
    {Fixture f;f.integer();f.record("task_struct",4,0);credential_failure(f,"EMPTY_TYPE:task_struct");}
    {Fixture f;f.integer();credential_failure(f,"MISSING:task_struct");}
    {auto f=credential_fixture();f.record("",8,10);f.record("",8,9);f.record("",2,9);
        f.record("task_struct",4,80,1);word(f.types,f.str("cred"));word(f.types,11);word(f.types,128);
        credential_failure(f,"TYPE_CYCLE");}
    {Fixture f;f.integer();f.record("task_struct",4,8,1);
        word(f.types,f.str("seccomp"));word(f.types,1);word(f.types,0);
        failure(f.bytes(),{{"task_struct",8,{{"seccomp.mode",0,32}}}},"MEMBER_TYPE");}
    {Fixture f;f.integer();f.record("seccomp",4,8,1);
        word(f.types,f.str("mode"));word(f.types,1);word(f.types,0);
        f.record("embedded",4,8);f.record("task_struct",4,16,1);
        word(f.types,f.str("seccomp"));word(f.types,3);word(f.types,0);
        failure(f.bytes(),{{"task_struct",16,{{"seccomp.mode",0,32}}}},"MEMBER:task_struct.seccomp.mode");
        success(f.bytes(),{{"task_struct",16,{{"seccomp",0,64}}}});}
    {Fixture f;f.integer();f.structure();
        failure(f.bytes(),{{"policy",8,{{".sid",0,32}}}},"MEMBER_PATH");
        failure(f.bytes(),{{"policy",8,{{"sid.",0,32}}}},"MEMBER_PATH");}
    printf("PASS %u BTF layout cases (offsets, bitfields, anonymous fields, duplicates, truncation and cycles)\n",tests);
}
