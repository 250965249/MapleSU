// SPDX-License-Identifier: GPL-3.0-only
#include "../../module-policy/src/boot_sdk_layout.h"
#include "../../runtime/ultra/policy/kernel_layout.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
using namespace maplesu::module_policy;
namespace {
#ifdef MAPLESU_TEST_FACT_CONSUMER
using Facts = BootSdkLayoutFacts;
#else
struct Facts {
    KernelLayoutDescription layout, stack, environment;
    std::vector<KernelFunctionAbi> field_abis;
    std::vector<std::pair<std::string, std::string>> function_errors;
};
#endif
Facts active;
unsigned parser_calls = 0, checks = 0;
const char* range_abi = "f*v(i8:64;i8:64;i8:64;i8:64;i4:32;s:8{0=i8:64;};i8:64;i4:16777248;*v;)";
[[maybe_unused]] const char* segmented_abi = "f*v(i8:64;i8:64;i4:32;i4:32;i4:32;i4:32;i8:64;i8:64;i4:32;s:8{0=i8:64;};i8:64;i4:16777248;*v;)";
Facts fixture(unsigned usage = 4) {
    Facts f;
    f.layout.types = {{"task_struct",4096,{{"cred",1600,64}}},
        {"cred",128,{{"suid",usage*8,32},{"sgid",usage*8+32,32},{"euid",usage*8+64,32},
                     {"securebits",usage*8+192,32},{"usage",0,usage*8}}},
        {"kprobe",128,{{"addr",0,64},{"symbol_name",64,64},{"pre_handler",128,64}}},
        {"pt_regs",288,{{"regs",0,31*64},{"pc",32*64,64}}}};
    f.field_abis = {{"task_struct.cred","*scred"},{"cred.suid","s:4{0=i4:32;}"},
        {"cred.sgid","s:4{0=i4:32;}"},{"cred.euid","s:4{0=i4:32;}"},{"cred.securebits","i4:32"},
        {"cred.usage",usage==8?"s:8{0=i8:16777280;}":"s:4{0=i4:16777248;}"}};
    for (const char* name : {"copy_from_kernel_nofault","copy_to_kernel_nofault","copy_from_user_nofault","copy_to_user_nofault"})
        f.layout.functions.push_back({name,"fi8:16777280(*v;*v;i8:64;)"});
    for (const char* name : {"set_memory_ro","set_memory_rw","set_memory_x","set_memory_nx"})
        f.layout.functions.push_back({name,"fi4:16777248(i8:64;i4:16777248;)"});
    f.layout.functions.insert(f.layout.functions.end(),{{"vfree","fv(*v;)"},{"get_random_bytes","fv(*v;i8:64;)"},
        {"prepare_creds","f*scred()"},{"commit_creds","fi4:16777248(*scred;)"},
        {"get_task_cred","f*scred(*stask_struct;)"},{"__put_cred","fv(*scred;)"},
        {"register_kprobe","fi4:16777248(*skprobe;)"},{"unregister_kprobe","fv(*skprobe;)"},
        {"__arm64_sys_execve","fi8:16777280(*spt_regs;)"},{"vmalloc","f*v(i8:64;)"},
        {"__vmalloc_node_range",range_abi},{"___vmalloc_node_range",range_abi},{"vmalloc_user","f*v(i8:64;)"},
        {"module_memfree","fv(*v;)"},{"execmem_free","fv(*v;)"}});
    f.stack.types = {{"pt_regs",288,{{"sp",31*64,64}}}};
    f.environment.types = {{"task_struct",4096,{{"seccomp.mode",3000*8,32}}},{"filename",8,{{"name",0,64}}}};
    f.environment.functions = {
        {"do_execveat_common","fi4:16777248(i4:16777248;*sfilename;suser_arg_ptr:16{0=i1:67108872;64=u:8{0=**i1:8;0=*i4:32;};};suser_arg_ptr:16{0=i1:67108872;64=u:8{0=**i1:8;0=*i4:32;};};i4:16777248;)"},
        {"avc_denied","fi4:16777248(i4:32;i4:32;i2:16;i4:32;i1:8;i1:8;i4:32;*sav_decision;)"},
        {"filldir64","fi1:67108872(*sdir_context;*i1:8;i4:16777248;i8:16777280;i8:64;i4:32;)"},
        {"slow_avc_audit","fi4:16777248(i4:32;i4:32;i2:16;i4:32;i4:32;i4:32;i4:16777248;*scommon_audit_data;)"}};
    return f;
}
[[maybe_unused]] void erase_function(Facts& f, const char* name) {
    for (auto* functions : {&f.layout.functions,&f.environment.functions})
        functions->erase(std::remove_if(functions->begin(),functions->end(),[&](const auto& a){return a.name==name;}),functions->end());
}
[[maybe_unused]] void set_function(Facts& f, const char* name, const char* signature) {
    for (auto* functions : {&f.layout.functions,&f.environment.functions})
        for(auto& a:*functions) if(a.name==name){a.signature=signature;return;}
    f.layout.functions.push_back({name,signature});
}
std::string function(const Facts& f, const std::string& name) {
    for(const auto& e:f.function_errors) if(e.first==name) throw std::runtime_error(e.second);
    for(const auto* functions:{&f.layout.functions,&f.environment.functions})
        for(const auto& a:*functions) if(a.name==name) return a.signature;
    throw std::runtime_error("MODULE_POLICY_LAYOUT_ABI_MISSING:"+name);
}
}
// These fixtures replace only the BTF producer. The real boot resolver and
// wire validation execute unchanged, including in the pre-refactor red run.
namespace maplesu::module_policy {
KernelLayoutDescription describe_task_credential_layout(const std::vector<uint8_t>&,
    const std::vector<std::string>&,const std::vector<std::string>&,std::vector<KernelFunctionAbi>& abis) {
    ++parser_calls;abis=active.field_abis;
    return {{active.layout.types[0],active.layout.types[1]}, {}};
}
KernelLayoutDescription describe_kernel_layout(const std::vector<uint8_t>&,
    const std::vector<LayoutTypeRequest>& requested,const std::vector<std::string>& functions) {
    ++parser_calls;KernelLayoutDescription result;
    for(const auto& request:requested) {
        const auto* source=&active.layout;
        if(!request.fields.empty() && request.fields[0]=="sp")source=&active.stack;
        if(request.name=="filename" || (!request.fields.empty() && request.fields[0]=="seccomp.mode"))source=&active.environment;
        const auto found=std::find_if(source->types.begin(),source->types.end(),[&](const auto& t){return t.name==request.name;});
        if(found==source->types.end())throw std::runtime_error("MODULE_POLICY_LAYOUT_MISSING:"+request.name);
        LayoutType t{found->name,found->size,{}};
        for(const auto& name:request.fields) {
            const auto field=std::find_if(found->fields.begin(),found->fields.end(),[&](const auto& a){return a.name==name;});
            if(field==found->fields.end())throw std::runtime_error("MODULE_POLICY_LAYOUT_MEMBER:"+request.name+"."+name);
            t.fields.push_back(*field);
        }
        result.types.push_back(std::move(t));
    }
    for(const auto& name:functions)result.functions.push_back({name,function(active,name)});
    return result;
}
}
namespace {
void production_failure(Facts f,const char* expected) {
    active=std::move(f);bool failed=false;
    try{(void)resolve_boot_sdk_layout({},4096);}
    catch(const std::runtime_error& e){failed=e.what()==std::string(expected);}
    if(!failed){std::fprintf(stderr,"FAIL production accepted incomplete fact: %s\n",expected);throw std::runtime_error("red mismatch");}
    ++checks;
}
#ifdef MAPLESU_TEST_FACT_CONSUMER
msu_boot_sdk_layout consume(const Facts& f,bool inner=false,bool user=false,bool segmented=false,unsigned page=4096) {
    const auto calls=parser_calls;
    const auto result=consume_boot_sdk_layout(f,page,inner,user,segmented);
    assert(parser_calls==calls && msu_boot_sdk_layout_valid(&result,page));++checks;return result;
}
void failure(Facts f,const char* expected) {
    const auto calls=parser_calls;bool failed=false;
    try{(void)consume_boot_sdk_layout(f,4096);}
    catch(const std::runtime_error& e){failed=e.what()==std::string(expected);if(!failed)std::fprintf(stderr,"expected %s, actual %s\n",expected,e.what());}
    assert(failed && parser_calls==calls);++checks;
}
void tests() {
    for(unsigned usage:{4U,8U})for(unsigned page:{4096U,16384U,65536U}) {
        auto f=fixture(usage);const auto r=consume(f,false,false,false,page);
        assert(r.cred_suid==usage && r.cred_usage_size==usage && r.environment==1 && r.seccomp==3000);
        active=f;const auto btf=resolve_boot_sdk_layout({},page);assert(!std::memcmp(&r,&btf,sizeof(r)));++checks;
    }
    {auto f=fixture();std::reverse(f.layout.types.begin(),f.layout.types.end());std::reverse(f.field_abis.begin(),f.field_abis.end());
        for(auto& t:f.layout.types)std::reverse(t.fields.begin(),t.fields.end());
        const auto r=consume(f);assert(r.task_cred==200 && r.kp_pre==16);}
    {auto f=fixture();f.layout.types[0].name="other";failure(f,"MODULE_POLICY_LAYOUT_MISSING:task_struct");}
    {auto f=fixture();f.layout.types[1].fields[0].name="other";failure(f,"MODULE_POLICY_LAYOUT_MEMBER:cred.suid");}
    {auto f=fixture();f.field_abis[0].name="other";failure(f,"MODULE_POLICY_LAYOUT_ABI_MISSING:task_struct.cred");}
    {auto f=fixture();f.field_abis.pop_back();failure(f,"MODULE_POLICY_LAYOUT_ABI_MISSING:cred.usage");}
    {auto f=fixture();f.field_abis.push_back({"cred.suid","i4:32"});failure(f,"MODULE_POLICY_LAYOUT_ABI_AMBIGUOUS:cred.suid");}
    {auto f=fixture();f.layout.types[0].size=0;failure(f,"MODULE_POLICY_LAYOUT_EMPTY_TYPE:task_struct");}
    {auto f=fixture();f.layout.types[1].size=0;failure(f,"MODULE_POLICY_LAYOUT_EMPTY_TYPE:cred");}
    {auto f=fixture();f.layout.types[0].fields[0].bit_offset=4096*8;failure(f,"MODULE_POLICY_LAYOUT_MEMBER_BOUNDS:task_struct.cred");}
    {auto f=fixture();f.layout.types[1].fields[4].bit_offset=32;failure(f,"BOOT_SDK_LAYOUT_RANGE");}
    {auto f=fixture();f.layout.types[2].fields[0].bit_size=32;failure(f,"BOOT_SDK_LAYOUT_FIELD:addr");}
    {auto f=fixture();f.layout.types[2].fields[2].bit_offset=64;failure(f,"BOOT_SDK_LAYOUT_RANGE");}
    {auto f=fixture();f.layout.types[2].fields[2].bit_offset=128*8;failure(f,"MODULE_POLICY_LAYOUT_MEMBER_BOUNDS:kprobe.pre_handler");}
    {auto f=fixture();f.layout.types[3].size=256;failure(f,"MODULE_POLICY_LAYOUT_MEMBER_BOUNDS:pt_regs.pc");}
    {auto f=fixture();f.layout.types[1].fields[4].bit_size=16;failure(f,"BOOT_SDK_CREDENTIAL_ABI");}
    {auto f=fixture();f.field_abis[5].signature="i4:32";failure(f,"BOOT_SDK_CREDENTIAL_TYPES");}
    {auto f=fixture();erase_function(f,"prepare_creds");failure(f,"MODULE_POLICY_LAYOUT_ABI_MISSING:prepare_creds");}
    {auto f=fixture();set_function(f,"prepare_creds","fv()");failure(f,"BOOT_SDK_ABI:prepare_creds");}
    {auto f=fixture();f.function_errors.push_back({"vmalloc","MODULE_POLICY_LAYOUT_ABI_AMBIGUOUS:vmalloc"});failure(f,"MODULE_POLICY_LAYOUT_ABI_AMBIGUOUS:vmalloc");}
    {auto f=fixture();erase_function(f,"vmalloc");set_function(f,"vmalloc_noprof","f*v(i8:64;)");set_function(f,"__vmalloc_node_range_noprof",range_abi);const auto r=consume(f);assert(r.allocator_noprof==1);}
    {auto f=fixture();f.function_errors.push_back({"vmalloc_noprof","MODULE_POLICY_LAYOUT_ABI_AMBIGUOUS:vmalloc_noprof"});const auto r=consume(f);assert(!r.allocator_noprof);}
    {const auto r=consume(fixture(),true,true);assert(r.allocator_noprof==6);}
    {auto f=fixture();set_function(f,"___vmalloc_node_range","bad");const auto r=consume(f,true,true);assert(r.allocator_noprof==4);}
    {auto f=fixture();f.function_errors.push_back({"___vmalloc_node_range","MODULE_POLICY_LAYOUT_ABI_AMBIGUOUS:___vmalloc_node_range"});const auto r=consume(f,true);assert(!r.allocator_noprof);}
    {auto f=fixture();set_function(f,"vmalloc_user","bad");const auto r=consume(f,false,true);assert(!r.allocator_noprof);}
    {auto f=fixture();set_function(f,"___vmalloc_node_range",segmented_abi);const auto r=consume(f,false,false,true);assert(r.allocator_noprof==8);}
    {auto f=fixture();set_function(f,"___vmalloc_node_range",segmented_abi);f.stack.types.clear();const auto r=consume(f,false,false,true);assert(!r.allocator_noprof);}
    {auto f=fixture();f.environment.types.clear();const auto r=consume(f);assert(!r.environment && !r.seccomp);}
    {auto f=fixture();erase_function(f,"avc_denied");const auto r=consume(f);assert(!r.environment);}
    {auto f=fixture();set_function(f,"avc_denied","bad");const auto r=consume(f);assert(!r.environment);}
    {auto f=fixture();f.environment.types[0].fields[0].bit_offset=4096*8;const auto r=consume(f);assert(!r.environment);}
    {auto f=fixture();erase_function(f,"module_memfree");const auto r=consume(f);assert(r.environment && r.execmem_free==1);}
    {auto f=fixture();set_function(f,"module_memfree","bad");const auto r=consume(f);assert(!r.environment && !r.execmem_free);}
    {auto f=fixture();f.function_errors.push_back({"module_memfree","MODULE_POLICY_LAYOUT_ABI_AMBIGUOUS:module_memfree"});const auto r=consume(f);assert(!r.environment);}
}
#endif
}
int main(int argc,char** argv) {
    assert(argc<=2);
    try {
        if(argc==1 || !std::strcmp(argv[1],"owner")) {
            auto f=fixture();f.layout.types[0].name="other";
            production_failure(f,"MODULE_POLICY_LAYOUT_MISSING:task_struct");
        }
        if(argc==1 || !std::strcmp(argv[1],"abi")) {
            auto f=fixture();f.field_abis[0].name="other";
            production_failure(f,"MODULE_POLICY_LAYOUT_ABI_MISSING:task_struct.cred");
        }
#ifdef MAPLESU_TEST_FACT_CONSUMER
        tests();
#endif
        std::printf("PASS %u boot SDK fact checks; parser calls=%u\n",checks,parser_calls);
        return 0;
    } catch(const std::exception& e) {std::fprintf(stderr,"%s\n",e.what());return 1;}
}
