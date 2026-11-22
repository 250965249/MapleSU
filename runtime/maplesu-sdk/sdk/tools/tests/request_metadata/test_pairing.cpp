#include "kernel_module_kit_umbrella.h"
#include "module_base_kernel_request.h"
#include "maplesu_request_private.h"

#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#if defined(MAPLESU_LEGACY_METADATA_V2_BYTES)
static_assert(MAPLESU_LEGACY_METADATA_V2_BYTES == 54u);
#endif

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);
namespace kernel_module {
KModErr get_append_package_data_offset(uint32_t&);
KModErr get_append_package_kallsyms_kaddr(uint64_t&);
KModErr get_append_package_run_fake_proc_path_addr(uint64_t&);
KModErr get_do_execve_info(uint64_t&,char&,bool&);
KModErr get_avc_denied_info(uint64_t&,uint64_t&);
KModErr get_filldir64_addr(uint64_t&);
KModErr get_seccomp_offset(uint32_t&);
KModErr get_slow_avc_audit_addr(uint64_t&);
}

namespace {
const char* phase = "cold_base";
unsigned checks, failures, transports, queries, prepares, uid_reads, gid_reads, old_calls;
unsigned channel_calls, read_calls;
unsigned unpublished_reads;
uint64_t append_address;
std::unordered_set<uint64_t> ids;
std::string input() {
    std::string value;
    for (int c;(c=std::getchar())!='\n';) {
        if(c==EOF) std::abort();
        if(c!='\r') value.push_back(static_cast<char>(c));
    }
    return value;
}
std::string hex(const void* pointer,size_t size) {
    constexpr char alphabet[]="0123456789abcdef";
    const auto* bytes=static_cast<const uint8_t*>(pointer);
    std::string value(size*2,'0');
    for(size_t i=0;i<size;++i) {value[2*i]=alphabet[bytes[i]>>4];value[2*i+1]=alphabet[bytes[i]&15];}
    return value;
}
std::vector<uint8_t> unhex(const std::string& text) {
    if(text.size()%2) std::abort();
    std::vector<uint8_t> bytes(text.size()/2);
    for(size_t i=0;i<bytes.size();++i) {
        const char pair[]={text[2*i],text[2*i+1],0};char* end=nullptr;
        bytes[i]=static_cast<uint8_t>(std::strtoul(pair,&end,16));
        if(*end) std::abort();
    }
    return bytes;
}
void check(bool value) {++checks;if(!value) ++failures;}
template<class T> T field(const std::vector<uint8_t>& bytes,size_t at) {
    if(at+sizeof(T)>bytes.size()) std::abort();
    T value{};std::memcpy(&value,bytes.data()+at,sizeof(value));return value;
}
struct Counts {
    unsigned transport=transports,query=queries,prepare=prepares,uid=uid_reads,gid=gid_reads;
};
void result(KModErr error,const Counts& before,unsigned expected_transports,bool passed) {
    const bool cold=std::strcmp(phase,"cold_base")==0;
    check(passed && transports-before.transport==expected_transports);
    check(queries-before.query==(cold?1u:0u) && prepares-before.prepare==(cold?1u:0u));
    check(uid_reads-before.uid==(cold?1u:0u) && gid_reads-before.gid==(cold?1u:0u));
    check(old_calls==0 && metadata_test::init_count==0);
    std::printf("{\"type\":\"result\",\"phase\":\"%s\",\"error\":%lld,\"transports\":%u,"
        "\"queries\":%u,\"prepares\":%u,\"uidReads\":%u,\"gidReads\":%u,"
        "\"legacyCalls\":%u,\"assemblerInitializations\":%u,\"failures\":%u}\n",phase,
        static_cast<long long>(error),transports-before.transport,queries-before.query,prepares-before.prepare,
        uid_reads-before.uid,gid_reads-before.gid,old_calls,metadata_test::init_count.load(),failures);
    std::fflush(stdout);
}
}

// The real client calls these captured OS boundaries. No credential syscall executes.
extern "C" int64_t maplesu_prepare_kernel_request() noexcept {++prepares;return 0;}
extern "C" int __wrap_getresuid(uid_t* a,uid_t* b,uid_t* c) {++uid_reads;*a=*b=10000;*c=1234;return 0;}
extern "C" int __wrap_getresgid(gid_t* a,gid_t* b,gid_t* c) {++gid_reads;*a=*b=10000;*c=5678;return 0;}
extern "C" long __wrap_syscall(long number,...) {
    ++transports;
    va_list args;va_start(args,number);const auto* packet=va_arg(args,const uint8_t*);va_end(args);
    std::array<uint8_t,18> frame{};
    for(size_t i=0;i<frame.size();++i) frame[i]=packet[48+i]+packet[66+i];
    check(number==221 && frame[0]==52 && frame[1]==0xa2 && packet[84]==0);
    if(number!=221 || frame[0]!=52 || frame[1]!=0xa2) std::abort();
    uint64_t pointer=0;std::memcpy(&pointer,frame.data()+10,8);
    const auto& request=*reinterpret_cast<const maplesu_request_v2*>(static_cast<uintptr_t>(pointer));
    auto* response=reinterpret_cast<maplesu_response_v2*>(static_cast<uintptr_t>(request.response_user));
    check(pointer>UINT32_MAX && request.response_user>UINT32_MAX && ids.insert(request.request_id).second);
    if(request.command==MAPLESU_REQUEST_QUERY) ++queries;
    maplesu_read_v2 read{};
    if(request.command==MAPLESU_REQUEST_READ)
        std::memcpy(&read,reinterpret_cast<void*>(static_cast<uintptr_t>(request.arg1)),sizeof(read));
    if(request.command==MAPLESU_REQUEST_READ && request.arg0>=append_address+54 && request.arg0<append_address+58)
        ++unpublished_reads;
    std::printf("{\"type\":\"transport\",\"phase\":\"%s\",\"packet\":\"%s\",\"frame\":\"%s\","
        "\"requestPointer\":%llu,\"responsePointer\":%llu,\"request\":\"%s\",\"response\":\"%s\","
        "\"readArgs\":\"%s\",\"destination\":\"%s\"}\n",phase,hex(packet,85).c_str(),hex(frame.data(),18).c_str(),
        static_cast<unsigned long long>(pointer),static_cast<unsigned long long>(request.response_user),
        hex(&request,48).c_str(),hex(response,48).c_str(),request.command==3?hex(&read,16).c_str():"",
        request.command==3?hex(reinterpret_cast<void*>(static_cast<uintptr_t>(read.destination_user)),read.length).c_str():"");
    std::fflush(stdout);
    const auto answer=input();const auto split=answer.find(' ');
    if(split==std::string::npos) std::abort();
    const auto reply=unhex(answer.substr(0,split)),data=unhex(answer.substr(split+1));
    if(reply.size()!=48) std::abort();
    std::memcpy(response,reply.data(),48);
    if(request.command==MAPLESU_REQUEST_READ) {
        if(data.size()!=read.length) std::abort();
        std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(read.destination_user)),data.data(),data.size());
    }
    return -1;
}

// Linker wrapping counts external consumer calls while retaining the actual client body.
extern "C" KModErr real_channel(maplesu_response_v2&,bool&)
    __asm__("__real__ZN13kernel_module26maplesu_request_v2_channelER19maplesu_response_v2Rb");
extern "C" KModErr wrapped_channel(maplesu_response_v2&,bool&)
    __asm__("__wrap__ZN13kernel_module26maplesu_request_v2_channelER19maplesu_response_v2Rb");
extern "C" KModErr wrapped_channel(maplesu_response_v2& response,bool& supported) {
    ++channel_calls;return real_channel(response,supported);
}
extern "C" KModErr real_read(uint64_t,void*,uint32_t)
    __asm__("__real__ZN13kernel_module23maplesu_request_v2_readEmPvj");
extern "C" KModErr wrapped_read(uint64_t,void*,uint32_t)
    __asm__("__wrap__ZN13kernel_module23maplesu_request_v2_readEmPvj");
extern "C" KModErr wrapped_read(uint64_t source,void* destination,uint32_t size) {
    ++read_calls;return real_read(source,destination,size);
}

namespace kernel_module {
void arm64_module_asm_func_start(Assembler*) {++old_calls;}
void maplesu_legacy_asm_func_start(Assembler*) {++old_calls;}
void maplesu_legacy_asm_func_end(Assembler*) {++old_calls;}
void maplesu_legacy_asm_func_end(Assembler*,GpX) {++old_calls;}
void arm64_module_asm_func_end(Assembler*) {++old_calls;}
void arm64_module_asm_func_end(Assembler*,GpX) {++old_calls;}
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&,uint64_t&) {++old_calls;return KModErr::ERR_MODULE_ASM;}
KModErr execute_kernel_asm_func_with_buf(const uint8_t*,uint32_t,uint64_t&) {++old_calls;return KModErr::ERR_MODULE_ASM;}
KModErr kallsyms_lookup_name(const char*,SymbolHit&,SymbolMatchMode) {++old_calls;return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;}
KModErr kallsyms_lookup_name(const char*,uint64_t&) {++old_calls;return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;}
bool is_kernel_version_less(const char*) {++old_calls;return false;}
KModErr icache_invalidate_all_cpus() {++old_calls;return KModErr::ERR_MODULE_ASM;}
}

int main() {
    using namespace kernel_module;
    const auto key_bytes=unhex(input());const std::string key(key_bytes.begin(),key_bytes.end());
    check(key.size()==48);__set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key.c_str());
    uint64_t base=0,append=0,source=0,published=0;std::istringstream(input())>>base>>append>>source>>published;
    append_address=append;
    const auto bytes=unhex(input()),ordinary=unhex(input());check(bytes.size()==54 && ordinary.size()==600 && published==54);
    uint64_t value=0,extra=0;uint32_t offset=0;char flag=0;bool present=false;
    Counts before;
    auto error=get_kernel_base_vaddr(value);result(error,before,2,error==KModErr::OK && value==base);
#define RUN_PHASE(name,transports,call,expect) do {phase=name;before=Counts{};error=(call);result(error,before,transports,error==KModErr::OK && (expect));} while(0)
    RUN_PHASE("warm_base",0,get_kernel_base_vaddr(value),value==base);
    RUN_PHASE("append_offset",1,get_append_package_data_offset(offset),offset==field<uint32_t>(bytes,0));
    RUN_PHASE("kallsyms",1,get_append_package_kallsyms_kaddr(value),value==base+field<uint32_t>(bytes,4));
    RUN_PHASE("fake_proc",0,get_append_package_run_fake_proc_path_addr(value),value==append+8);
    RUN_PHASE("execve",1,get_do_execve_info(value,flag,present),value==base+field<uint32_t>(bytes,36) && flag==field<char>(bytes,40) && present==bool(field<uint8_t>(bytes,41)));
    RUN_PHASE("avc",1,get_avc_denied_info(value,extra),value==base+field<uint32_t>(bytes,42) && extra==value-4+int64_t(field<int16_t>(bytes,46))*4);
    RUN_PHASE("filldir",1,get_filldir64_addr(value),value==base+field<uint32_t>(bytes,48));
    RUN_PHASE("seccomp",1,get_seccomp_offset(offset),offset==uint32_t(int32_t(field<int16_t>(bytes,52))));
    phase="slow_avc";before=Counts{};value=UINT64_C(0xa1b2c3d4e5f60718);
    const auto read_calls_before_missing=read_calls;
    error=get_slow_avc_audit_addr(value);
    std::printf("{\"type\":\"append_contract\",\"publishedBytes\":%llu,\"requiredBytes\":58,"
        "\"error\":%lld,\"outputUnchanged\":%s,\"unpublishedReads\":%u,\"fieldReadCalls\":%u,"
        "\"missingFieldImplemented\":false}\n",static_cast<unsigned long long>(published),static_cast<long long>(error),
        value==UINT64_C(0xa1b2c3d4e5f60718)?"true":"false",unpublished_reads,read_calls-read_calls_before_missing);
    result(error,before,0,error==KModErr::ERR_MODULE_INTERNAL_APPEND && value==UINT64_C(0xa1b2c3d4e5f60718) &&
        read_calls==read_calls_before_missing && unpublished_reads==0);
    std::vector<uint8_t> full(bytes.size(),0xcc);
    RUN_PHASE("append_full",1,read_kernel_mem(append,full.data(),full.size()),full==bytes);
    std::vector<uint8_t> output(ordinary.size(),0xcc);
    RUN_PHASE("ordinary_600",3,read_kernel_mem(source,output.data(),output.size()),output==ordinary);
    phase="kernel_fault";before=Counts{};full.assign(bytes.size(),0xcc);
    error=read_kernel_mem(append,full.data(),full.size());
    result(error,before,1,error==KModErr::ERR_MODULE_NOT_KADDR && full==std::vector<uint8_t>(bytes.size(),0xcc));
    phase="partial_data";before=Counts{};full.assign(bytes.size(),0xcc);
    error=read_kernel_mem(append,full.data(),full.size());
    const auto expected=[&]{auto x=std::vector<uint8_t>(bytes.size(),0xcc);std::memcpy(x.data(),bytes.data(),17);return x;}();
    result(error,before,1,error==KModErr::ERR_MODULE_NOT_KADDR && full==expected);
    RUN_PHASE("warm_end",0,get_kernel_base_vaddr(value),value==base);
#undef RUN_PHASE
    check(queries==1 && prepares==1 && uid_reads==1 && gid_reads==1 && transports==14 && channel_calls>0 && read_calls>0 && unpublished_reads==0);
    std::printf("{\"type\":\"summary\",\"checks\":%u,\"failures\":%u,\"transports\":%u,\"queries\":%u,\"prepares\":%u,"
        "\"uidReads\":%u,\"gidReads\":%u,\"legacyCalls\":%u,\"assemblerInitializations\":%u,"
        "\"externalChannelCalls\":%u,\"externalReadCalls\":%u,\"uniqueRequestIds\":%zu,\"unpublishedReads\":%u}\n",
        checks,failures,transports,queries,prepares,uid_reads,gid_reads,old_calls,metadata_test::init_count.load(),channel_calls,read_calls,ids.size(),unpublished_reads);
    return failures?1:0;
}
