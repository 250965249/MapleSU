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
const char* phase="cold_base";
unsigned checks,failures,transports,queries,prepares,uid_reads,gid_reads,old_calls;
std::unordered_set<uint64_t> ids;
void check(bool value) { ++checks; if(!value) { ++failures; std::fprintf(stderr,"failed: %s check %u\n",phase,checks); } }
std::string input() {
    std::string value;
    for(int c;(c=std::getchar())!='\n';) { if(c==EOF) std::abort(); if(c!='\r') value.push_back(char(c)); }
    return value;
}
std::string hex(const void* data,size_t size) {
    constexpr char alphabet[]="0123456789abcdef";
    const auto* p=static_cast<const uint8_t*>(data);std::string result(size*2,'0');
    for(size_t i=0;i<size;++i) { result[2*i]=alphabet[p[i]>>4];result[2*i+1]=alphabet[p[i]&15]; }
    return result;
}
std::vector<uint8_t> unhex(const std::string& text) {
    if(text.size()%2) std::abort();std::vector<uint8_t> result(text.size()/2);
    for(size_t i=0;i<result.size();++i) { const char pair[]={text[2*i],text[2*i+1],0};result[i]=std::strtoul(pair,nullptr,16); }
    return result;
}
template<class T> T field(const std::vector<uint8_t>& bytes,size_t at) {
    if(at+sizeof(T)>bytes.size()) std::abort();T result{};std::memcpy(&result,bytes.data()+at,sizeof result);return result;
}
void summary() {
    check(old_calls==0 && metadata_test::init_count==0);
    check(queries==1 && prepares==1 && uid_reads==1 && gid_reads==1 && ids.size()==transports);
    std::printf("{\"type\":\"summary\",\"checks\":%u,\"failures\":%u,\"transports\":%u,\"queries\":%u,"
        "\"prepares\":%u,\"uidReads\":%u,\"gidReads\":%u,\"legacyCalls\":%u,\"assemblerInitializations\":%u}\n",
        checks,failures,transports,queries,prepares,uid_reads,gid_reads,old_calls,metadata_test::init_count.load());
}
void result(KModErr error,unsigned before,unsigned expected,bool accepted) {
    check(accepted && transports-before==expected);
    check(old_calls==0 && metadata_test::init_count==0);
    std::printf("{\"type\":\"result\",\"phase\":\"%s\",\"error\":%lld,\"transports\":%u,\"failures\":%u}\n",
        phase,static_cast<long long>(error),transports-before,failures);
}
}
extern "C" int64_t maplesu_prepare_kernel_request() noexcept { ++prepares;return 0; }
extern "C" int __wrap_getresuid(uid_t* a,uid_t* b,uid_t* c) { ++uid_reads;*a=*b=10000;*c=1234;return 0; }
extern "C" int __wrap_getresgid(gid_t* a,gid_t* b,gid_t* c) { ++gid_reads;*a=*b=10000;*c=5678;return 0; }
extern "C" long __wrap_syscall(long number,...) {
    ++transports;va_list args;va_start(args,number);const auto* packet=va_arg(args,const uint8_t*);va_end(args);
    std::array<uint8_t,18> frame{};for(size_t i=0;i<frame.size();++i) frame[i]=packet[48+i]+packet[66+i];
    check(number==221 && frame[0]==52 && frame[1]==0xa2 && packet[84]==0);
    uint64_t pointer=0;std::memcpy(&pointer,frame.data()+10,8);
    const auto& request=*reinterpret_cast<const maplesu_request_v2*>(uintptr_t(pointer));
    auto* response=reinterpret_cast<maplesu_response_v2*>(uintptr_t(request.response_user));
    check(pointer>UINT32_MAX && request.response_user>UINT32_MAX && ids.insert(request.request_id).second);
    if(request.command==MAPLESU_REQUEST_QUERY) ++queries;
    maplesu_read_v2 read{};if(request.command==MAPLESU_REQUEST_READ)
        std::memcpy(&read,reinterpret_cast<void*>(uintptr_t(request.arg1)),sizeof read);
    std::printf("{\"type\":\"transport\",\"phase\":\"%s\",\"packetPointer\":%llu,\"packet\":\"%s\","
        "\"requestPointer\":%llu,\"request\":\"%s\",\"response\":\"%s\",\"readArgs\":\"%s\",\"destination\":\"%s\"}\n",
        phase,(unsigned long long)uintptr_t(packet),hex(packet,85).c_str(),(unsigned long long)pointer,
        hex(&request,sizeof request).c_str(),hex(response,sizeof *response).c_str(),
        request.command==3?hex(&read,sizeof read).c_str():"",
        request.command==3?hex(reinterpret_cast<void*>(uintptr_t(read.destination_user)),read.length).c_str():"");
    std::fflush(stdout);const auto answer=input();const auto split=answer.find(' ');if(split==std::string::npos) std::abort();
    const auto reply=unhex(answer.substr(0,split)),data=unhex(answer.substr(split+1));if(reply.size()!=48) std::abort();
    std::memcpy(response,reply.data(),48);
    if(request.command==3) { if(data.size()!=read.length) std::abort();std::memcpy(reinterpret_cast<void*>(uintptr_t(read.destination_user)),data.data(),data.size()); }
    return -1;
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
int main(int argc,char** argv) {
    using namespace kernel_module;
    const auto key_bytes=unhex(input());const std::string key(key_bytes.begin(),key_bytes.end());
    check(key.size()==48);__set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key.c_str());
    uint64_t base=0,append=0,source=0,capabilities=0,published=0;
    std::istringstream(input())>>base>>append>>source>>capabilities>>published;
    const auto bytes=unhex(input()),ordinary=unhex(input());check(bytes.size()==published && ordinary.size()==600);
    uint64_t value=UINT64_C(0xa1b2c3d4e5f60718),extra=0;uint32_t offset=0;char flag=0;bool present=false;
    if(argc>1) {
        phase=argv[1];const auto error=get_kernel_base_vaddr(value);
        result(error,0,2,error==KModErr::ERR_MODULE_INTERNAL_APPEND && value==UINT64_C(0xa1b2c3d4e5f60718));
        summary();return failures?1:0;
    }
    unsigned before=transports;auto error=get_kernel_base_vaddr(value);
    result(error,before,2,error==KModErr::OK && value==base);
#define RUN(name,count,call,expect) do {phase=name;before=transports;error=(call);result(error,before,count,error==KModErr::OK && (expect));} while(0)
    RUN("warm_base",0,get_kernel_base_vaddr(value),value==base);
    RUN("append_offset",1,get_append_package_data_offset(offset),offset==field<uint32_t>(bytes,0));
    RUN("kallsyms",1,get_append_package_kallsyms_kaddr(value),value==base+field<uint32_t>(bytes,4));
    RUN("fake_proc",0,get_append_package_run_fake_proc_path_addr(value),value==append+8);
    RUN("execve",1,get_do_execve_info(value,flag,present),value==base+field<uint32_t>(bytes,36) && flag==field<char>(bytes,40) && present==bool(bytes[41]));
    RUN("avc",1,get_avc_denied_info(value,extra),value==base+field<uint32_t>(bytes,42) && extra==value-4+int64_t(field<int16_t>(bytes,46))*4);
    RUN("filldir",1,get_filldir64_addr(value),value==base+field<uint32_t>(bytes,48));
    RUN("seccomp",1,get_seccomp_offset(offset),offset==uint32_t(int32_t(field<int16_t>(bytes,52))));
    phase="slow_avc";before=transports;value=UINT64_C(0xa1b2c3d4e5f60718);error=get_slow_avc_audit_addr(value);
    const bool audit=capabilities&MAPLESU_CAP_APPEND_AUDIT;
    result(error,before,audit?1:0,audit?(error==KModErr::OK && value==base+field<uint32_t>(bytes,54)):
        (error==KModErr::ERR_MODULE_INTERNAL_APPEND && value==UINT64_C(0xa1b2c3d4e5f60718)));
    std::vector<uint8_t> full(bytes.size(),0xcc);
    RUN("append_full",1,read_kernel_mem(append,full.data(),full.size()),full==bytes);
    std::vector<uint8_t> output(ordinary.size(),0xcc);
    RUN("ordinary_600",3,read_kernel_mem(source,output.data(),output.size()),output==ordinary);
    for(const uint64_t test: {UINT64_C(0),UINT64_C(1),UINT64_MAX,UINT64_C(0x8000000000000001),uint64_t(-19999)}) {
        phase="echo64";before=transports;maplesu_response_v2 response{};
        error=maplesu_request_v2_exchange(MAPLESU_REQUEST_ECHO64,test,0,response);
        result(error,before,1,error==KModErr::OK && response.status==0 && response.result==test);
    }
    for(const char* fault: {"request_version","request_length_short","request_length_long","response_version","response_length"}) {
        phase=fault;before=transports;maplesu_response_v2 response{};
        error=maplesu_request_v2_exchange(MAPLESU_REQUEST_ECHO64,UINT64_MAX,0,response);
        const bool bad_response=std::strncmp(fault,"response_",9)==0;
        result(error,before,1,bad_response?error==KModErr::ERR_MODULE_TEST_CHANNEL:
            (error==KModErr::OK && response.status==MAPLESU_REQUEST_STATUS_INVALID && response.result==0));
    }
    phase="unsupported";before=transports;maplesu_response_v2 response{};
    error=maplesu_request_v2_exchange(0xfeed,0,0,response);
    result(error,before,1,error==KModErr::OK && response.status==MAPLESU_REQUEST_STATUS_UNSUPPORTED);
    for(const char* fault: {"kernel_fault","partial_data"}) {
        phase=fault;before=transports;full.assign(bytes.size(),0xcc);
        error=read_kernel_mem(append,full.data(),full.size());auto expected=std::vector<uint8_t>(bytes.size(),0xcc);
        if(!std::strcmp(fault,"partial_data")) std::memcpy(expected.data(),bytes.data(),17);
        result(error,before,1,error==KModErr::ERR_MODULE_NOT_KADDR && full==expected);
    }
    RUN("warm_end",0,get_kernel_base_vaddr(value),value==base);
#undef RUN
    summary();return failures?1:0;
}
