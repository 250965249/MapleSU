#include "module_base_kernel_request.h"
#include "maplesu_request_private.h"

#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);

namespace {
const char* phase = "query";
int prepares, uid_reads, gid_reads, transports, failures;
std::unordered_set<uint64_t> ids;
std::array<unsigned char, 48> expected_metadata{};
std::string hex(const void* pointer, size_t count) {
    const auto* bytes = static_cast<const unsigned char*>(pointer);
    std::string out(count * 2, '0');
    constexpr char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < count; ++i) { out[2*i] = digits[bytes[i] >> 4]; out[2*i+1] = digits[bytes[i] & 15]; }
    return out;
}
std::vector<unsigned char> unhex(const std::string& value) {
    if (value.size() % 2) std::abort();
    std::vector<unsigned char> out(value.size()/2);
    for (size_t i=0; i<out.size(); ++i) {
        char pair[] = {value[2*i], value[2*i+1], 0}; char* end = nullptr;
        out[i] = static_cast<unsigned char>(std::strtoul(pair, &end, 16));
        if (*end) std::abort();
    }
    return out;
}
std::string input() {
    char buffer[4096];
    if (!std::fgets(buffer, sizeof(buffer), stdin)) std::abort();
    std::string out = buffer;
    while (!out.empty() && (out.back()=='\n' || out.back()=='\r')) out.pop_back();
    return out;
}
void check(bool value) { if (!value) ++failures; }
void result(const char* name, KModErr error, int expected_transports, bool passed) {
    check(passed && transports == expected_transports && prepares == 0 && uid_reads == 0 && gid_reads == 0);
    std::printf("{\"type\":\"result\",\"phase\":\"%s\",\"error\":%lld,\"transports\":%d,"
                "\"prepares\":%d,\"uidReads\":%d,\"gidReads\":%d,\"failures\":%d}\n",
                name, static_cast<long long>(error), transports, prepares, uid_reads, gid_reads, failures);
    std::fflush(stdout);
}
void reset(const char* name) { phase=name; transports=prepares=uid_reads=gid_reads=0; }
}
namespace kernel_module { uint32_t get_page_size() { return 4096; } }
extern "C" int64_t maplesu_prepare_kernel_request() noexcept { ++prepares; return 0; }
extern "C" int __wrap_getresuid(uid_t* a, uid_t* b, uid_t* c) { ++uid_reads; *a=*b=10000; *c=1234; return 0; }
extern "C" int __wrap_getresgid(gid_t* a, gid_t* b, gid_t* c) { ++gid_reads; *a=*b=10000; *c=5678; return 0; }
extern "C" long __wrap_syscall(long number, ...) {
    ++transports;
    va_list args; va_start(args, number); const auto* packet=va_arg(args,const unsigned char*); va_end(args);
    std::array<unsigned char,18> frame{};
    for (size_t i=0;i<18;++i) frame[i]=packet[48+i]+packet[66+i];
    uint64_t pointer=0; std::memcpy(&pointer,frame.data()+10,8);
    const auto& request=*reinterpret_cast<const maplesu_request_v2*>(static_cast<uintptr_t>(pointer));
    auto* response=reinterpret_cast<maplesu_response_v2*>(static_cast<uintptr_t>(request.response_user));
    check(number==221 && packet[84]==0 && frame[0]==52 && frame[1]==0xa2);
    check(pointer>UINT32_MAX && request.response_user>UINT32_MAX && ids.insert(request.request_id).second);
    maplesu_read_v2 read{};
    if (request.command==MAPLESU_REQUEST_READ)
        std::memcpy(&read,reinterpret_cast<const void*>(static_cast<uintptr_t>(request.arg1)),sizeof(read));
    std::printf("{\"type\":\"transport\",\"phase\":\"%s\",\"packet\":\"%s\",\"frame\":\"%s\","
                "\"requestPointer\":%llu,\"responsePointer\":%llu,\"request\":\"%s\",\"response\":\"%s\","
                "\"readArgs\":\"%s\",\"destination\":\"%s\"}\n",phase,hex(packet,85).c_str(),hex(frame.data(),18).c_str(),
                static_cast<unsigned long long>(pointer),static_cast<unsigned long long>(request.response_user),
                hex(&request,48).c_str(),hex(response,48).c_str(),request.command==3?hex(&read,16).c_str():"",
                request.command==3?hex(reinterpret_cast<void*>(static_cast<uintptr_t>(read.destination_user)),read.length).c_str():"");
    std::fflush(stdout);
    const auto answer=input(); const auto split=answer.find(' ');
    if (split==std::string::npos) std::abort();
    const auto response_bytes=unhex(answer.substr(0,split));
    const auto data=unhex(answer.substr(split+1));
    if(response_bytes.size()!=48) std::abort();
    std::memcpy(response,response_bytes.data(),48);
    if(request.command==MAPLESU_REQUEST_QUERY) {
        if(data.size()!=48) std::abort();
        std::memcpy(expected_metadata.data(),data.data(),48);
    } else if(request.command==MAPLESU_REQUEST_READ) {
        if(data.size()!=read.length) std::abort();
        std::memcpy(reinterpret_cast<void*>(static_cast<uintptr_t>(read.destination_user)),data.data(),data.size());
    }
    return -1;
}
int main() {
    const auto key_bytes=unhex(input()); const std::string key(key_bytes.begin(),key_bytes.end());
    check(key.size()==48); __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key.c_str());
    maplesu_response_v2 channel{}; bool supported=false;
    const auto query=kernel_module::maplesu_request_v2_channel(channel,supported);
    check(query==KModErr::OK && supported && channel.result==7 && channel.metadata_address>=UINT64_C(0xffff000000000000));
    check(prepares==1 && uid_reads==1 && gid_reads==1 && transports==1);
    std::printf("{\"type\":\"query\",\"passed\":%s,\"metadata\":\"%s\",\"address\":%llu}\n",
                failures?"false":"true",hex(expected_metadata.data(),48).c_str(),
                static_cast<unsigned long long>(channel.metadata_address)); std::fflush(stdout);
    std::array<unsigned char,48> destination{};
    reset("metadata_read");
    auto error=kernel_module::maplesu_request_v2_read(channel.metadata_address,destination.data(),destination.size());
    result(phase,error,1,error==KModErr::OK && destination==expected_metadata);
    destination.fill(0xcc); reset("warm_metadata_read");
    error=kernel_module::maplesu_request_v2_read(channel.metadata_address,destination.data(),destination.size());
    result(phase,error,1,error==KModErr::OK && destination==expected_metadata);
    std::array<unsigned char,257> large{}; reset("chunked257");
    error=kernel_module::maplesu_request_v2_read(UINT64_C(0xffff000001200000),large.data(),large.size());
    bool equal=true; for(size_t i=0;i<large.size();++i) equal &= large[i]==static_cast<unsigned char>(i*73+19);
    result(phase,error,2,error==KModErr::OK && equal);
    destination.fill(0xcc); reset("kernel_fault");
    error=kernel_module::maplesu_request_v2_read(channel.metadata_address,destination.data(),48);
    equal=true; for(const auto byte:destination) equal &= byte==0xcc;
    result(phase,error,1,error==KModErr::ERR_MODULE_NOT_KADDR && equal);
    destination.fill(0xcc); reset("partial_data");
    error=kernel_module::maplesu_request_v2_read(channel.metadata_address,destination.data(),48);
    equal=!std::memcmp(destination.data(),expected_metadata.data(),17);
    for(size_t i=17;i<48;++i) equal &= destination[i]==0xcc;
    result(phase,error,1,error==KModErr::ERR_MODULE_NOT_KADDR && equal);
    std::printf("{\"type\":\"summary\",\"uniqueRequestIds\":%zu,\"failures\":%d}\n",ids.size(),failures);
    return failures?1:0;
}
