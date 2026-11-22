#include "kernel_module_kit_umbrella.h"
#include "maplesu_request_private.h"
#include "kernel_read_metadata.h"
#include <array>
#include <atomic>
#include <cassert>
#include <cstring>
#include <new>
#include <thread>

#if defined(MAPLESU_LEGACY_METADATA_V2_BYTES)
static_assert(MAPLESU_LEGACY_METADATA_V2_BYTES == 54u);
#endif

extern "C" KModErr _ZN13kernel_module23request_kernel_read_memEmPvj(uint64_t,void*,uint32_t);
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
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
constexpr uint64_t descriptor = UINT64_C(0xffff800000700000);
constexpr uint64_t base = UINT64_C(0xffff800000100000);
constexpr uint64_t append = UINT64_C(0xffff800000200000);
constexpr uint64_t source = UINT64_C(0xffff800000300000);
std::atomic<unsigned> checks{0}, failures{0}, old_calls{0};
struct Fixture {
    std::string key;
    pid_t pid = 123;
    bool supported = true;
    bool channel_oom = false, read_oom = false;
    unsigned identity_change_on_read = 0, identity_change_on_channel = 0;
    unsigned identity_change_on_legacy = 0;
    uint64_t legacy_result = append;
    uint64_t capabilities = 7, address = descriptor;
    unsigned descriptor_reads = 0, data_reads = 0, channel_calls = 0, read_calls = 0, unpublished_reads = 0;
    KModErr channel_error = KModErr::OK, read_error = KModErr::OK;
    KModErr legacy_error = KModErr::OK;
    maplesu_metadata_v2 metadata{};
    uint32_t published_bytes = 54;
    std::array<uint8_t,58> data{};
};
thread_local Fixture fixture;
void check_at(bool value, unsigned line) {
    ++checks;
    if (!value) { ++failures; std::fprintf(stderr,"check failed at line %u\n",line); }
}
#define check(...) check_at((__VA_ARGS__),__LINE__)
template<class T> void field(size_t offset, T value) { std::memcpy(fixture.data.data()+offset,&value,sizeof(value)); }
void reset(unsigned tag) {
    fixture = {};
    fixture.key.assign(48,'K'); fixture.key.replace(0,3,"021"); fixture.key[15]='0';
    // Preserve a textual, terminated fixture Key while selecting a new module identity.
    for (size_t i=20;i<28;++i) fixture.key[i]=char('A'+((tag>>(4*(i-20)))&15));
    fixture.metadata = {MAPLESU_METADATA_MAGIC,2,48,7,
        -INT64_C(0x600000),-INT64_C(0x500000),0,0,0};
    field<uint32_t>(0,0x2000); field<uint32_t>(4,0x3333);
    field<uint32_t>(36,0x1234); field<uint8_t>(40,1); field<uint8_t>(41,1);
    field<uint32_t>(42,0x2222); field<int16_t>(46,-2); field<uint32_t>(48,0x4444);
    field<int16_t>(52,0x120);
}
}

extern "C" pid_t getpid() { return fixture.pid; }
extern "C" uid_t getuid() { return 10000; }
extern "C" long sysconf(int) { return 4096; }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() {
    return fixture.key.c_str();
}
namespace kernel_module {
// This suite exercises the legacy-Key QUERY/READ consumers. Keep owner-mode
// transport unavailable so the fixture cannot accidentally claim v3 coverage.
uint64_t maplesu_request_auth_state() { return 0; }
bool maplesu_request_managed_allocation(uint64_t) { return false; }
KModErr maplesu_request_key_alloc(uint32_t, uint64_t&, bool& supported) {
    supported = false; return KModErr::OK;
}
bool maplesu_request_owner_binding_matches(const RequestOwnerBinding&) { return false; }
KModErr maplesu_request_owner_channel(maplesu_metadata_owner_v3&, uint64_t&,
                                      RequestOwnerBinding&) {
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
KModErr maplesu_request_owner_read(uint64_t, void*, uint32_t,
                                   const RequestOwnerBinding&) {
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
KModErr maplesu_request_owner_write_text(uint64_t, const void*, uint32_t) {
    return KModErr::ERR_MODULE_TEST_CHANNEL;
}
// Windows uint64_t mangles differently from the fixed Android canonical entry.
KModErr request_kernel_read_mem(uint64_t a,void* b,uint32_t c) {
    return _ZN13kernel_module23request_kernel_read_memEmPvj(a,b,c);
}

extern "C" int64_t maplesu_release_staging(uint64_t) { return 0; }
KModErr maplesu_request_v2_channel(maplesu_response_v2& response,bool& supported) {
    ++fixture.channel_calls; response={}; supported=fixture.supported;
    if (fixture.channel_oom) throw std::bad_alloc();
    if (is_failed(fixture.channel_error)) { supported=false; return fixture.channel_error; }
    if (supported) {
        response.result=fixture.capabilities; response.metadata_address=fixture.address;
        response.metadata_length=48; response.metadata_version=2;
    }
    if (fixture.identity_change_on_channel) {
        fixture.key[47] = 'Q';
        fixture.identity_change_on_channel = 0;
    }
    return KModErr::OK;
}
KModErr maplesu_request_v2_read(uint64_t address,void* output,uint32_t size) {
    ++fixture.read_calls;
    if (fixture.read_oom) throw std::bad_alloc();
    if (!(fixture.capabilities&MAPLESU_CAP_READ)) return KModErr::ERR_MODULE_TEST_CHANNEL;
    if (is_failed(fixture.read_error)) return fixture.read_error;
    if (address==fixture.address && size==48) {
        ++fixture.descriptor_reads; std::memcpy(output,&fixture.metadata,48);
        switch (fixture.identity_change_on_read) {
        case 1: fixture.key[47]='Z'; break;
        case 2: ++fixture.pid; break;
        case 3: fixture.key.pop_back(); break;
        }
        fixture.identity_change_on_read=0;
        return KModErr::OK;
    }
    if (address>=append && address-append<=fixture.published_bytes && size<=fixture.published_bytes-(address-append)) {
        ++fixture.data_reads; std::memcpy(output,fixture.data.data()+(address-append),size); return KModErr::OK;
    }
    if (address>=append && address-append<0x1000) ++fixture.unpublished_reads;
    if (address>=source && address-source<=600 && size<=600-(address-source)) {
        ++fixture.data_reads;
        for (uint32_t i=0;i<size;++i) static_cast<uint8_t*>(output)[i]=uint8_t((address-source+i)*37+11);
        return KModErr::OK;
    }
    return KModErr::ERR_MODULE_NOT_KADDR;
}
void arm64_module_asm_func_start(Assembler*) { ++old_calls; }
void arm64_module_asm_func_end(Assembler*) { ++old_calls; }
void arm64_module_asm_func_end(Assembler*,GpX) { ++old_calls; }
void maplesu_legacy_asm_func_start(Assembler*) { ++old_calls; }
void maplesu_legacy_asm_func_end(Assembler*) { ++old_calls; }
void maplesu_legacy_asm_func_end(Assembler*,GpX) { ++old_calls; }
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&,uint64_t& result) {
    ++old_calls; result=fixture.legacy_result;
    if (fixture.identity_change_on_legacy == 1) fixture.key[47] = 'Z';
    if (fixture.identity_change_on_legacy == 2) ++fixture.pid;
    fixture.identity_change_on_legacy = 0;
    return fixture.legacy_error;
}
KModErr execute_kernel_asm_func_with_buf(const uint8_t*,uint32_t,uint64_t&) {
    ++old_calls; return KModErr::ERR_MODULE_ASM;
}
KModErr kallsyms_lookup_name(const char*,SymbolHit&,SymbolMatchMode) {
    ++old_calls; return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
}
KModErr kallsyms_lookup_name(const char*,uint64_t&) { ++old_calls; return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST; }
bool is_kernel_version_less(const char*) { ++old_calls; return false; }
KModErr request_kernel_alloc_mem(uint32_t,uint64_t&) { ++old_calls; return KModErr::ERR_MODULE_ALLOC_MEM; }
KModErr request_kernel_write_mem(uint64_t,const void*,uint32_t) { ++old_calls; return KModErr::ERR_MODULE_PARAM; }
KModErr icache_invalidate_all_cpus() { ++old_calls; return KModErr::OK; }
}

int main() {
    using namespace kernel_module;
    uint64_t value=0,extra=0;
    uint32_t offset=0;
    char flag=0; bool present=false,supported=false;
    maplesu_metadata_v2 metadata{};
    reset(1);
    check(is_ok(get_kernel_base_vaddr(value))&&value==base);
    check(is_ok(get_append_package_data_offset(offset))&&offset==0x2000);
    check(is_ok(get_append_package_kallsyms_kaddr(value))&&value==base+0x3333);
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&value==append+8);
    check(is_ok(get_do_execve_info(value,flag,present))&&value==base+0x1234&&flag==1&&present);
    check(is_ok(get_avc_denied_info(value,extra))&&value==base+0x2222&&extra==base+0x2222-12);
    check(is_ok(get_filldir64_addr(value))&&value==base+0x4444);
    check(is_ok(get_seccomp_offset(offset))&&offset==0x120);
    value=UINT64_C(0xa1b2c3d4e5f60718);
    const auto reads_before_missing=fixture.read_calls;
    const auto data_before_missing=fixture.data_reads;
    check(get_slow_avc_audit_addr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    check(value==UINT64_C(0xa1b2c3d4e5f60718));
    check(fixture.read_calls==reads_before_missing&&fixture.data_reads==data_before_missing&&fixture.unpublished_reads==0);
    check(fixture.descriptor_reads==1&&old_calls==0&&metadata_test::init_count==0);
    field<uint32_t>(4,0x7777);
    check(is_ok(get_append_package_kallsyms_kaddr(value))&&value==base+0x7777);
    std::array<uint8_t,600> bytes{};
    check(is_ok(request_kernel_read_mem(source,bytes.data(),bytes.size())));
    for (size_t i=0;i<bytes.size();++i) check(bytes[i]==uint8_t(i*37+11));
    check(request_kernel_read_mem(UINT64_MAX-1,bytes.data(),4)==KModErr::ERR_MODULE_PARAM);
    check(request_kernel_read_mem(1,bytes.data(),1)==KModErr::ERR_MODULE_PARAM);
    check(request_kernel_read_mem(source,nullptr,1)==KModErr::ERR_MODULE_PARAM);
    check(request_kernel_read_mem(source,bytes.data(),0)==KModErr::ERR_MODULE_PARAM);
    fixture.key[47]='Z';
    check(is_ok(get_kernel_base_vaddr(value))&&fixture.descriptor_reads==2);
    ++fixture.pid;
    check(is_ok(get_kernel_base_vaddr(value))&&fixture.descriptor_reads==3);
    fixture.channel_error=KModErr::ERR_MODULE_TEST_CHANNEL;
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_TEST_CHANNEL);
    fixture.channel_error=KModErr::OK;
    check(is_ok(get_kernel_base_vaddr(value))&&fixture.descriptor_reads==4);
    fixture.supported=false;
    check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&!supported);
    fixture.supported=true;
    check(is_ok(get_kernel_base_vaddr(value))&&fixture.descriptor_reads==5);
    reset(2); fixture.metadata.kernel_base_displacement=0x1000;
    fixture.metadata.layout_displacement=0x2000;
    fixture.metadata.layout_length=24; fixture.metadata.layout_version=1;
    check(is_ok(get_kernel_base_vaddr(value))&&value==descriptor+0x1000);
    check(maplesu_kernel_read::metadata_address(descriptor,8,48,value)&&value==descriptor+8);
    check(!maplesu_kernel_read::metadata_address(0,INT64_MIN,1,value));
    check(!maplesu_kernel_read::metadata_address(descriptor,0,0,value));
    check(!maplesu_kernel_read::metadata_address(descriptor,INT64_MIN,1,value));
    check(!maplesu_kernel_read::metadata_address(UINT64_MAX-1,2,1,value));
    check(!maplesu_kernel_read::metadata_address(UINT64_MAX-1,0,3,value));
    for (unsigned bad=0;bad<12;++bad) {
        reset(10+bad);
        switch(bad) {
        case 0: ++fixture.metadata.magic; break;
        case 1: ++fixture.metadata.version; break;
        case 2: --fixture.metadata.length; break;
        case 3: fixture.metadata.capabilities=3; break;
        case 4: fixture.metadata.kernel_base_displacement=INT64_MAX; break;
        case 5: fixture.metadata.kernel_base_displacement=INT64_MIN; break;
        case 6: fixture.metadata.legacy_metadata_displacement=INT64_MAX; break;
        case 7: fixture.metadata.layout_displacement=8; break;
        case 8: fixture.metadata.layout_version=1; break;
        case 9: fixture.metadata.layout_length=1; break;
        case 10: ++fixture.address; break;
        case 11: fixture.address=UINT64_MAX-7; break;
        }
        check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
        check(fixture.descriptor_reads==1);
        check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND&&fixture.descriptor_reads==2);
    }
    reset(30); fixture.read_error=KModErr::ERR_MODULE_NOT_KADDR;
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_NOT_KADDR);
    fixture.read_error=KModErr::OK;
    check(is_ok(get_kernel_base_vaddr(value))&&fixture.descriptor_reads==1);
    fixture.read_error=KModErr::ERR_MODULE_NOT_KADDR;
    check(request_kernel_read_mem(source,bytes.data(),4)==KModErr::ERR_MODULE_NOT_KADDR);
    reset(31); fixture.capabilities=3;
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_TEST_CHANNEL&&fixture.descriptor_reads==0);
    check(request_kernel_read_mem(source,bytes.data(),4)==KModErr::ERR_MODULE_TEST_CHANNEL);
    reset(32); fixture.channel_error=KModErr::ERR_MODULE_TEST_CHANNEL;
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_TEST_CHANNEL);
    check(request_kernel_read_mem(source,bytes.data(),4)==KModErr::ERR_MODULE_TEST_CHANNEL);
    reset(33); fixture.channel_oom=true;
    check(request_kernel_read_mem(source,bytes.data(),4)==KModErr::ERR_NO_MEM);
    fixture.channel_oom=false; fixture.read_oom=true;
    check(request_kernel_read_mem(source,bytes.data(),4)==KModErr::ERR_NO_MEM);
    reset(34); fixture.key.pop_back();
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_ROOT_KEY);
    reset(35); fixture.metadata.layout_length=24; fixture.metadata.layout_version=1;
    fixture.metadata.layout_displacement=INT64_MAX;
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    reset(36); fixture.metadata.layout_length=24; fixture.metadata.layout_version=1;
    fixture.metadata.layout_displacement=-INT64_C(0x800000000000000);
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    // A missing field may negotiate and read the descriptor once, but never read
    // outside the producer's 54-byte append publication or replay a legacy path.
    reset(37); value=UINT64_C(0xa1b2c3d4e5f60718);
    check(get_slow_avc_audit_addr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    check(value==UINT64_C(0xa1b2c3d4e5f60718));
    check(fixture.descriptor_reads==1&&fixture.read_calls==1&&fixture.data_reads==0&&fixture.unpublished_reads==0);
    check(old_calls==0&&metadata_test::init_count==0);
    // A producer may explicitly publish the optional audit field. Its presence
    // must not extend the default 54-byte contract of other producers.
    constexpr uint64_t audit_cap = UINT64_C(16);
    static_assert(audit_cap==MAPLESU_CAP_APPEND_AUDIT);
    static_assert(MAPLESU_LEGACY_METADATA_AUDIT_BYTES==58u);
    static_assert(MAPLESU_REQUEST_CAPABILITIES==7);
    reset(38); fixture.capabilities |= audit_cap;
    fixture.metadata.capabilities = fixture.capabilities;
    fixture.published_bytes = 58; field<uint32_t>(54,0x5555);
    value=UINT64_C(0xa1b2c3d4e5f60718);
    check(is_ok(get_slow_avc_audit_addr(value))&&value==base+0x5555);
    check(fixture.descriptor_reads==1&&fixture.data_reads==1&&fixture.unpublished_reads==0);
    check(old_calls==0&&metadata_test::init_count==0);
    reset(39); fixture.capabilities |= audit_cap;
    fixture.metadata.capabilities=fixture.capabilities; fixture.published_bytes=58;
    value=UINT64_C(0xa1b2c3d4e5f60718);
    check(get_slow_avc_audit_addr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    check(value==UINT64_C(0xa1b2c3d4e5f60718)&&fixture.data_reads==1);
    check(fixture.unpublished_reads==0&&old_calls==0);
    reset(40); fixture.capabilities |= audit_cap;
    fixture.metadata.capabilities=fixture.capabilities; fixture.published_bytes=58;
    field<uint32_t>(54,0x5555);
    check(is_ok(get_kernel_base_vaddr(value))&&value==base);
    fixture.read_error=KModErr::ERR_MODULE_NOT_KADDR;
    value=UINT64_C(0xa1b2c3d4e5f60718);
    check(get_slow_avc_audit_addr(value)==KModErr::ERR_MODULE_NOT_KADDR);
    check(value==UINT64_C(0xa1b2c3d4e5f60718)&&fixture.data_reads==0);
    check(fixture.unpublished_reads==0&&old_calls==0);
    for(unsigned mismatch=0;mismatch<2;++mismatch) {
        reset(41+mismatch); fixture.published_bytes=58; field<uint32_t>(54,0x5555);
        if(mismatch) fixture.metadata.capabilities |= audit_cap;
        else fixture.capabilities |= audit_cap;
        value=UINT64_C(0xa1b2c3d4e5f60718);
        check(get_slow_avc_audit_addr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
        check(value==UINT64_C(0xa1b2c3d4e5f60718)&&fixture.data_reads==0);
        check(fixture.descriptor_reads==1&&fixture.unpublished_reads==0&&old_calls==0);
    }
    reset(43); fixture.capabilities |= audit_cap;
    fixture.metadata.capabilities=fixture.capabilities;
    fixture.metadata.legacy_metadata_displacement=static_cast<int64_t>(UINT64_MAX-57-descriptor);
    check(maplesu_kernel_read::valid_metadata(fixture.metadata,descriptor,fixture.capabilities));
    ++fixture.metadata.legacy_metadata_displacement;
    check(!maplesu_kernel_read::valid_metadata(fixture.metadata,descriptor,fixture.capabilities));
    fixture.capabilities=fixture.metadata.capabilities=7;
    fixture.metadata.legacy_metadata_displacement=static_cast<int64_t>(UINT64_MAX-53-descriptor);
    check(maplesu_kernel_read::valid_metadata(fixture.metadata,descriptor,fixture.capabilities));
    ++fixture.metadata.legacy_metadata_displacement;
    check(!maplesu_kernel_read::valid_metadata(fixture.metadata,descriptor,fixture.capabilities));
    // The wire flag is a byte, including nonzero encodings that are not valid
    // C++ bool object representations. Normalize it only after reading the wire.
    reset(44); field<uint8_t>(41,0x80);
    check(is_ok(get_do_execve_info(value,flag,present))&&present);
    field<uint8_t>(41,0);
    check(is_ok(get_do_execve_info(value,flag,present))&&!present);
    constexpr uint64_t sentinel=UINT64_C(0xa1b2c3d4e5f60718);
    for(unsigned item=0;item<5;++item) {
        reset(45+item);
        fixture.capabilities|=audit_cap; fixture.metadata.capabilities=fixture.capabilities;
        fixture.published_bytes=58;
        fixture.metadata.kernel_base_displacement=static_cast<int64_t>(UINT64_MAX-0x1000-descriptor);
        field<uint32_t>(item==0?4:item==1?36:item==2?42:item==3?48:54,0x1001);
        value=extra=sentinel; flag=7; present=false;
        const auto error=item==0?get_append_package_kallsyms_kaddr(value):
            item==1?get_do_execve_info(value,flag,present):
            item==2?get_avc_denied_info(value,extra):
            item==3?get_filldir64_addr(value):get_slow_avc_audit_addr(value);
        check(error==KModErr::ERR_MODULE_INTERNAL_APPEND);
        check(value==sentinel&&extra==sentinel&&flag==7&&!present);
        check(fixture.data_reads==1&&fixture.unpublished_reads==0);
    }
    reset(50);
    fixture.metadata.kernel_base_displacement=static_cast<int64_t>(UINT64_MAX-0x1000-descriptor);
    field<uint32_t>(4,0x1000);
    check(is_ok(get_append_package_kallsyms_kaddr(value))&&value==UINT64_MAX);
    reset(51);
    fixture.metadata.kernel_base_displacement=static_cast<int64_t>(UINT64_MAX-0x1000-descriptor);
    field<uint32_t>(42,0x1000); field<int16_t>(46,1);
    check(is_ok(get_avc_denied_info(value,extra))&&value==UINT64_MAX&&extra==UINT64_MAX);
    reset(52);
    fixture.metadata.kernel_base_displacement=static_cast<int64_t>(UINT64_MAX-0x1000-descriptor);
    field<uint32_t>(42,0x1000); field<int16_t>(46,2);
    value=extra=sentinel;
    check(get_avc_denied_info(value,extra)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    check(value==sentinel&&extra==sentinel);
    reset(53);
    fixture.metadata.kernel_base_displacement=static_cast<int64_t>(UINT64_C(0xffff000000000000)-descriptor);
    field<uint32_t>(42,4); field<int16_t>(46,-1);
    value=extra=sentinel;
    check(get_avc_denied_info(value,extra)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    check(value==sentinel&&extra==sentinel);
    // Exercise the actual descriptor publication, with the identity changing
    // inside the READ boundary. No descriptor from that request may be cached.
    for (unsigned change=1;change<=3;++change) {
        reset(60+change); fixture.identity_change_on_read=change;
        metadata.magic=1; value=sentinel; supported=false;
        check(maplesu_kernel_metadata_v2(metadata,value,supported)==KModErr::ERR_MODULE_ROOT_KEY);
        check(metadata.magic==0&&value==0&&fixture.descriptor_reads==1);
        if (change==3) fixture.key.push_back('Z');
        check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&supported&&value==descriptor);
        check(fixture.descriptor_reads==2);
        check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&fixture.descriptor_reads==2);
    }
    reset(64);
    check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&fixture.descriptor_reads==1);
    fixture.identity_change_on_channel=1;
    check(maplesu_kernel_metadata_v2(metadata,value,supported)==KModErr::ERR_MODULE_ROOT_KEY);
    check(metadata.magic==0&&value==0&&fixture.descriptor_reads==1);
    check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&fixture.descriptor_reads==2);
    reset(65); fixture.identity_change_on_channel=1;
    check(maplesu_kernel_metadata_v2(metadata,value,supported)==KModErr::ERR_MODULE_ROOT_KEY);
    check(metadata.magic==0&&value==0&&fixture.descriptor_reads==0);
    check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&fixture.descriptor_reads==1);
    check(old_calls==0&&metadata_test::init_count==0);
    std::vector<std::thread> threads;
    for (unsigned i=0;i<16;++i) threads.emplace_back([i]{
        reset(100+i);
        for (unsigned j=0;j<100;++j) {
            uint64_t own=0;
            check(is_ok(kernel_module::get_append_package_kallsyms_kaddr(own))&&own==base+0x3333);
        }
        check(fixture.descriptor_reads==1);
    });
    for(auto& thread:threads) thread.join();
    check(old_calls==0&&metadata_test::init_count==0);
    reset(200); fixture.supported=false;
    check(is_ok(maplesu_kernel_metadata_v2(metadata,value,supported))&&!supported);
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&value==append+8);
    const auto legacy_before=old_calls.load();
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&old_calls==legacy_before);
    ++fixture.pid;
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&old_calls>legacy_before);
    const auto legacy_pid=old_calls.load();
    fixture.key[47]='Y';
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&old_calls>legacy_pid);
    // The legacy read assembler is deliberately unavailable, so the retained base
    // locator reaches its original symbol bootstrap and reports that exact error.
    check(get_kernel_base_vaddr(value)==KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);
    // A zero QUERY response remains ambiguous; the consumer preserves current compatibility semantics.
    check(request_kernel_read_mem(source,bytes.data(),1)==KModErr::ERR_MODULE_SYMBOL_NOT_EXIST);
    // A legacy result cannot be cached or returned under another Key/process identity.
    for (unsigned change=1;change<=2;++change) {
        reset(210+change); fixture.supported=false; fixture.identity_change_on_legacy=change;
        value=sentinel;
        check(get_append_package_run_fake_proc_path_addr(value)==KModErr::ERR_MODULE_ROOT_KEY);
        check(value==sentinel);
        const auto calls_after_change=old_calls.load();
        check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&value==append+8);
        check(old_calls>calls_after_change);
    }
    unsigned legacy_tag=220;
    for (const uint64_t invalid : {UINT64_C(0),UINT64_C(1),UINT64_C(0xfffeffffffffffff),UINT64_MAX-52}) {
        reset(legacy_tag++); fixture.supported=false; fixture.legacy_result=invalid;
        value=sentinel;
        check(get_append_package_run_fake_proc_path_addr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
        check(value==sentinel);
        fixture.legacy_result=append;
        check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&value==append+8);
    }
    reset(230); fixture.supported=false; fixture.legacy_result=UINT64_MAX-53;
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&value==UINT64_MAX-45);
    value=sentinel;
    const auto legacy_before_wider_field=old_calls.load();
    check(get_slow_avc_audit_addr(value)==KModErr::ERR_MODULE_INTERNAL_APPEND);
    check(value==sentinel&&old_calls==legacy_before_wider_field);
    reset(231); fixture.supported=false; fixture.legacy_error=KModErr::ERR_MODULE_ASM;
    value=sentinel;
    check(get_append_package_run_fake_proc_path_addr(value)==KModErr::ERR_MODULE_ASM);
    check(value==sentinel);
    const auto legacy_after_error=old_calls.load();
    fixture.legacy_error=KModErr::OK;
    check(is_ok(get_append_package_run_fake_proc_path_addr(value))&&value==append+8);
    check(old_calls>legacy_after_error);
    std::printf("request-metadata: %u checks, %u failures; 16 threads, 1600 lookups; legacy seam %u\n",
                checks.load(),failures.load(),old_calls.load());
    return failures?1:0;
}
