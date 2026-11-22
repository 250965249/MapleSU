// Execute the production receipt functions with kernel memory/hook/storage seams.
#include "module_err_def.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>
constexpr uint64_t kKernelAddressFloor=0xffff000000000000ULL;
constexpr auto kProErrSelinuxStatusPageAddr=-19987;
constexpr char kFirstPatchBootSessionKey[]="receipt";
constexpr char kSelinuxStatusPageSymbol[]="enforce";
constexpr char kSelinuxPolicyloadSymbol[]="policy";
static std::string boot="boot-1", failure;
static std::vector<uint8_t> stored;
static std::map<uint64_t,std::vector<uint8_t>> memory;
static unsigned installs, removals, saves;
static bool enforce_live, policy_live, corrupt_write;
static uint64_t next_flag=kKernelAddressFloor+0x1000;
static constexpr uint64_t enforce_address=kKernelAddressFloor+0x2000;
static constexpr uint64_t policy_address=kKernelAddressFloor+0x3000;
static KModErr point(const char* name)
{
    return failure==name ? KModErr::ERR_MODULE_STORAGE_READ : KModErr::OK;
}
namespace boot_session_utils { std::string read_boot_session() { return boot; } }
namespace kernel_module {
enum class KernMemProt { KMP_RW };
using HookHandle=void*;
KModErr read_blob_disk_storage(const char*,std::vector<uint8_t>& out)
{
    RETURN_IF_ERROR(point("storage-read"));
    if (failure=="storage-commit-unreadable" && saves)
        return KModErr::ERR_MODULE_STORAGE_READ;
    out=stored;
    return stored.empty() ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND : KModErr::OK;
}
KModErr write_blob_disk_storage(const char*,const void* data,uint64_t size)
{
    assert(enforce_live && policy_live);
    RETURN_IF_ERROR(point("storage-write"));
    const auto* bytes=static_cast<const uint8_t*>(data);
    stored.assign(bytes,bytes+size);++saves;
    RETURN_IF_ERROR(point("storage-commit-unreadable"));
    return point("storage-after-commit");
}
KModErr read_kernel_mem(uint64_t address,void* out,uint32_t size)
{
    RETURN_IF_ERROR(point("memory-read"));
    assert(memory.count(address) && memory[address].size()>=size);
    memcpy(out,memory[address].data(),size);return KModErr::OK;
}
KModErr write_kernel_mem(uint64_t address,const void* data,uint32_t size,KernMemProt)
{
    RETURN_IF_ERROR(point("memory-write"));
    const auto* bytes=static_cast<const uint8_t*>(data);
    if (!corrupt_write) memory[address].assign(bytes,bytes+size);
    return KModErr::OK;
}
KModErr kallsyms_lookup_name(const char* name,uint64_t& address)
{
    RETURN_IF_ERROR(point(name));
    address=!strcmp(name,"enforce") ? enforce_address : policy_address;
    return KModErr::OK;
}
KModErr alloc_kernel_mem(uint32_t size,uint64_t& address)
{
    assert(size==1);RETURN_IF_ERROR(point("allocate"));
    address=next_flag++;memory[address]={0xaa};return KModErr::OK;
}
KModErr fill00_kernel_mem(uint64_t address,uint32_t size,KernMemProt)
{
    assert(size==1);RETURN_IF_ERROR(point("zero"));
    memory[address]={0};return KModErr::OK;
}
KModErr uninstall_kernel_hook(HookHandle handle)
{
    ++removals;
    if (handle==reinterpret_cast<void*>(1)) enforce_live=false;
    else {assert(handle==reinterpret_cast<void*>(2));policy_live=false;}
    return point("rollback");
}
}
static KModErr get_selinux_kernel_status_page_kaddr(uint64_t& address)
{
    RETURN_IF_ERROR(point("status-page"));
    address=kKernelAddressFloor+0x4000;return KModErr::OK;
}
class PatchBase {};
class PatchSelinuxStatusUpdateSetenforce {
public:
    PatchSelinuxStatusUpdateSetenforce(const PatchBase&,uint64_t address) {assert(address==enforce_address);}
    KModErr patch_selinux_status_update_setenforce(uint64_t,uint32_t,uint64_t flag,kernel_module::HookHandle* handle)
    {
        assert(memory[flag][0]==0);RETURN_IF_ERROR(point("install-enforce"));
        ++installs;enforce_live=true;memory[enforce_address]=std::vector<uint8_t>(16,0x11);
        *handle=reinterpret_cast<void*>(1);return KModErr::OK;
    }
};
class PatchSelinuxStatusUpdatePolicyload {
public:
    PatchSelinuxStatusUpdatePolicyload(const PatchBase&,uint64_t address) {assert(address==policy_address);}
    KModErr patch_selinux_status_update_policyload(uint64_t flag,kernel_module::HookHandle* handle)
    {
        assert(memory[flag][0]==0);RETURN_IF_ERROR(point("install-policy"));
        ++installs;policy_live=true;memory[policy_address]=std::vector<uint8_t>(16,0x22);
        *handle=reinterpret_cast<void*>(2);return KModErr::OK;
    }
};
#include "selinux_hooks_under_test.inc"
static void reset()
{
    boot="boot-1";failure.clear();stored.clear();memory.clear();
    installs=removals=saves=0;enforce_live=policy_live=corrupt_write=false;
}
int main()
{
    uint64_t address=0,again=0;
    reset();assert(prepare_selinux_status_hooks(address)==KModErr::OK);
    assert(installs==2 && saves==1 && !memory[address][0]);
    assert(enable_selinux_status_hooks(address)==KModErr::OK && memory[address][0]==1);
    assert(prepare_selinux_status_hooks(again)==KModErr::OK && again==address && installs==2);
    memory[enforce_address][0]^=1;
    assert(prepare_selinux_status_hooks(again)==KModErr::ERR_MODULE_STORAGE_READ && installs==2);
    for (const char* stage : {"storage-read","status-page","enforce","policy","allocate","zero",
                              "install-enforce","install-policy","memory-read","storage-write"}) {
        reset();failure=stage;
        assert(is_failed(prepare_selinux_status_hooks(address)) && stored.empty());
        assert(!enforce_live && !policy_live && !saves);
        if (failure=="install-policy") assert(removals==1);
        if (failure=="memory-read" || failure=="storage-write") assert(removals==2);
        failure.clear();
        assert(prepare_selinux_status_hooks(address)==KModErr::OK && saves==1);
    }
    reset();failure="storage-after-commit";
    assert(is_failed(prepare_selinux_status_hooks(address)) && saves==1);
    assert(enforce_live && policy_live && !removals && !memory[next_flag-1][0]);
    failure.clear();
    assert(prepare_selinux_status_hooks(address)==KModErr::OK && installs==2);
    assert(enable_selinux_status_hooks(address)==KModErr::OK);
    reset();failure="storage-commit-unreadable";
    assert(is_failed(prepare_selinux_status_hooks(address)) && saves==1);
    failure.clear();
    assert(prepare_selinux_status_hooks(address)==KModErr::OK && installs==2);
    assert(enable_selinux_status_hooks(address)==KModErr::OK);
    assert(enforce_live && policy_live && !removals && memory[address][0]==1);
    reset();assert(prepare_selinux_status_hooks(address)==KModErr::OK);
    corrupt_write=true;
    assert(enable_selinux_status_hooks(address)==KModErr::ERR_MODULE_STORAGE_READ);
    corrupt_write=false;failure="memory-write";
    assert(enable_selinux_status_hooks(address)==KModErr::ERR_MODULE_STORAGE_READ);
    failure="memory-read";
    assert(enable_selinux_status_hooks(address)==KModErr::ERR_MODULE_STORAGE_READ);
    failure.clear();assert(enable_selinux_status_hooks(address)==KModErr::OK);
    assert(enable_selinux_status_hooks(0)==KModErr::ERR_MODULE_PARAM);
    boot="boot-2";
    assert(prepare_selinux_status_hooks(again)==KModErr::OK && again!=address && installs==4);
    reset();boot.clear();assert(is_failed(prepare_selinux_status_hooks(address)) && !installs);
    puts("PASS production hook receipts: install ordering, 10 failure/retry stages, resident validation, switch readback, boot change");
}
