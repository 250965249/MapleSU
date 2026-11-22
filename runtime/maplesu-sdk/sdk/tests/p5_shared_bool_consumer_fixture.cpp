// Real production consumer bodies; provider, text and disk I/O are seams.
#include "module_err_def.h"
#include "request_protocol.h"
#include <cassert>
#include <cstdint>
#include <cerrno>
#ifdef _WIN32
#include <cstdlib>
#endif
#include <cstdio>
#include <cstring>
#include <map>
#include <new>
#include <string>
#include <vector>
constexpr uint64_t kKernelAddressFloor = UINT64_C(0xffff000000000000);
constexpr auto kUltraErrSelinuxStatusPageAddr = -19987;
constexpr char kFirstPatchBootSessionKey[] = "old184";
constexpr char kFirstPatchOwnerBootSessionKey[] = "owner216";
constexpr char kFirstPatchLegacyBootSessionKey[] = "legacy216";
constexpr char kSelinuxStatusPageSymbol[] = "enforce";
constexpr char kSelinuxPolicyloadSymbol[] = "policy";
static std::string boot = "boot-1", failure;
static std::map<std::string, std::vector<uint8_t>> storage;
static std::map<uint64_t, std::vector<uint8_t>> memory;
static unsigned installs, removals, saves, creates, stores, releases, closes, refs;
static unsigned raw_allocations, raw_writes;
static bool owner_mode, boot_mode, enforce_live, policy_live, creator_live;
static constexpr uint64_t flag_address = kKernelAddressFloor + 0x1000;
static constexpr uint64_t enforce_address = kKernelAddressFloor + 0x2000;
static constexpr uint64_t policy_address = kKernelAddressFloor + 0x3000;
static KModErr point(const char* name) {
    return failure == name ? KModErr::ERR_MODULE_STORAGE_READ : KModErr::OK;
}
namespace boot_session_utils { std::string read_boot_session() { return boot; } }
namespace kernel_module {
using HookHandle = void*;
struct RequestSharedBool {
    uint64_t id = 0, address = 0;
    maplesu_host_instance host{};
    uint32_t epoch = 0;
};
struct RequestManagementReply { bool completed = true; uint32_t effects = 0; };
static RequestManagementReply reply;
struct HookCleanupReceiptScope {
    RequestManagementReply saved = reply;
    ~HookCleanupReceiptScope() { reply = saved; }
};
bool maplesu_request_owner_mode() { return owner_mode; }
KModErr maplesu_hook_legacy_boot_selected(bool& selected) {
    RETURN_IF_ERROR(point("backend-query"));
    selected = boot_mode;
    return KModErr::OK;
}
enum class KernMemProt { KMP_RW };
KModErr request_kernel_alloc_mem(uint32_t size, uint64_t& address) {
    assert(boot_mode && !owner_mode && size == 1);
    RETURN_IF_ERROR(point("raw-alloc"));
    ++raw_allocations; address = flag_address; memory[address] = {0xff};
    return KModErr::OK;
}
KModErr write_kernel_mem(uint64_t address, const void* data, uint32_t size, KernMemProt) {
    assert(boot_mode && address == flag_address && size == 1);
    const auto value = *static_cast<const uint8_t*>(data);
    RETURN_IF_ERROR(point(value ? "raw-enable-write" : "raw-init-write"));
    ++raw_writes; memory[address] = {value};
    return KModErr::OK;
}
RequestManagementReply maplesu_hook_reply() { return reply; }
KModErr maplesu_hook_shared_bool_create(bool initial, RequestSharedBool& object) {
    assert(!boot_mode);
    ++creates; reply = {};
    RETURN_IF_ERROR(point("create"));
    assert(!initial && !refs);
    object = {71, flag_address, {2, 3}, owner_mode ? 44u : 1u};
    creator_live = true; refs = 1; memory[flag_address] = {0};
    return KModErr::OK;
}
KModErr maplesu_hook_shared_bool_release(const RequestSharedBool& object) {
    ++releases; reply = {};
    assert(object.id == 71 && creator_live && refs);
    RETURN_IF_ERROR(point("release"));
    creator_live = false; --refs; reply.effects = MAPLESU_EFFECT_REFERENCE_DROPPED;
    return KModErr::OK;
}
KModErr maplesu_hook_shared_bool_store(const RequestSharedBool& object, bool value) {
    ++stores;
    if (!refs || object.id != 71 || object.host.low != 2 || object.host.high != 3 ||
        object.epoch != (owner_mode ? 44u : 1u)) return KModErr::ERR_MODULE_ROOT_KEY;
    RETURN_IF_ERROR(point("store"));
    memory[object.address][0] = value;
    return KModErr::OK;
}
KModErr maplesu_hook_close() {
    ++closes;
    if (creator_live) { creator_live = false; assert(refs); --refs; }
    return KModErr::OK;
}
KModErr read_blob_disk_storage(const char* key, std::vector<uint8_t>& out) {
    RETURN_IF_ERROR(point("storage-read"));
    if (failure == "storage-commit-unreadable" && saves)
        return KModErr::ERR_MODULE_STORAGE_READ;
    out = storage[key];
    return out.empty() ? KModErr::ERR_MODULE_STORAGE_NOT_FOUND : KModErr::OK;
}
KModErr write_blob_disk_storage(const char* key, const void* data, uint32_t size) {
    assert(enforce_live && policy_live && !creator_live);
    assert(boot_mode ? (!refs && size == 184) : (refs == 2 && size == 216));
    RETURN_IF_ERROR(point("storage-write"));
    const auto* bytes = static_cast<const uint8_t*>(data);
    storage[key].assign(bytes, bytes + size); ++saves;
    RETURN_IF_ERROR(point("storage-commit-unreadable"));
    return point("storage-after-commit");
}
KModErr read_kernel_mem(uint64_t address, void* out, uint32_t size) {
    RETURN_IF_ERROR(point("memory-read"));
    if (boot_mode && address == flag_address) {
        RETURN_IF_ERROR(point(memory[address][0] ? "raw-enable-read" : "raw-init-read"));
        if (failure == "raw-init-mismatch" || failure == "raw-enable-mismatch") {
            *static_cast<uint8_t*>(out) = memory[address][0] ^ 1;
            return KModErr::OK;
        }
    }
    assert(memory.count(address) && memory[address].size() >= size);
    memcpy(out, memory[address].data(), size);
    return KModErr::OK;
}
KModErr kallsyms_lookup_name(const char* name, uint64_t& address) {
    RETURN_IF_ERROR(point(name));
    address = !strcmp(name, "enforce") ? enforce_address : policy_address;
    return KModErr::OK;
}
KModErr uninstall_kernel_hook(HookHandle handle) {
    ++removals;
    if (handle == reinterpret_cast<void*>(1)) { assert(enforce_live); enforce_live = false; }
    else { assert(handle == reinterpret_cast<void*>(2) && policy_live); policy_live = false; }
    if (boot_mode) { errno = EINPROGRESS; return KModErr::ERR_MODULE_MUST_UNINSTALL; }
    assert(refs); --refs;
    return point("rollback");
}
}
static KModErr get_selinux_kernel_status_page_kaddr(uint64_t& address) {
    RETURN_IF_ERROR(point("status-page"));
    address = kKernelAddressFloor + 0x4000;
    return KModErr::OK;
}
// The extracted enable function also retains the fixed helper branch. Its
// transport is separate from both native boot-retained and provider paths.
enum class EarlySelinuxOperation { Enable };
struct RequestEarlySelinuxResult {};
static KModErr maplesu_request_helper_selinux(EarlySelinuxOperation,
    uint64_t, uint64_t, uint32_t, RequestEarlySelinuxResult&) {
    return KModErr::ERR_MODULE_PARAM;
}
class PatchBase {};
static void dependency(const kernel_module::RequestSharedBool* object, uint64_t flag) {
    if (boot_mode) { assert(!object && flag == flag_address && !memory[flag][0]); return; }
    assert(object && object->id == 71 && object->address == flag && !memory[flag][0]);
    assert(object->epoch == (owner_mode ? 44u : 1u));
}
class PatchSelinuxStatusUpdateSetenforce {
public:
    PatchSelinuxStatusUpdateSetenforce(const PatchBase&, uint64_t address) { assert(address == enforce_address); }
    KModErr patch_selinux_status_update_setenforce(uint64_t, uint32_t, uint64_t flag,
        kernel_module::HookHandle* handle, const kernel_module::RequestSharedBool* object) {
        dependency(object, flag); RETURN_IF_ERROR(point("install-enforce"));
        ++installs; if (!boot_mode) ++refs; enforce_live = true; memory[enforce_address] = std::vector<uint8_t>(16, 0x11);
        *handle = reinterpret_cast<void*>(1);
        return point("install-enforce-unknown");
    }
};
class PatchSelinuxStatusUpdatePolicyload {
public:
    PatchSelinuxStatusUpdatePolicyload(const PatchBase&, uint64_t address) { assert(address == policy_address); }
    KModErr patch_selinux_status_update_policyload(uint64_t flag, kernel_module::HookHandle* handle,
        const kernel_module::RequestSharedBool* object) {
        dependency(object, flag); RETURN_IF_ERROR(point("install-policy"));
        ++installs; if (!boot_mode) ++refs; policy_live = true; memory[policy_address] = std::vector<uint8_t>(16, 0x22);
        *handle = reinterpret_cast<void*>(2);
        return point("install-policy-unknown");
    }
};
#include "selinux_hooks_under_test.inc"
static void reset(bool owner) {
    owner_mode = owner; boot_mode = false; boot = "boot-1"; failure.clear(); storage.clear(); memory.clear();
    installs = removals = saves = creates = stores = releases = closes = refs = 0;
    enforce_live = policy_live = creator_live = false;
    raw_allocations = raw_writes = 0;
}
int main() {
#ifdef _WIN32
    _set_abort_behavior(_WRITE_ABORT_MSG, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
    unsigned cases = 0;
    for (bool owner : {false, true}) {
        reset(owner);
        SelinuxHookSwitch info{}, again{};
        assert(prepare_selinux_status_hooks(info) == KModErr::OK);
        assert(installs == 2 && refs == 2 && saves == 1 && creates == 1 && releases == 1);
        assert(storage[owner ? "owner216" : "legacy216"].size() == 216);
        assert(enable_selinux_status_hooks(info) == KModErr::OK && stores == 1 && memory[flag_address][0]);
        assert(prepare_selinux_status_hooks(again) == KModErr::OK && creates == 1 && installs == 2);
        assert(again.shared.id == info.shared.id && again.address == info.address);
        memory[enforce_address][0] ^= 1;
        assert(prepare_selinux_status_hooks(again) == KModErr::ERR_MODULE_STORAGE_READ && creates == 1);
        ++cases;
        for (const char* stage : {"storage-read", "status-page", "enforce", "policy", "create",
                                 "install-enforce", "install-policy", "release", "memory-read", "storage-write"}) {
            reset(owner); failure = stage;
            assert(prepare_selinux_status_hooks(info) == KModErr::ERR_MODULE_STORAGE_READ);
            assert(!enforce_live && !policy_live && !refs && !creator_live && !saves);
            if (failure == "install-policy") assert(removals == 1);
            if (failure == "release") assert(closes == 1);
            ++cases;
        }
        for (const char* stage : {"storage-after-commit", "storage-commit-unreadable"}) {
            reset(owner); failure = stage;
            assert(prepare_selinux_status_hooks(info) == KModErr::ERR_MODULE_STORAGE_READ);
            assert(enforce_live && policy_live && refs == 2 && !creator_live && !removals && saves == 1);
            failure.clear();
            assert(prepare_selinux_status_hooks(info) == KModErr::OK && creates == 1 && installs == 2);
            assert(enable_selinux_status_hooks(info) == KModErr::OK);
            ++cases;
        }
        reset(owner); assert(prepare_selinux_status_hooks(info) == KModErr::OK);
        ++info.shared.host.high;
        assert(enable_selinux_status_hooks(info) == KModErr::ERR_MODULE_ROOT_KEY);
        ++cases;
    }
    reset(false);
    SelinuxHookReceipt old{}; memcpy(old.boot, boot.c_str(), boot.size() + 1);
    auto* bytes = reinterpret_cast<uint8_t*>(&old);
    storage["old184"].assign(bytes, bytes + sizeof(old));
    auto preserved = storage["old184"];
    SelinuxHookSwitch info{};
    assert(prepare_selinux_status_hooks(info) == KModErr::ERR_MODULE_STORAGE_READ);
    assert(!creates && !installs && storage["old184"] == preserved);
    ++cases;
    boot = "boot-2";
    assert(prepare_selinux_status_hooks(info) == KModErr::OK && refs == 2);
    assert(storage["old184"] == preserved && storage["legacy216"].size() == 216);
    ++cases;
    assert(enable_selinux_status_hooks({}) == KModErr::ERR_MODULE_PARAM);
    ++cases;
    reset(false); boot_mode = true;
    assert(prepare_selinux_status_hooks(info) == KModErr::OK);
    assert(!creates && !refs && !releases && !closes && raw_allocations == 1 && installs == 2);
    assert(storage["legacy216"].size() == 184 && raw_writes == 1);
    // A new process has no host Hook handles. Its boot receipt and resident
    // entry/flag bytes are sufficient, without a fabricated shared reference.
    SelinuxHookSwitch next_process{};
    assert(prepare_selinux_status_hooks(next_process) == KModErr::OK);
    assert(raw_allocations == 1 && installs == 2 && saves == 1);
    assert(enable_selinux_status_hooks(next_process) == KModErr::OK && !stores && memory[flag_address][0] == 1);
    assert(prepare_selinux_status_hooks(next_process) == KModErr::OK && raw_allocations == 1);
    memory[policy_address][0] ^= 1;
    assert(prepare_selinux_status_hooks(next_process) == KModErr::ERR_MODULE_STORAGE_READ && installs == 2);
    ++cases;
    for (const char* stage : {"backend-query", "raw-alloc", "raw-init-write", "raw-init-read",
                             "install-enforce", "install-policy", "install-enforce-unknown",
                             "install-policy-unknown", "storage-write"}) {
        reset(false); boot_mode = true; failure = stage;
        assert(prepare_selinux_status_hooks(info) == KModErr::ERR_MODULE_STORAGE_READ);
        assert(!enforce_live && !policy_live && !creates && !refs && !releases && !closes && !saves);
        if (failure == "install-policy" || failure == "install-enforce-unknown") assert(removals == 1);
        if (failure == "install-policy-unknown" || failure == "storage-write") assert(removals == 2);
        // A pending disable never raw-frees the byte still referenced by code.
        if (installs) assert(memory.count(flag_address));
        ++cases;
    }
    reset(false); boot_mode = true; failure = "raw-init-mismatch";
    assert(prepare_selinux_status_hooks(info) == KModErr::ERR_MODULE_ASM && !installs);
    ++cases;
    for (const char* stage : {"storage-after-commit", "storage-commit-unreadable"}) {
        reset(false); boot_mode = true; failure = stage;
        assert(prepare_selinux_status_hooks(info) == KModErr::ERR_MODULE_STORAGE_READ);
        assert(enforce_live && policy_live && !removals && saves == 1 && storage["legacy216"].size() == 184);
        failure.clear();
        assert(prepare_selinux_status_hooks(next_process) == KModErr::OK && raw_allocations == 1 && installs == 2);
        assert(enable_selinux_status_hooks(next_process) == KModErr::OK);
        ++cases;
    }
    for (const char* stage : {"raw-enable-write", "raw-enable-read", "raw-enable-mismatch"}) {
        reset(false); boot_mode = true;
        assert(prepare_selinux_status_hooks(info) == KModErr::OK);
        failure = stage;
        const auto expected = failure == "raw-enable-mismatch" ? KModErr::ERR_MODULE_ASM : KModErr::ERR_MODULE_STORAGE_READ;
        assert(enable_selinux_status_hooks(info) == expected && !stores);
        ++cases;
    }
    reset(false); boot_mode = true;
    assert(prepare_selinux_status_hooks(info) == KModErr::OK);
    boot_mode = false;
    assert(prepare_selinux_status_hooks(next_process) == KModErr::ERR_MODULE_STORAGE_READ && !creates && installs == 2);
    ++cases;
    reset(false);
    assert(prepare_selinux_status_hooks(info) == KModErr::OK);
    boot_mode = true;
    assert(prepare_selinux_status_hooks(next_process) == KModErr::ERR_MODULE_STORAGE_READ && raw_allocations == 0 && installs == 2);
    ++cases;
    printf("PASS %u production shared-bool consumer groups: Owner/Legacy deps, creator release, rollback, pending receipt, old184 protection\n", cases);
}
