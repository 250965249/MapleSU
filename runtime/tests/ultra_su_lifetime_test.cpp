#include "module_err_def.h"
#include "module_base_disk_storage.h"
#include "module_base_kernel_mem.h"
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <vector>

extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>&, const char*, bool);
KModErr maplesu_store_su_retention(const void* data, uint64_t size) {
    return kernel_module::write_blob_disk_storage("uid_retention_budget.20261105", data, size);
}
namespace {
constexpr uint64_t control = 0x1000;
uint64_t live, retired, next_address;
unsigned allocations;
std::map<uint64_t, std::vector<uint32_t>> memory;
std::map<std::string, std::vector<uint8_t>> storage;
std::set<uint64_t> published;
uint32_t target_uid;
std::string failure;
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
void reset() {
    live = 0x2000; retired = 0; next_address = 0x3000; allocations = 0;
    memory = {{live, {10001, 0}}}; storage.clear(); published = {live};
    target_uid = 10002; failure.clear();
}
KModErr update() { return maplesu_write_su_allowlist({"target"}, nullptr, true); }
}
namespace android_pkgmap {
std::unordered_map<std::string, uint32_t> read_pkg_uids_from_packages_list(
        const std::vector<std::string>&, const std::string&) { return {{"target", target_uid}}; }
}
namespace kernel_module {
KModErr read_uint64_disk_storage(const char* key, uint64_t& out) {
    out = std::string(key).find("next_free") == 0 ? retired : control;
    return KModErr::OK;
}
KModErr write_uint64_disk_storage(const char*, uint64_t value) { retired = value; return KModErr::OK; }
KModErr read_blob_disk_storage_with_cb(const char* key, void (*cb)(const void*, uint64_t)) {
    if (failure == "ledger_read") return KModErr::ERR_MODULE_STORAGE_READ;
    const auto found = storage.find(key);
    if (found == storage.end()) return KModErr::ERR_MODULE_STORAGE_NOT_FOUND;
    const auto& out = found->second;
    cb(out.data(), out.size()); return KModErr::OK;
}
KModErr write_blob_disk_storage(const char* key, const void* data, uint64_t size) {
    if (failure == "ledger_write") return KModErr::ERR_MODULE_STORAGE_WRITE;
    const auto* bytes = static_cast<const uint8_t*>(data);
    storage[key] = {bytes, bytes + size}; return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t address, void* out, uint32_t size) {
    if (address == control) { require(size == 8, "control width"); memcpy(out, &live, 8); }
    else {
        const auto entry = memory.upper_bound(address);
        require(entry != memory.begin(), "invalid table address");
        const auto& block = *std::prev(entry);
        const auto offset = address - block.first;
        require(offset + size <= block.second.size() * 4, "read past UID terminator allocation");
        memcpy(out, reinterpret_cast<const uint8_t*>(block.second.data()) + offset, size);
    }
    return KModErr::OK;
}
KModErr alloc_kernel_mem(uint32_t size, uint64_t& out) {
    out = next_address; next_address += 0x10000; ++allocations;
    memory[out].resize(size / 4); return KModErr::OK;
}
KModErr write_kernel_mem(uint64_t address, const void* data, uint32_t size, KernMemProt) {
    if (failure == "copy") return KModErr::ERR_MODULE_PARAM;
    memcpy(memory.at(address).data(), data, size); return KModErr::OK;
}
KModErr write_kernel_rw_mem_atomic64(uint64_t address, uint64_t value) {
    require(address == control, "publication address");
    if (failure == "publish") return KModErr::ERR_MODULE_PARAM;
    live = value; if (value) published.insert(value); return KModErr::OK;
}
KModErr free_kernel_mem(uint64_t address) {
    require(!published.count(address), "published table freed while a reader may be paused");
    memory.erase(address); return KModErr::OK;
}
}
int main() {
    unsigned failed = 0;
    for (const std::string test : {"paused_reader", "unchanged", "empty", "budget", "copy", "publish", "ledger_read", "ledger_write", "legacy_retired", "zero_ledger", "wrong_version", "wrong_size", "new_boot_ledger"}) {
        reset();
        try {
            if (test == "paused_reader") {
                const auto paused = live;
                require(!is_failed(update()), "first update"); ++target_uid;
                require(!is_failed(update()), "second update");
                require(memory.at(paused) == std::vector<uint32_t>({10001, 0}), "paused snapshot lost");
            } else if (test == "unchanged") {
                target_uid = 10001;
                require(!is_failed(update()) && allocations == 0 && live == 0x2000, "unchanged refresh allocated");
            } else if (test == "empty") {
                require(!is_failed(maplesu_write_su_allowlist({}, nullptr, true)), "clear failed");
                require(live == 0 && memory.count(0x2000), "clear released published snapshot");
            } else if (test == "budget") {
                unsigned accepted = 0;
                for (; accepted < 5000; ++accepted) {
                    ++target_uid; const auto before = live;
                    if (is_failed(update())) { require(live == before, "budget error changed live table"); --target_uid; break; }
                }
                require(accepted > 0 && accepted <= 4096, "retention is unbounded");
                const auto before_alloc = allocations;
                require(!is_failed(update()) && allocations == before_alloc, "unchanged table should survive exhausted budget");
            } else if (test == "legacy_retired") {
                retired = 0x2100; published.insert(retired); memory[retired] = {9999, 0};
                require(!is_failed(update()) && memory.count(0x2100), "legacy retired snapshot released");
            } else if (test == "zero_ledger" || test == "wrong_version" || test == "wrong_size") {
                auto& ledger = storage["uid_retention_budget.20261105"];
                ledger.assign(test == "wrong_size" ? 63 : 64, 0);
                if (test == "wrong_version") ledger[0] = 2;
                require(update() == KModErr::ERR_MODULE_STORAGE_TYPE && allocations == 0 && live == 0x2000,
                    "damaged ledger bypassed retention budget");
            } else if (test == "new_boot_ledger") {
                auto& ledger = storage["uid_retention_budget.20261105"];
                ledger.assign(64, 0);
                ledger[0] = 1;
                memset(ledger.data() + 4, 'x', 36);
                const uint64_t maximum = 16 * 1024 * 1024;
                const uint32_t generations = 4096;
                memcpy(ledger.data() + 40, &maximum, sizeof(maximum));
                memcpy(ledger.data() + 48, &generations, sizeof(generations));
                require(!is_failed(update()) && allocations == 1 && ledger[0] == 1,
                    "new boot did not reset a valid old boot ledger");
            } else {
                failure = test;
                require(is_failed(update()) && live == 0x2000, "failure changed live table");
                require(memory.size() == (test == "publish" ? 2 : 1), "allocation ownership lost");
            }
            printf("PASS %s\n", test.c_str());
        } catch (const std::exception& error) { ++failed; printf("FAIL %s: %s\n", test.c_str(), error.what()); }
    }
    return failed ? 1 : 0;
}
