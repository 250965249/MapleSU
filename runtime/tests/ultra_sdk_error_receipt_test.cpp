#include "sdk_error_receipt.h"
#include "module_base_kernel_mem.h"
#include "su_auth_result_private.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include "maplesu_sdk/maplesu_su_auth.h"

namespace default_modules::module_su_redirect { KModErr add_su_allowlist(const char*); }

namespace {
enum class Failure { None, Delivery, Persistence };
constexpr uint64_t old_table = 0x1000, new_table = 0x2000;
uint64_t live_table = old_table;
bool persisted = false, copies_open = false;
unsigned rollback_count = 0, restore_count = 0, thaw_count = 0;
Failure failure = Failure::None;

void reset(Failure next) {
    live_table = old_table;
    persisted = copies_open = false;
    rollback_count = restore_count = thaw_count = 0;
    failure = next;
}

void check_receipt(KModErr error, const char* expected_name) {
    auto* root = cJSON_CreateObject();
    assert(root);
    cJSON_AddBoolToObject(root, "ok", true);
    maplesu::ultra::write_sdk_error_receipt(root, error, "fixture reason");
    char* text = cJSON_PrintUnformatted(root);
    assert(text);
    auto* parsed = cJSON_Parse(text);
    assert(parsed);
    const auto* name = cJSON_GetObjectItemCaseSensitive(parsed, "sdkError");
    const auto* code = cJSON_GetObjectItemCaseSensitive(parsed, "sdkErrorCode");
    const auto* reason = cJSON_GetObjectItemCaseSensitive(parsed, "reason");
    assert(cJSON_IsString(name) && std::strcmp(name->valuestring, expected_name) == 0);
    assert(cJSON_IsNumber(code) && code->valuedouble == to_num(error));
    assert(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(parsed, "ok")));
    assert(cJSON_IsString(reason) && std::strcmp(reason->valuestring, "fixture reason") == 0);
    cJSON_Delete(parsed);
    cJSON_free(text);
    cJSON_Delete(root);
}
}

namespace kernel_module {
KModErr read_uint64_disk_storage(const char*, uint64_t& value) {
    value = 0x3000;
    return KModErr::OK;
}
KModErr read_kernel_mem(uint64_t address, void* output, uint32_t bytes) {
    assert(address == 0x3000 && bytes == sizeof(live_table));
    std::memcpy(output, &live_table, bytes);
    return KModErr::OK;
}
KModErr write_kernel_rw_mem_atomic64(uint64_t address, uint64_t value) {
    assert(address == 0x3000);
    ++rollback_count;
    live_table = value;
    return KModErr::OK;
}
}

namespace maplesu::sdk { KModErr get_root(const char*) { return KModErr::OK; } }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return "fixture"; }
extern "C" KModErr maplesu_prepare_su_exec(const char*) { return KModErr::OK; }
extern "C" KModErr maplesu_freeze_su_copies(const char*) {
    copies_open = false;
    return KModErr::OK;
}
extern "C" void maplesu_thaw_su_copies() { ++thaw_count; }
extern "C" KModErr maplesu_open_su_copies_from_control(const char*, uint64_t) {
    if (failure == Failure::Delivery) return KModErr::ERR_MODULE_WRITE_FILE;
    copies_open = true;
    return KModErr::OK;
}
extern "C" KModErr maplesu_sync_su_copies_from_control(const char*, uint64_t) {
    ++restore_count;
    copies_open = true;
    return KModErr::OK;
}
extern "C" KModErr maplesu_sdk_add_su_allowlist(const char*) {
    live_table = new_table;
    if (failure == Failure::Persistence) return KModErr::ERR_MODULE_WRITE_FILE;
    persisted = true;
    return KModErr::OK;
}
extern "C" KModErr maplesu_sdk_remove_su_allowlist(const char*) { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_clear_su_allowlist() { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_get_su_allowlist(void (*)(const maplesu::sdk::su_auth_item*)) { return KModErr::OK; }
extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>&, const char*, bool) { return KModErr::OK; }

namespace maplesu::su_auth::detail {
KModErr sdk_add(const char* package, ResultV1& result) {
    const auto error = maplesu_sdk_add_su_allowlist(package);
    return is_failed(error) ? fail(result, error, Phase::ActionPersist) : finish(result, error);
}
KModErr sdk_remove(const char* package, ResultV1& result) {
    return finish(result, maplesu_sdk_remove_su_allowlist(package));
}
KModErr sdk_clear(ResultV1& result) {
    return finish(result, maplesu_sdk_clear_su_allowlist());
}
KModErr write_allowlist(const std::vector<std::string>& packages, const char* package,
                      bool refresh, ResultV1& result) {
    return finish(result, maplesu_write_su_allowlist(packages, package, refresh));
}
}

int main() {
    reset(Failure::Delivery);
    const auto committed = default_modules::module_su_redirect::add_su_allowlist("fixture");
    assert(to_num(committed) == -21001);
    assert(live_table == new_table && persisted && !copies_open);
    assert(rollback_count == 0 && restore_count == 0 && thaw_count == 1);
    check_receipt(committed, "ERR_SU_DELIVERY_INCOMPLETE");
    assert(live_table == new_table && persisted && !copies_open && rollback_count == 0);
    std::cout << "PASS committed grant stays published/persisted and receipt requests delivery retry\n";

    failure = Failure::None;
    assert(is_ok(default_modules::module_su_redirect::add_su_allowlist("fixture")));
    assert(live_table == new_table && persisted && copies_open && rollback_count == 0);
    std::cout << "PASS delivery retry opens the committed grant\n";

    reset(Failure::Persistence);
    const auto uncommitted = default_modules::module_su_redirect::add_su_allowlist("fixture");
    assert(uncommitted == KModErr::ERR_MODULE_WRITE_FILE);
    assert(live_table == old_table && !persisted && copies_open);
    assert(rollback_count == 1 && restore_count == 1 && thaw_count == 1);
    check_receipt(uncommitted, "ERR_MODULE_WRITE_FILE");
    std::cout << "PASS persistence failure rolls back and keeps ordinary SDK receipt\n";

    check_receipt(static_cast<KModErr>(-21002), "ERR_BOOTSTRAP_NOT_READY");
    check_receipt(KModErr::ERR_MAPLESU_ENV_NOT_INSTALL, "ERR_MAPLESU_ENV_UNPREPARED");
    check_receipt(static_cast<KModErr>(-31999), "Unknown(-31999)");
    std::cout << "PASS bootstrap, environment and unknown errors retain numeric failure receipts\n";
}
