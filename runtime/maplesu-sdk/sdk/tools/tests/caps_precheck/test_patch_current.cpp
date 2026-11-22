// Link the actual patch_current.cpp TU; no generated instruction runs on a kernel.
#include "kernel_module_kit_umbrella.h"
#include "default_modules_module_root_patch_base.h"
#include "maplesu_caps_private.h"
#include "maplesu_request_private.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <sched.h>

namespace {
struct Fixture {
    KModErr offset_error = KModErr::OK, snapshot_error = KModErr::OK;
    KModErr execute_error = KModErr::OK, saved_error = KModErr::OK;
    bool ambient = true, managed = false;
    KModErr channel_error = KModErr::OK;
    uint64_t capabilities = 0;
    uint64_t maximum = 0x1ffffffffffULL;
    unsigned offsets = 0, snapshots = 0, maxima = 0, executions = 0, saved = 0, counts = 0;
    unsigned typed_roots = 0, typed_caps = 0, typed_tasks = 0, channels = 0;
    unsigned legacy_frames = 0, vector_calls = 0;
    maplesu_caps_v3 typed_value{};
} fixture;
unsigned checks = 0, failures = 0;
void check(bool passed, const char* message) {
    ++checks;
    if (!passed) { ++failures; std::fprintf(stderr, "FAIL: %s\n", message); }
}
void reset() { fixture = {}; current_test::builds = 0; current_test::stores.clear(); current_test::cap_offset = UINT64_MAX; }
}

extern "C" int __wrap_sched_getaffinity(pid_t, size_t, cpu_set_t*) { errno = EPERM; return -1; }
namespace kernel_module {
bool maplesu_request_owner_mode() { return fixture.managed; }
KModErr maplesu_request_credential_channel(bool& managed, uint64_t& capabilities) {
    ++fixture.channels;
    managed = fixture.managed;
    capabilities = fixture.capabilities;
    return fixture.channel_error;
}
KModErr maplesu_request_owner_root() { ++fixture.typed_roots; return fixture.execute_error; }
KModErr maplesu_request_owner_task_state() { ++fixture.typed_tasks; return fixture.execute_error; }
KModErr maplesu_request_owner_caps(const maplesu_caps_v3& value) {
    ++fixture.typed_caps; fixture.typed_value = value; return fixture.execute_error;
}
KModErr get_cred_cap_inheritable_offset(uint32_t& offset) {
    ++fixture.offsets; offset = 40; return fixture.offset_error;
}
KModErr get_current_caps_snapshot(caps_info& out, bool& ambient) {
    ++fixture.snapshots; out = {}; ambient = fixture.ambient; return fixture.snapshot_error;
}
uint64_t get_cap_ability_max() { ++fixture.maxima; return fixture.maximum; }
int get_caps_cnt() { ++fixture.counts; return fixture.ambient ? 5 : 4; }
KModErr request_kernel_set_suid_sgid(uint32_t, uint32_t) {
    ++fixture.saved; return fixture.saved_error;
}
KModErr execute_kernel_asm_func(const std::vector<uint8_t>&, uint64_t&) {
    ++fixture.vector_calls; return KModErr::ERR_MODULE_ASM;
}
KModErr maplesu_execute_legacy_credential_frame(const uint8_t*, uint32_t, uint64_t&) {
    ++fixture.executions; ++fixture.legacy_frames; return fixture.execute_error;
}
}
namespace default_modules::module_root {
// Existing shared 16-byte ABI; these base stubs avoid linking unrelated Hook code.
PatchBase::PatchBase(uint32_t cred, uint32_t usage, uint32_t securebits, uint32_t caps)
    : m_cred_offset(cred), m_cred_atomic_usage_size(usage),
      m_cred_securebits_offset(securebits), m_cred_cap_effective_offset(caps) {}
PatchBase::PatchBase(const PatchBase&) = default;
PatchBase::~PatchBase() = default;
int PatchBase::get_cred_atomic_usage_size() { return m_cred_atomic_usage_size; }
class PatchCurrent : public PatchBase {
public:
    explicit PatchCurrent(const PatchBase&);
    ~PatchCurrent();
    int get_need_write_cap_cnt();
    KModErr set_current_root(uint32_t);
    KModErr set_current_caps(const kernel_module::caps_info&);
};
static_assert(sizeof(PatchCurrent) == 16 && alignof(PatchCurrent) == 4);
}

int main() {
    using namespace default_modules::module_root;
    const PatchBase base(512, 4, 36, 48);
    PatchCurrent current(base);
    const kernel_module::caps_info requested{1, 2, 3, 4, 5};
    for (const auto error : {KModErr::ERR_MODULE_OPEN_FILE, KModErr::ERR_MODULE_READ_FILE,
                            KModErr::ERR_MODULE_GET_CAPS}) {
        reset(); fixture.snapshot_error = error;
        check(current.set_current_caps(requested) == error, "snapshot error remains exact");
        check(fixture.offsets == 0 && fixture.snapshots == 1 && fixture.counts == 0 &&
              current_test::builds == 0 && current_test::stores.empty() && fixture.executions == 0,
              "failed snapshot emits and executes no capability writes");
    }
    reset(); fixture.offset_error = KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    check(current.set_current_caps(requested) == KModErr::OK && fixture.offsets == 0 &&
          fixture.snapshots == 1 && fixture.executions == 1 && current_test::cap_offset == 48,
          "caps reuse the validated Base offset without another BTF getter");
    for (const bool ambient : {false, true}) {
        reset(); fixture.ambient = ambient;
        check(current.set_current_caps(requested) == KModErr::OK, "valid snapshot writes requested caps");
        check(fixture.snapshots == 1 && fixture.counts == 0 && fixture.executions == 1 &&
              fixture.legacy_frames == 1 && fixture.vector_calls == 0 &&
              current_test::builds == 1 && current_test::stores.size() == (ambient ? 5U : 4U),
              "one snapshot selects four or five writes without legacy count");
        for (size_t i = 0; i < current_test::stores.size(); ++i)
            check(current_test::stores[i] == i + 1, "caller capability values remain unchanged");
    }
    reset(); fixture.execute_error = KModErr::ERR_MODULE_ASM;
    check(current.set_current_caps(requested) == fixture.execute_error && fixture.executions == 1,
          "existing executor error remains exact without retry");
    reset(); fixture.maximum = 0;
    check(current.set_current_root(1024) == KModErr::ERR_MODULE_CAP_ABILITY, "zero maximum is an error");
    check(fixture.executions == 1 && fixture.saved == 1 && fixture.maxima == 1 &&
          fixture.snapshots == 0 && current_test::builds == 1,
          "original root actions precede maximum; no false rollback or second write");
    reset(); fixture.execute_error = KModErr::ERR_MODULE_ASM;
    check(current.set_current_root(1024) == fixture.execute_error && fixture.maxima == 0 &&
          fixture.saved == 0, "initial root execution failure precedes maximum probe");
    reset(); fixture.saved_error = KModErr::ERR_MODULE_NO_BOOT;
    check(current.set_current_root(1024) == fixture.saved_error && fixture.maxima == 0 &&
          fixture.snapshots == 0, "saved-ID failure preserves existing ordering");
    reset(); fixture.snapshot_error = KModErr::ERR_MODULE_READ_FILE;
    check(current.set_current_root(1024) == fixture.snapshot_error && fixture.executions == 1 &&
          fixture.saved == 1 && fixture.maxima == 1 && fixture.snapshots == 1 &&
          current_test::builds == 1, "later snapshot failure stops caps phase; earlier root actions remain");
    reset();
    check(current.set_current_root(1024) == KModErr::OK && fixture.executions == 2 &&
          fixture.saved == 1 && fixture.maxima == 1 && fixture.snapshots == 1 && fixture.counts == 0 &&
          fixture.offsets == 0 && current_test::cap_offset == 48,
          "successful root retains ordering with one capability snapshot");
    reset();
    check(current.get_need_write_cap_cnt() == 5 && fixture.counts == 1,
          "external count method remains an explicit compatibility ABI");
    reset(); fixture.managed = true;
    fixture.capabilities = MAPLESU_CAP_CREDENTIAL | MAPLESU_CAP_TASK_STATE;
    check(current.set_current_root(1024) == KModErr::OK &&
          current.set_current_caps(requested) == KModErr::OK,
          "owner root and caps select typed handlers");
    check(fixture.channels == 2 && fixture.typed_roots == 1 && fixture.typed_caps == 1 &&
          fixture.typed_tasks == 1 && fixture.executions == 0 &&
          fixture.legacy_frames == 0 && fixture.vector_calls == 0 && fixture.offsets == 0 &&
          fixture.snapshots == 0 && fixture.saved == 0 && fixture.maxima == 0 && current_test::builds == 0,
          "owner path avoids legacy credential writes and saved-ID operations");
    check(fixture.typed_value.inheritable == requested.inheritable &&
          fixture.typed_value.permitted == requested.permitted && fixture.typed_value.effective == requested.effective &&
          fixture.typed_value.bounding == requested.bounding && fixture.typed_value.ambient == requested.ambient,
          "typed caps preserve every capability field");
    reset(); fixture.managed = true; fixture.capabilities = MAPLESU_CAP_CREDENTIAL | MAPLESU_CAP_TASK_STATE;
    fixture.execute_error = KModErr::ERR_MODULE_CRED_DANGER;
    check(current.set_current_root(1024) == fixture.execute_error &&
          current.set_current_caps(requested) == fixture.execute_error && fixture.typed_roots == 1 &&
          fixture.typed_caps == 1 && fixture.typed_tasks == 0 && fixture.executions == 0 && current_test::builds == 0,
          "typed errors remain exact and never fall through to compatibility");
    reset(); fixture.channel_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    check(current.set_current_root(1024) == fixture.channel_error &&
          current.set_current_caps(requested) == fixture.channel_error && fixture.channels == 2 &&
          fixture.typed_roots == 0 && fixture.typed_caps == 0 && fixture.typed_tasks == 0 &&
          fixture.executions == 0 && fixture.saved == 0 && current_test::builds == 0,
          "credential-channel errors never fall through to legacy writes");
    reset(); fixture.managed = true; fixture.capabilities = MAPLESU_CAP_TASK_STATE;
    check(current.set_current_root(1024) == KModErr::ERR_MODULE_TEST_CHANNEL &&
          fixture.typed_roots == 0 && fixture.typed_tasks == 0 && fixture.executions == 0 &&
          current_test::builds == 0,
          "managed root requires credential and task-state capabilities before dispatch");
    reset(); fixture.managed = true; fixture.capabilities = MAPLESU_CAP_TASK_STATE;
    check(current.set_current_caps(requested) == KModErr::ERR_MODULE_TEST_CHANNEL &&
          fixture.typed_caps == 0 && fixture.executions == 0 && current_test::builds == 0,
          "managed caps requires credential capability before dispatch");
    std::printf("patch-current-caps: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
