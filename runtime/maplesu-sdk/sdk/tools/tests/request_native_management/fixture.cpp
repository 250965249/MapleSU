// Execute the current provider resource helpers through its real legacy dispatcher.
#include <algorithm>
#include <set>
#include <vector>
#define MSU_MANAGEMENT_TASK_STATE_VERIFIED 1
#include "prefix.inc"
#include "execution_frame.h"

#define __user
#define PAGE_SHIFT 12
#define ALIGN(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
#define PAGE_ALIGN(value) ALIGN(value, PAGE_SIZE)
#define MSU_ICACHE_ADDRESS_LENGTH 1
#define __builtin_choose_expr(condition, yes, no) (yes)
// Production is C; this local variable happens to be a C++ keyword.
#define protected fixture_protected

static std::set<void*> buffers;
static std::vector<char> transitions;
static unsigned frees, calls, nx_count, fail_nx_at;
static bool fail_vm, copy_error, invalid_frame, fail_ro, fail_x;
static u64 call_result = UINT64_C(0xfedcba9876543210);
static void* vmalloc(size_t bytes) {
    if (fail_vm) return nullptr;
    void* result = std::malloc(bytes);
    assert(result && buffers.insert(result).second);
    std::memset(result, 0x5a, bytes);
    return result;
}
static void vfree(void* value) {
    assert(buffers.erase(value)); ++frees; std::free(value);
}
static void* msu_management_code_alloc(size_t bytes) { return vmalloc(bytes); }
static void msu_management_resource_free(struct msu_management_resource* resource) { vfree(resource->address); }
static int set_memory_nx(unsigned long, unsigned) {
    transitions.push_back('N'); return ++nx_count == fail_nx_at ? -EIO : 0;
}
static int set_memory_rw(unsigned long, unsigned) { transitions.push_back('W'); return 0; }
static int set_memory_ro(unsigned long, unsigned) { transitions.push_back('R'); return fail_ro ? -EACCES : 0; }
static int set_memory_x(unsigned long, unsigned) { transitions.push_back('X'); return fail_x ? -EPERM : 0; }
static int copy_from_user_nofault(void* output, const void* input, size_t bytes) {
    if (copy_error) return -EFAULT;
    std::memcpy(output, input, bytes); return 0;
}
static int copy_to_kernel_nofault(void* output, const void* input, size_t bytes) {
    std::memcpy(output, input, bytes); return 0;
}
static bool msu_management_branch(u64, u64, u32*) { return true; }
static bool msu_management_protected(u64, u64) { return false; }
static bool msu_management_user_range(u64 p, u32 bytes) { return p && bytes && p <= UINT64_MAX - (bytes - 1); }
static int msu_management_write_text(msu_management_session*, const maplesu_management_v3*, u32*, maplesu_response_owner_v3*) {
    std::abort();
}
static int msu_publication_cancel_session(msu_management_session*, u32*) { return 0; }
static int msu_shared_bool_close_session(msu_management_session*, u32*) { return 0; }
static int msu_uid_gateway_close(u64, u32*) { return 0; }
static struct mutex text_mutex;
static void sync_icache_aliases(void*, unsigned long) { transitions.push_back('I'); }
static u64 msu_management_call(void* address) {
    assert(buffers.count(address)); ++calls; transitions.push_back('C'); return call_result;
}
static unsigned replacement_calls, next_credential, task_state_calls;
static int replacement_error, task_state_error;
static bool replacement_commit, replacement_split, replacement_root;
static maplesu_caps_v3 replacement_caps;
static int msu_credential_replace_current(const maplesu_caps_v3* caps,
    int (*validate)(void*), void* context, u32* effects) {
    ++replacement_calls; *effects = 0;
    const int error = validate(context);
    if (error) return error;
    replacement_root = !caps;
    if (caps) replacement_caps = *caps;
    if (replacement_commit) {
        assert(next_credential < 4);
        const auto before = active_cred;
        active_cred = &credentials[next_credential++];
        real_cred = replacement_split ? before : active_cred;
        *effects = MAPLESU_EFFECT_COMMITTED;
    }
    return replacement_error;
}
static int msu_task_state_release_current(int (*validate)(void*), void* context,
    u32* effects, u64* previous_mode) {
    ++task_state_calls;
    const int error = validate(context);
    if (error) return error;
    *previous_mode = 2;
    *effects = MAPLESU_EFFECT_TASK_STATE_CHANGED;
    if (!task_state_error) *effects |= MAPLESU_EFFECT_TASK_STATE_COMPLETED;
    return task_state_error;
}
#include "functions.inc"
#include "legacy.inc"

static u64 scope, allocated;
static uint32_t length;
static maplesu_response_owner_v3 response;
static unsigned groups;
static void check(bool value, const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL group=%u check=%u: %s\n", groups, checks, message); std::abort(); }
}
static maplesu_management_v3 operation(u64 handle = 0) {
    maplesu_management_v3 result{}; result.host = management.host; result.session = scope; result.handle = handle; return result;
}
static int dispatch(u32 command, maplesu_management_v3 value) {
    const auto error = msu_legacy_hook_dispatch(scope, command, &value, &response);
    check(response.completion_magic == MAPLESU_RESPONSE_MAGIC && response.status == error &&
          response.command == command && response.length == sizeof(response), "complete native response shape");
    return error;
}
static void start() {
    ++groups;
    check(buffers.empty() && !management.live_sessions, "previous lifecycle has no owned allocations or sessions");
    management = {}; management.ready = true; management.host = {1, 2}; management.next_session = management.next_resource = 1;
    check(std::all_of(credentials, credentials + 4, [](const cred& value) { return !value.refs; }),
          "previous lifecycle balances every original and replacement credential");
    for (auto& value : credentials) value = {};
    active_cred = real_cred = &credentials[0]; task = {}; task.mm = &mm0;
    fixture_caller = UINT64_C(0xffff000000001010); current = &task;
    sleepable = true; nofault = fail_alloc = false; helper_error = 0;
    transitions.clear(); frees = calls = nx_count = fail_nx_at = 0;
    fail_vm = copy_error = invalid_frame = fail_ro = fail_x = false;
    replacement_calls = task_state_calls = credential_calls = procattr_calls = 0;
    next_credential = 1; replacement_error = task_state_error = 0;
    replacement_commit = true; replacement_split = replacement_root = false; replacement_caps = {};
    const u64 gateway = msu_legacy_hook_bind(fixture_caller - 16, 64);
    check(gateway != 0 && (scope = msu_legacy_hook_begin(gateway)), "real bind and begin establish a producer scope");
    auto open = operation(); open.session = 0;
    check(!dispatch(MAPLESU_REQUEST_SESSION_OPEN, open) && response.result == scope, "real provider opens the scope session");
}
static void close() {
    auto value = operation(); value.session = 0;
    check(!dispatch(MAPLESU_REQUEST_SESSION_CLOSE, value) &&
          (response.metadata_length & MAPLESU_EFFECT_SESSION_CLOSED), "real close releases this scope");
    check(!msu_legacy_hook_end(scope) && !management.live_sessions && !task.refs && !mm0.refs &&
          std::all_of(credentials, credentials + 4, [](const cred& value) { return !value.refs; }),
          "scope, task, mm and cred references balance after close");
}
static std::vector<uint8_t> frame() {
    const uint32_t prefix[] = {0xd503245f, 0xa9bf53f3, 0xa9bf5bf5, 0xa9bf63f7,
        0xa9bf6bf9, 0xa9bf73fb, 0xa9bf7bfd, 0x14000005};
    const uint32_t suffix[] = {0xa8c17bfd, 0xa8c173fb, 0xa8c16bf9, 0xa8c163f7,
        0xa8c15bf5, 0xa8c153f3, 0xd65f03c0};
    std::vector<uint8_t> result(100);
    const maplesu_execution_marker begin{MAPLESU_FRAME_MAGIC, 1, 16, MAPLESU_FRAME_BEGIN, 0};
    const maplesu_execution_marker end{MAPLESU_FRAME_MAGIC, 1, 16, MAPLESU_FRAME_U64, 0};
    const uint32_t branch = 0x14000005, move = 0xaa0003e0;
    std::memcpy(result.data(), prefix, sizeof(prefix)); std::memcpy(result.data() + 32, &begin, sizeof(begin));
    std::memcpy(result.data() + 48, &branch, 4); std::memcpy(result.data() + 52, &end, sizeof(end));
    std::memcpy(result.data() + 68, &move, 4); std::memcpy(result.data() + 72, suffix, sizeof(suffix));
    return result;
}
static void allocate(uint32_t bytes) {
    auto value = operation(); value.length = bytes;
    check(!dispatch(MAPLESU_REQUEST_ALLOC, value) && response.result && response.metadata_address &&
          response.metadata_length == MAPLESU_EFFECT_ALLOCATED, "actual ALLOC publishes one owned buffer and handle");
    allocated = response.metadata_address; length = bytes;
    check(management.resources[0].reserved && management.resources[0].session &&
          management.resources[0].bytes == bytes && !management.resources[0].uploaded,
          "actual allocator creates the live resource metadata");
}
static void upload(const std::vector<uint8_t>& bytes) {
    auto value = operation(allocated); value.data_user = reinterpret_cast<uintptr_t>(bytes.data()); value.length = bytes.size();
    check(!dispatch(MAPLESU_REQUEST_WRITE, value) && response.result == bytes.size() &&
          response.metadata_length == MAPLESU_EFFECT_WRITTEN, "actual WRITE uploads the complete frame");
}
static maplesu_management_v3 exec_operation() { auto value = operation(allocated); value.length = length; return value; }
int main() {
    auto bytes = frame(); check(maplesu_standard_frame_valid(bytes.data(), bytes.size()), "fixture is a real complete standard frame");
    start(); allocate(bytes.size()); upload(bytes); transitions.clear();
    check(!dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) && response.result == call_result &&
          response.metadata_length == (MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_RELEASED), "actual EXEC preserves the full result and release facts");
    check(transitions == std::vector<char>({'R', 'X', 'I', 'C', 'N', 'W'}) && calls == 1 && !management.resources[0].reserved,
          "actual EXEC protects, validates, publishes, calls, then frees in order");
    check(dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) == -ESTALE && calls == 1, "actual resource cannot execute twice"); close();
    start(); allocate(bytes.size());
    check(dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) == -EINVAL && !calls && buffers.empty() &&
          response.metadata_length == MAPLESU_EFFECT_RELEASED, "incomplete upload consumes/releases without executing"); close();
    start(); allocate(bytes.size()); auto invalid = bytes; invalid[0] ^= 1; upload(invalid);
    check(dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) == -EINVAL && !calls && buffers.empty(), "bad complete frame never becomes executable");
    check(std::find(transitions.begin(), transitions.end(), 'X') == transitions.end(), "frame rejection precedes X permission"); close();
    for (int failure = 0; failure < 2; ++failure) {
        start(); allocate(bytes.size()); upload(bytes); fail_ro = !failure; fail_x = failure;
        check(dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) == (failure ? -EPERM : -EACCES) && !calls && buffers.empty() &&
              response.metadata_length == MAPLESU_EFFECT_RELEASED, "permission failure preserves its first error and releases once"); close();
    }
    start(); allocate(bytes.size()); upload(bytes); fail_nx_at = nx_count + 1; const auto freed_before = frees;
    check(dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) == -EIO && calls == 1 && response.result == call_result &&
          response.metadata_length == (MAPLESU_EFFECT_EXECUTED | MAPLESU_EFFECT_QUARANTINED), "post-execution failure keeps full result and quarantine fact");
    check(management.resources[0].quarantined && !management.resources[0].session && frees == freed_before,
          "quarantine is detached and retains its resource allocation");
    close(); for (void* p : buffers) std::free(p); buffers.clear();
    start(); allocate(bytes.size()); auto release = operation(allocated);
    check(!dispatch(MAPLESU_REQUEST_RELEASE, release) && buffers.empty() && response.metadata_length == MAPLESU_EFFECT_RELEASED,
          "actual explicit release frees once");
    check(dispatch(MAPLESU_REQUEST_RELEASE, release) == -ESTALE && frees == 1, "actual duplicate release is stale"); close();
    start(); fail_vm = true; auto value = operation(); value.length = 100;
    check(dispatch(MAPLESU_REQUEST_ALLOC, value) == -ENOMEM && !response.result && !response.metadata_address &&
          !management.resources[0].reserved, "allocator failure clears its reserved slot and output"); fail_vm = false; close();
    start(); fail_nx_at = 1; value = operation(); value.length = 100;
    check(dispatch(MAPLESU_REQUEST_ALLOC, value) == -EIO && !response.result && !response.metadata_address && buffers.empty() &&
          response.metadata_length == (MAPLESU_EFFECT_ALLOCATED | MAPLESU_EFFECT_RELEASED), "ALLOC transition failure cleans its actual allocation"); close();
    start(); allocate(bytes.size()); copy_error = true; value = operation(allocated); value.length = bytes.size(); value.data_user = reinterpret_cast<uintptr_t>(bytes.data());
    check(dispatch(MAPLESU_REQUEST_WRITE, value) == -EFAULT && !management.resources[0].uploaded &&
          !response.result && !response.metadata_length, "failed user copy publishes no upload or write fact"); copy_error = false; close();
    start(); allocate(bytes.size()); value = operation(allocated); value.length = 1; value.address = 1; value.data_user = reinterpret_cast<uintptr_t>(bytes.data());
    check(dispatch(MAPLESU_REQUEST_WRITE, value) == -EINVAL && !management.resources[0].uploaded, "upload hole is rejected before copying");
    value = operation(); value.length = 0; check(dispatch(MAPLESU_REQUEST_ALLOC, value) == -EINVAL, "actual shape rejects zero allocation length");
    value.length = 1; value.reserved = 1; check(dispatch(MAPLESU_REQUEST_ALLOC, value) == -EINVAL, "actual shape rejects reserved fields"); close();
    start(); allocate(bytes.size()); upload(bytes); check(!msu_legacy_hook_end(scope), "END leaves an opened session idle");
    check(dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) == -EPERM && !calls, "idle scope cannot execute");
    check(msu_legacy_hook_begin(1) == scope, "producer BEGIN resumes its same task scope");
    check(!dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) && calls == 1, "resumed authenticated scope executes its own allocation"); close();
    start();
    check(!dispatch(MAPLESU_REQUEST_CRED_ROOT, operation()) && replacement_calls == 1 && replacement_root &&
          response.metadata_length == MAPLESU_EFFECT_COMMITTED && management.sessions[0]->active == &credentials[1] &&
          credentials[0].refs == 1 && credentials[1].refs == 1, "real ROOT session helper adopts the exact committed credential");
    const maplesu_caps_v3 caps{1, 3, 1, 7, 0}; value = operation();
    value.data_user = reinterpret_cast<uintptr_t>(&caps); value.length = sizeof(caps);
    check(!dispatch(MAPLESU_REQUEST_CRED_CAPS, value) && replacement_calls == 2 && !replacement_root &&
          !std::memcmp(&replacement_caps, &caps, sizeof(caps)) && management.sessions[0]->active == &credentials[2] &&
          credentials[0].refs == 1 && !credentials[1].refs && credentials[2].refs == 1,
          "real CAPS helper copies the payload and rotates only the session's active credential reference");
    const char context[] = "u:r:su:s0"; value = operation(); value.address = MAPLESU_PROCATTR_CURRENT;
    value.data_user = reinterpret_cast<uintptr_t>(context); value.length = sizeof(context) - 1;
    check(!dispatch(MAPLESU_REQUEST_CRED_PROCATTR, value) && procattr_calls == 1,
          "real Key dispatcher routes controlled procattr requests to the existing helper");
    check(!dispatch(MAPLESU_REQUEST_TASK_STATE, operation()) && task_state_calls == 1 && response.result == 2 &&
          response.metadata_length == (MAPLESU_EFFECT_TASK_STATE_CHANGED | MAPLESU_EFFECT_TASK_STATE_COMPLETED),
          "real Key dispatcher preserves task-state completion and previous mode");
    allocate(bytes.size()); upload(bytes);
    check(!dispatch(MAPLESU_REQUEST_EXEC, exec_operation()) && calls == 1,
          "credential replacement retains the authenticated session's executable consumer"); close();
    start(); replacement_commit = false; replacement_error = -EPERM;
    check(dispatch(MAPLESU_REQUEST_CRED_ROOT, operation()) == -EPERM && !response.metadata_length &&
          management.sessions[0]->active == &credentials[0] && credentials[0].refs == 2,
          "precommit credential rejection retains the original session and first error"); close();
    start(); copy_error = true; value = operation(); value.data_user = reinterpret_cast<uintptr_t>(&caps); value.length = sizeof(caps);
    check(dispatch(MAPLESU_REQUEST_CRED_CAPS, value) == -EFAULT && !replacement_calls && !response.metadata_length,
          "CAPS user-copy failure never invokes replacement or publishes a commit"); copy_error = false; close();
    for (int failure = 0; failure < 2; ++failure) {
        start(); replacement_error = failure ? 0 : -EIO; replacement_split = failure;
        check(dispatch(MAPLESU_REQUEST_CRED_ROOT, operation()) == (failure ? -ESTALE : -EIO) &&
              response.metadata_length == (MAPLESU_EFFECT_COMMITTED | MAPLESU_EFFECT_SESSION_CLOSED),
              "committed credential failure keeps its irreversible fact and retires the session");
        check(!msu_legacy_hook_end(scope) && !management.live_sessions && !task.refs && !mm0.refs &&
              std::all_of(credentials, credentials + 4, [](const cred& item) { return !item.refs; }),
              "postcommit error balances original and replacement references without a second close");
    }
    start(); task_state_error = -EIO;
    check(dispatch(MAPLESU_REQUEST_TASK_STATE, operation()) == -EIO && response.result == 2 &&
          response.metadata_length == MAPLESU_EFFECT_TASK_STATE_CHANGED && task_state_calls == 1,
          "task-state failure preserves the partial change, mode and exact first error"); close();
    std::printf("native management groups=%u checks=%u passed; actual resource helpers, explicit OS/JIT seams\n", groups, checks);
    return 0;
}
