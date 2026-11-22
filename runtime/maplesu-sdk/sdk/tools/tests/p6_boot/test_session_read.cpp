#include "private/helper_core.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <string>

struct File {
    std::string bytes;
    bool regular = true;
    int read_override = -1;
};

namespace {
std::map<std::string, File> files;
std::map<int, File*> handles;
int next_fd, blocking_opens, writes, checks, mismatches;
const char current_boot[] = "11111111-2222-3333-4444-555555555555";
const char old_boot[] = "61111111-2222-3333-4444-555555555555\n";

int open_file(const char* path, helper_u32 flags, helper_u32) {
    const std::string name = path + std::strlen("/fixture/init");
    auto file = files.find(name);
    if (file == files.end()) {
        if (!(flags & HELPER_OPEN_CREATE)) return HELPER_E_NOENT;
        file = files.emplace(name, File{}).first;
    }
    if (!file->second.regular && !(flags & HELPER_OPEN_NONBLOCK)) {
        ++blocking_opens;
        return HELPER_E_AGAIN;  // Record would-block open without hanging the test runner.
    }
    handles[++next_fd] = &file->second;
    return next_fd;
}
int stat_file(int fd, helper_stat_info* stat) {
    const auto& file = *handles.at(fd);
    *stat = {};
    stat->size = file.bytes.size();
    stat->is_reg = file.regular;
    stat->nlink = 1;
    return HELPER_OK;
}
long long read_file(int fd, void* out, helper_u32 capacity) {
    const auto& file = *handles.at(fd);
    if (file.read_override < -1) return file.read_override;
    const size_t count = file.read_override >= 0 ? file.read_override : file.bytes.size();
    if (count > capacity || count > file.bytes.size()) return HELPER_E_OVERFLOW;
    std::memcpy(out, file.bytes.data(), count);
    return count;
}
long long write_file(int fd, const void* in, helper_u32 size) {
    ++writes;
    handles.at(fd)->bytes.assign(static_cast<const char*>(in), size);
    return size;
}
int close_file(int fd) { return handles.erase(fd) == 1 ? HELPER_OK : HELPER_E_INVAL; }
int sync_file(int) { return HELPER_OK; }

void check(bool test, const char* what) {
    ++checks;
    if (test) return;
    ++mismatches;
    std::printf("FAIL %s\n", what);
}
void scenario(const char* name, std::map<std::string, File> initial,
              int expected, int expected_action, int expected_writes) {
    files = std::move(initial);
    handles.clear();
    next_fd = blocking_opens = writes = 0;
    helper_context context{};
    std::strcpy(context.self_path, "/fixture/init");
    std::strcpy(context.boot_id, current_boot);
    context.ops.open_path = open_file;
    context.ops.fstat = stat_file;
    context.ops.read = read_file;
    context.ops.write = write_file;
    context.ops.close = close_file;
    context.ops.fsync = sync_file;
    int action = -1;
    const int result = helper_session_begin(&context, &action);
    std::printf("%s: rc=%d action=%d writes=%d blocking_opens=%d\n",
        name, result, action, writes, blocking_opens);
    check(result == expected, "status");
    check(action == expected_action, "action");
    check(writes == expected_writes, "state writes");
    check(blocking_opens == 0, "non-regular open does not block");
    check(handles.empty(), "all file descriptors closed");
}
}

extern "C" int maplesu_bootstrap_finish(const char*, helper_i64) { return HELPER_E_NOSYS; }

int main() {
    scenario("first boot, missing files", {}, HELPER_OK, HELPER_SESSION_NORMAL, 2);
    scenario("first boot, empty files", {{HELPER_SUFFIX_SAFE_FLAG, {""}},
             {HELPER_SUFFIX_DUPLICATE, {""}}}, HELPER_OK, HELPER_SESSION_NORMAL, 2);
    scenario("same boot, complete", {{HELPER_SUFFIX_SAFE_FLAG, {"2"}},
             {HELPER_SUFFIX_WORK, {std::string(current_boot) + "\n"}},
             {HELPER_SUFFIX_COMPLETED, {std::string(current_boot) + "\n"}}},
             HELPER_OK, HELPER_SESSION_COMPLETED, 0);
    scenario("previous failed boot, protection enabled", {{HELPER_SUFFIX_SAFE_FLAG, {"1"}},
             {HELPER_SUFFIX_DUPLICATE, {old_boot}}, {HELPER_SUFFIX_FAIL_PROTECT, {""}}},
             HELPER_OK, HELPER_SESSION_PROTECTED, 2);
    scenario("same incomplete boot, protection enabled", {{HELPER_SUFFIX_SAFE_FLAG, {"1"}},
             {HELPER_SUFFIX_DUPLICATE, {std::string(current_boot) + "\n"}},
             {HELPER_SUFFIX_FAIL_PROTECT, {""}}}, HELPER_E_AGAIN, HELPER_SESSION_NORMAL, 0);
    scenario("FIFO safe flag", {{HELPER_SUFFIX_SAFE_FLAG, {"", false}}},
             HELPER_E_INVAL, HELPER_SESSION_NORMAL, 0);
    scenario("FIFO protection file", {{HELPER_SUFFIX_SAFE_FLAG, {"3"}},
             {HELPER_SUFFIX_FAIL_PROTECT, {"", false}}}, HELPER_E_INVAL, HELPER_SESSION_NORMAL, 0);
    scenario("FIFO work receipt", {{HELPER_SUFFIX_WORK, {"", false}}},
             HELPER_E_INVAL, HELPER_SESSION_NORMAL, 0);
    scenario("FIFO completion receipt", {{HELPER_SUFFIX_SAFE_FLAG, {"2"}},
             {HELPER_SUFFIX_WORK, {std::string(current_boot) + "\n"}},
             {HELPER_SUFFIX_COMPLETED, {"", false}}}, HELPER_E_INVAL, HELPER_SESSION_NORMAL, 0);
    scenario("FIFO duplicate receipt", {{HELPER_SUFFIX_DUPLICATE, {"", false}}},
             HELPER_E_INVAL, HELPER_SESSION_NORMAL, 0);
    scenario("zero read on nonempty safe flag", {{HELPER_SUFFIX_SAFE_FLAG, {"1", true, 0}}},
             HELPER_E_IO, HELPER_SESSION_NORMAL, 0);
    scenario("short read on work receipt", {{HELPER_SUFFIX_WORK, {old_boot, true, 10}}},
             HELPER_E_IO, HELPER_SESSION_NORMAL, 0);
    scenario("short read on completion receipt", {{HELPER_SUFFIX_SAFE_FLAG, {"2"}},
             {HELPER_SUFFIX_WORK, {std::string(current_boot) + "\n"}},
             {HELPER_SUFFIX_COMPLETED, {old_boot, true, 10}}}, HELPER_E_IO, HELPER_SESSION_NORMAL, 0);
    scenario("short read on duplicate receipt", {{HELPER_SUFFIX_DUPLICATE, {old_boot, true, 10}}},
             HELPER_E_IO, HELPER_SESSION_NORMAL, 0);
    scenario("original negative read error", {{HELPER_SUFFIX_SAFE_FLAG, {"1", true, HELPER_E_ACCES}}},
             HELPER_E_ACCES, HELPER_SESSION_NORMAL, 0);
    std::printf("%d checks, %d mismatches\n", checks, mismatches);
    return mismatches != 0;
}
