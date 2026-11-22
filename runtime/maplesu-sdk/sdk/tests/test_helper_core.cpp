// Host test for the boot helper's transaction logic.
//
// The production syscall binding is `helper_platform_android.cpp`; this file
// supplies an in-memory filesystem, a recording process runner and a fake
// dynamic loader through the same `struct helper_ops` table.  The helper
// sources themselves are included unmodified, so the tested code is exactly the
// code that is compiled for AArch64.
//
// Build (wasm32, no libc) and execute with `run_helper_test.py`.
#include "../../src/helper/helper_text.cpp"
#include "../../src/helper/helper_session.cpp"
#include "../../src/helper/helper_policy.cpp"
#include "../../src/helper/helper_properties.cpp"
#include "../../src/helper/helper_su.cpp"
#include "../../src/helper/helper_boot.cpp"

// Reported to the JavaScript driver; the driver prints the buffers it receives.
extern "C" void test_report(const char* text, int length);

extern "C" const char maplesu_helper_root_key_token[4096] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl";

namespace {

// ---------------------------------------------------------------- fixtures --
const char kKey[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl";
const char kDataDir[] = "/data/ABCDEFGHIJKLMNOPA";
const char kSelfPath[] = "/data/ABCDEFGHIJKLMNOPA/init";
const char kBootId[] = "11111111-2222-3333-4444-555555555555";
const char kPackagesList[] = "com.example.app 10001\ncom.example.other 10002\n";
const char kCanonicalImage[] = "#!/system/bin/su\nfixture-image\n";
const char kBackendPath[] = "/data/adb/maplesu/bin/libmaplesu_policy_boot.so";
const char kAllowlistPath[] = "/data/ABCDEFGHIJKLMNOPA/su_allowlist.txt";
const char kSafeFlag[] = "/data/ABCDEFGHIJKLMNOPA/init.safe_flag";
const char kDuplicate[] = "/data/ABCDEFGHIJKLMNOPA/init.boot_session.duplicate";
const char kCompleted[] = "/data/ABCDEFGHIJKLMNOPA/init.boot_session.completed";
const char kWork[] = "/data/ABCDEFGHIJKLMNOPA/init.boot_session.work";
const char kProtect[] = "/data/ABCDEFGHIJKLMNOPA/init.boot_fail_protect";
const char kLock[] = "/data/ABCDEFGHIJKLMNOPA/init.running.lock";
const char kPrivate[] = "/data/ABCDEFGHIJKLMNOPA/u-00000000";
const char kPrivateImage[] = "/data/ABCDEFGHIJKLMNOPA/u-00000000/su";
const char kDelivery10001[] = "/data/ABCDEFGHIJKLMNOPA/u-00002711";
const char kDelivery10002[] = "/data/ABCDEFGHIJKLMNOPA/u-00002712";

enum { kMaxNodes = 64, kMaxPath = 512, kMaxFile = 8192, kMaxFds = 64, kMaxLog = 8192,
       kMaxCommands = 16, kMaxReport = 16384 };

struct Node {
    char path[kMaxPath];
    int used;
    int is_dir;
    unsigned int uid;
    unsigned int gid;
    unsigned int mode;
    unsigned int nlink;
    unsigned int size;
    char data[kMaxFile];
    char xattr[128];
};

struct FakeFileSystem {
    Node nodes[kMaxNodes];
    int node_count;
    int fd_node[kMaxFds];
    long long fd_offset[kMaxFds];
    int uid;
    int euid;
    int pid;
    int lock_fails;
    int policy_symbol_missing;
    int policy_status;
    int aborted;
    int exec_calls;
    char exec_path[kMaxPath];
    char exec_argv0[128];
    char exec_argv1[128];
    char exec_env0[512];
    char exec_env1[512];
    int shell_calls;
    char shell_commands[kMaxCommands][256];
    int log_length;
    char log[kMaxLog];
    int policy_calls;
    char policy_key[64];
    int report_length;
    char report[kMaxReport];

    void reset() {
        node_count = 0;
        for (int index = 0; index < kMaxFds; ++index) {
            fd_node[index] = -1;
            fd_offset[index] = 0;
        }
        uid = 0;
        euid = 0;
        pid = 4242;
        lock_fails = 0;
        policy_symbol_missing = 0;
        policy_status = 0;
        aborted = 0;
        exec_calls = 0;
        exec_path[0] = '\0';
        exec_argv0[0] = '\0';
        exec_argv1[0] = '\0';
        exec_env0[0] = '\0';
        exec_env1[0] = '\0';
        shell_calls = 0;
        log_length = 0;
        log[0] = '\0';
        policy_calls = 0;
        policy_key[0] = '\0';
        report_length = 0;
        report[0] = '\0';
    }
};

FakeFileSystem g_fs;

int text_length(const char* text) {
    int length = 0;
    while (text[length] != '\0') ++length;
    return length;
}

int text_equal(const char* left, const char* right) {
    int index = 0;
    while (left[index] == right[index]) {
        if (left[index] == '\0') return 1;
        ++index;
    }
    return 0;
}

void text_copy(char* out, int capacity, const char* text) {
    int index = 0;
    while (text[index] != '\0' && index + 1 < capacity) {
        out[index] = text[index];
        ++index;
    }
    out[index] = '\0';
}

char g_report[kMaxReport];
int g_report_length = 0;

void append_report(const char* text) {
    const int length = text_length(text);
    if (g_report_length + length + 2 >= kMaxReport) return;
    for (int index = 0; index < length; ++index) g_report[g_report_length++] = text[index];
    g_report[g_report_length++] = '\n';
    g_report[g_report_length] = '\0';
}

int find_node(const char* path) {
    for (int index = 0; index < g_fs.node_count; ++index)
        if (g_fs.nodes[index].used && text_equal(g_fs.nodes[index].path, path)) return index;
    return -1;
}

int make_node(const char* path, int is_dir, unsigned int uid, unsigned int gid,
              unsigned int mode) {
    if (g_fs.node_count >= kMaxNodes) return -1;
    Node& node = g_fs.nodes[g_fs.node_count];
    node.used = 1;
    node.is_dir = is_dir;
    node.uid = uid;
    node.gid = gid;
    node.mode = mode;
    node.nlink = is_dir ? 2u : 1u;
    node.size = 0;
    node.xattr[0] = '\0';
    text_copy(node.path, kMaxPath, path);
    return g_fs.node_count++;
}

int make_file(const char* path, const char* content, unsigned int uid, unsigned int gid,
              unsigned int mode) {
    const int index = make_node(path, 0, uid, gid, mode);
    if (index < 0) return index;
    const int length = text_length(content);
    for (int position = 0; position < length; ++position)
        g_fs.nodes[index].data[position] = content[position];
    g_fs.nodes[index].size = static_cast<unsigned int>(length);
    return index;
}

int make_dir(const char* path, unsigned int uid, unsigned int gid, unsigned int mode) {
    return make_node(path, 1, uid, gid, mode);
}

// -------------------------------------------------------------- fake ops ----
int fake_getuid(void) { return g_fs.uid; }
int fake_geteuid(void) { return g_fs.euid; }
int fake_getpid(void) { return g_fs.pid; }
void fake_abort(void) { g_fs.aborted = 1; }

int fake_read_self_path(char* out, helper_u32 capacity, helper_u32* length) {
    (void)capacity;
    text_copy(out, kMaxPath, kSelfPath);
    *length = static_cast<helper_u32>(text_length(kSelfPath));
    return HELPER_OK;
}

int fake_read_boot_id(char* out, helper_u32 capacity, helper_u32* length) {
    (void)capacity;
    text_copy(out, 37, kBootId);
    *length = HELPER_BOOT_ID_LEN;
    return HELPER_OK;
}

int fake_open_flags_to_node(const char* path, helper_u32 flags) {
    int node = find_node(path);
    if (node >= 0 && (flags & HELPER_OPEN_EXCL) != 0) return HELPER_E_EXIST;
    if (node < 0) {
        if ((flags & HELPER_OPEN_CREATE) == 0) return HELPER_E_NOENT;
        node = make_file(path, "", 0, 0, 0600);
    }
    if (node < 0) return HELPER_E_NOSPC;
    if ((flags & HELPER_OPEN_DIRECTORY) != 0 && !g_fs.nodes[node].is_dir) return HELPER_E_NOTDIR;
    if ((flags & HELPER_OPEN_DIRECTORY) == 0 && g_fs.nodes[node].is_dir)
        return HELPER_E_ISDIR;
    for (int fd = 3; fd < kMaxFds; ++fd) {
        if (g_fs.fd_node[fd] < 0) {
            g_fs.fd_node[fd] = node;
            g_fs.fd_offset[fd] = 0;
            return fd;
        }
    }
    return HELPER_E_MFILE;
}

int fake_open_path(const char* path, helper_u32 flags, helper_u32 mode) {
    (void)mode;
    return fake_open_flags_to_node(path, flags);
}

int fake_openat(int dirfd, const char* name, helper_u32 flags, helper_u32 mode) {
    (void)mode;
    if (dirfd < 0 || dirfd >= kMaxFds || g_fs.fd_node[dirfd] < 0) return HELPER_E_INVAL;
    char path[kMaxPath];
    const char* base = g_fs.nodes[g_fs.fd_node[dirfd]].path;
    text_copy(path, kMaxPath, base);
    int length = text_length(path);
    if (length + 1 + text_length(name) >= kMaxPath) return HELPER_E_NAMETOOLONG;
    if (length > 0 && path[length - 1] != '/') path[length++] = '/';
    text_copy(path + length, kMaxPath - length, name);
    return fake_open_flags_to_node(path, flags);
}

void fill_stat_from_node(struct helper_stat_info* out, const Node& node) {
    out->size = node.size;
    out->mode = node.mode | (node.is_dir ? 0040000u : 0100000u);
    out->uid = node.uid;
    out->gid = node.gid;
    out->nlink = node.nlink;
    out->is_dir = node.is_dir ? 1u : 0u;
    out->is_reg = node.is_dir ? 0u : 1u;
}

int fake_fstat(int fd, struct helper_stat_info* out) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    fill_stat_from_node(out, g_fs.nodes[g_fs.fd_node[fd]]);
    return HELPER_OK;
}

int fake_fstatat(int dirfd, const char* name, struct helper_stat_info* out,
                 helper_u32 flags) {
    (void)flags;
    if (dirfd < 0 || dirfd >= kMaxFds || g_fs.fd_node[dirfd] < 0) return HELPER_E_INVAL;
    char path[kMaxPath];
    const char* base = g_fs.nodes[g_fs.fd_node[dirfd]].path;
    text_copy(path, kMaxPath, base);
    int length = text_length(path);
    if (length > 0 && path[length - 1] != '/') path[length++] = '/';
    text_copy(path + length, kMaxPath - length, name);
    const int node = find_node(path);
    if (node < 0) return HELPER_E_NOENT;
    fill_stat_from_node(out, g_fs.nodes[node]);
    return HELPER_OK;
}

long long fake_read(int fd, void* buffer, helper_u32 capacity) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    Node& node = g_fs.nodes[g_fs.fd_node[fd]];
    if (node.is_dir) return HELPER_E_ISDIR;
    const long long offset = g_fs.fd_offset[fd];
    if (offset < 0 || offset > static_cast<long long>(node.size)) return HELPER_E_INVAL;
    long long remaining = static_cast<long long>(node.size) - offset;
    if (remaining == 0) return 0;
    if (remaining > static_cast<long long>(capacity)) remaining = capacity;
    char* out = static_cast<char*>(buffer);
    for (long long index = 0; index < remaining; ++index)
        out[index] = node.data[offset + index];
    g_fs.fd_offset[fd] += remaining;
    return remaining;
}

long long fake_write(int fd, const void* buffer, helper_u32 length) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    Node& node = g_fs.nodes[g_fs.fd_node[fd]];
    if (node.is_dir) return HELPER_E_ISDIR;
    const long long offset = g_fs.fd_offset[fd];
    if (offset < 0 || offset + static_cast<long long>(length) > kMaxFile)
        return HELPER_E_NOSPC;
    const char* in = static_cast<const char*>(buffer);
    for (helper_u32 index = 0; index < length; ++index)
        node.data[offset + index] = in[index];
    g_fs.fd_offset[fd] += length;
    if (static_cast<unsigned int>(g_fs.fd_offset[fd]) > node.size)
        node.size = static_cast<unsigned int>(g_fs.fd_offset[fd]);
    return length;
}

long long fake_lseek(int fd, long long offset, int whence) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    long long target = offset;
    if (whence == HELPER_SEEK_CUR) target += g_fs.fd_offset[fd];
    if (target < 0 || target > kMaxFile) return HELPER_E_INVAL;
    g_fs.fd_offset[fd] = target;
    return target;
}

int fake_close(int fd) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    g_fs.fd_node[fd] = -1;
    g_fs.fd_offset[fd] = 0;
    return HELPER_OK;
}

int fake_fsync(int fd) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    return HELPER_OK;
}
int fake_fchmod(int fd, helper_u32 mode) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    g_fs.nodes[g_fs.fd_node[fd]].mode = mode;
    return HELPER_OK;
}
int fake_fchown(int fd, helper_u32 uid, helper_u32 gid) {
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    g_fs.nodes[g_fs.fd_node[fd]].uid = uid;
    g_fs.nodes[g_fs.fd_node[fd]].gid = gid;
    return HELPER_OK;
}
int fake_set_xattr(int fd, const char* name, const char* value, helper_u32 length) {
    (void)name;
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    Node& node = g_fs.nodes[g_fs.fd_node[fd]];
    helper_u32 copy = length;
    if (copy >= sizeof(node.xattr)) copy = sizeof(node.xattr) - 1;
    for (helper_u32 index = 0; index < copy; ++index) node.xattr[index] = value[index];
    node.xattr[copy] = '\0';
    return HELPER_OK;
}
int fake_get_xattr(int fd, const char* name, char* out, helper_u32 capacity) {
    (void)name;
    if (fd < 0 || fd >= kMaxFds || g_fs.fd_node[fd] < 0) return HELPER_E_INVAL;
    const char* value = g_fs.nodes[g_fs.fd_node[fd]].xattr;
    const int length = text_length(value);
    if (length == 0) return HELPER_E_NOENT;
    if (static_cast<helper_u32>(length + 1) > capacity) return HELPER_E_OVERFLOW;
    for (int index = 0; index <= length; ++index) out[index] = value[index];
    return length + 1;
}

int fake_mkdirat(int dirfd, const char* name, helper_u32 mode) {
    if (dirfd < 0 || dirfd >= kMaxFds || g_fs.fd_node[dirfd] < 0) return HELPER_E_INVAL;
    char path[kMaxPath];
    const char* base = g_fs.nodes[g_fs.fd_node[dirfd]].path;
    text_copy(path, kMaxPath, base);
    int length = text_length(path);
    if (length > 0 && path[length - 1] != '/') path[length++] = '/';
    text_copy(path + length, kMaxPath - length, name);
    if (find_node(path) >= 0) return HELPER_E_EXIST;
    if (make_dir(path, 0, 0, mode) < 0) return HELPER_E_NOSPC;
    return HELPER_OK;
}

int fake_renameat(int olddir, const char* oldname, int newdir, const char* newname) {
    if (olddir < 0 || newdir < 0) return HELPER_E_INVAL;
    char old_path[kMaxPath];
    char new_path[kMaxPath];
    const char* base = g_fs.nodes[g_fs.fd_node[olddir]].path;
    text_copy(old_path, kMaxPath, base);
    int length = text_length(old_path);
    if (length > 0 && old_path[length - 1] != '/') old_path[length++] = '/';
    text_copy(old_path + length, kMaxPath - length, oldname);
    base = g_fs.nodes[g_fs.fd_node[newdir]].path;
    text_copy(new_path, kMaxPath, base);
    length = text_length(new_path);
    if (length > 0 && new_path[length - 1] != '/') new_path[length++] = '/';
    text_copy(new_path + length, kMaxPath - length, newname);
    const int source = find_node(old_path);
    if (source < 0) return HELPER_E_NOENT;
    int target = find_node(new_path);
    if (target >= 0) {
        if (g_fs.nodes[target].is_dir || g_fs.nodes[source].is_dir) return HELPER_E_EXIST;
        g_fs.nodes[target].uid = g_fs.nodes[source].uid;
        g_fs.nodes[target].gid = g_fs.nodes[source].gid;
        g_fs.nodes[target].mode = g_fs.nodes[source].mode;
        g_fs.nodes[target].size = g_fs.nodes[source].size;
        for (unsigned int index = 0; index < g_fs.nodes[source].size; ++index)
            g_fs.nodes[target].data[index] = g_fs.nodes[source].data[index];
        g_fs.nodes[source].used = 0;
        return HELPER_OK;
    }
    text_copy(g_fs.nodes[source].path, kMaxPath, new_path);
    return HELPER_OK;
}

int fake_unlinkat(int dirfd, const char* name, helper_u32 flags) {
    if (dirfd < 0 || dirfd >= kMaxFds || g_fs.fd_node[dirfd] < 0) return HELPER_E_INVAL;
    char path[kMaxPath];
    const char* base = g_fs.nodes[g_fs.fd_node[dirfd]].path;
    text_copy(path, kMaxPath, base);
    int length = text_length(path);
    if (length > 0 && path[length - 1] != '/') path[length++] = '/';
    text_copy(path + length, kMaxPath - length, name);
    const int node = find_node(path);
    if (node < 0) return HELPER_E_NOENT;
    if ((flags & HELPER_AT_REMOVEDIR) != 0) {
        if (!g_fs.nodes[node].is_dir) return HELPER_E_NOTDIR;
        // Refuse to remove a directory that still has children.
        const int prefix = text_length(path);
        for (int index = 0; index < g_fs.node_count; ++index) {
            if (!g_fs.nodes[index].used || index == node) continue;
            int matches = 1;
            for (int position = 0; position < prefix; ++position)
                if (g_fs.nodes[index].path[position] != path[position]) {
                    matches = 0;
                    break;
                }
            if (matches && g_fs.nodes[index].path[prefix] == '/') return HELPER_E_EXIST;
        }
    } else if (g_fs.nodes[node].is_dir) {
        return HELPER_E_ISDIR;
    }
    g_fs.nodes[node].used = 0;
    return HELPER_OK;
}

int fake_list_dir(int dirfd, char names[][HELPER_NAME_MAX], helper_u32 capacity,
                  helper_u32* count) {
    *count = 0;
    if (dirfd < 0 || dirfd >= kMaxFds || g_fs.fd_node[dirfd] < 0) return HELPER_E_INVAL;
    const char* base = g_fs.nodes[g_fs.fd_node[dirfd]].path;
    const int prefix = text_length(base);
    for (int index = 0; index < g_fs.node_count; ++index) {
        if (!g_fs.nodes[index].used) continue;
        const char* path = g_fs.nodes[index].path;
        int matches = 1;
        for (int position = 0; position < prefix; ++position)
            if (path[position] != base[position]) {
                matches = 0;
                break;
            }
        if (!matches || path[prefix] != '/' || path[prefix + 1] == '\0') continue;
        if (*count >= capacity) return HELPER_E_OVERFLOW;
        text_copy(names[*count], HELPER_NAME_MAX, path + prefix + 1);
        // Only direct children are listed.
        int slash = 0;
        for (int position = 0; names[*count][position] != '\0'; ++position)
            if (names[*count][position] == '/') slash = 1;
        if (slash) continue;
        ++*count;
    }
    return HELPER_OK;
}

int fake_flock(int fd, helper_u32 operation) {
    (void)fd;
    (void)operation;
    return g_fs.lock_fails ? HELPER_E_AGAIN : HELPER_OK;
}

int fake_execve(const char* path, char* const argv[], char* const envp[]) {
    g_fs.exec_calls = 1;
    text_copy(g_fs.exec_path, kMaxPath, path);
    if (argv != 0 && argv[0] != 0) text_copy(g_fs.exec_argv0, sizeof(g_fs.exec_argv0), argv[0]);
    if (argv != 0 && argv[1] != 0) text_copy(g_fs.exec_argv1, sizeof(g_fs.exec_argv1), argv[1]);
    if (envp != 0 && envp[0] != 0) text_copy(g_fs.exec_env0, sizeof(g_fs.exec_env0), envp[0]);
    if (envp != 0 && envp[1] != 0) text_copy(g_fs.exec_env1, sizeof(g_fs.exec_env1), envp[1]);
    return HELPER_E_NOSYS;
}

int fake_run_shell(const char* command, char* out, helper_u32 capacity, helper_u32* length,
                   int* status) {
    (void)out;
    (void)capacity;
    *length = 0;
    *status = 0;
    if (g_fs.shell_calls < kMaxCommands)
        text_copy(g_fs.shell_commands[g_fs.shell_calls], 256, command);
    ++g_fs.shell_calls;
    return HELPER_OK;
}

int fake_policy_start(const char* key) {
    ++g_fs.policy_calls;
    text_copy(g_fs.policy_key, sizeof(g_fs.policy_key), key);
    return g_fs.policy_status;
}

void* fake_dlopen_fd(int fd, helper_u32 flags) {
    (void)fd;
    (void)flags;
    return reinterpret_cast<void*>(1);  // non-null opaque handle
}

void* fake_dlsym(void* handle, const char* name) {
    (void)handle;
    if (g_fs.policy_symbol_missing) return 0;
    if (!text_equal(name, "maplesu_environment_policy_start")) return 0;
    union {
        int (*function)(const char*);
        void* pointer;
    } cast;
    cast.function = fake_policy_start;
    return cast.pointer;
}

void fake_log_line(const char* text) {
    const int length = text_length(text);
    if (g_fs.log_length + length + 1 >= kMaxLog) return;
    for (int index = 0; index < length; ++index) g_fs.log[g_fs.log_length++] = text[index];
    g_fs.log[g_fs.log_length++] = '\n';
    g_fs.log[g_fs.log_length] = '\0';
}

const struct helper_ops kFakeOps = {
    fake_getuid,          fake_geteuid,
    fake_getpid,          fake_abort,
    fake_read_self_path,  fake_read_boot_id,
    fake_open_path,       fake_openat,
    fake_fstat,           fake_fstatat,
    fake_read,            fake_write,
    fake_lseek,           fake_close,
    fake_fsync,           fake_fchmod,
    fake_fchown,          fake_set_xattr,
    fake_get_xattr,       fake_mkdirat,
    fake_renameat,        fake_unlinkat,
    fake_list_dir,        fake_flock,
    fake_execve,          fake_run_shell,
    fake_dlopen_fd,       fake_dlsym,
    fake_log_line,
};

// ---------------------------------------------------------------- assertions
int g_failures = 0;
int g_checks = 0;

void check(int condition, const char* name) {
    ++g_checks;
    char line[256];
    int length = 0;
    const char* prefix = condition ? "PASS " : "FAIL ";
    while (prefix[length] != '\0' && length < 250) {
        line[length] = prefix[length];
        ++length;
    }
    int index = 0;
    while (name[index] != '\0' && length < 250) line[length++] = name[index++];
    line[length] = '\0';
    append_report(line);
    if (!condition) ++g_failures;
}

int file_contains(const char* path, const char* expected) {
    const int node = find_node(path);
    if (node < 0) return 0;
    Node& file = g_fs.nodes[node];
    const int length = text_length(expected);
    if (static_cast<unsigned int>(length) > file.size) return 0;
    for (int index = 0; index < length; ++index)
        if (file.data[index] != expected[index]) return 0;
    return length == static_cast<int>(file.size);
}

int node_mode(const char* path) {
    const int node = find_node(path);
    return node < 0 ? -1 : static_cast<int>(g_fs.nodes[node].mode & 07777u);
}

int node_uid(const char* path) {
    const int node = find_node(path);
    return node < 0 ? -1 : static_cast<int>(g_fs.nodes[node].uid);
}

int node_gid(const char* path) {
    const int node = find_node(path);
    return node < 0 ? -1 : static_cast<int>(g_fs.nodes[node].gid);
}

int node_is_file(const char* path) {
    const int node = find_node(path);
    return node >= 0 && !g_fs.nodes[node].is_dir;
}

// ------------------------------------------------------------ environment ---
void make_directories() {
    make_dir("/data", 0, 0, 0711);
    make_dir(kDataDir, 0, 0, 0711);
}

void install_environment(int install_allowlist, int install_backend) {
    g_fs.reset();
    make_directories();
    make_node(kSelfPath, 0, 0, 0, 0700);
    if (install_allowlist) make_file(kAllowlistPath, "com.example.app\n", 0, 0, 0600);
    if (install_backend) {
        make_dir("/data/adb", 0, 0, 0755);
        make_dir("/data/adb/maplesu", 0, 0, 0755);
        make_dir("/data/adb/maplesu/bin", 0, 0, 0700);
        make_file(kBackendPath, "backend-image", 0, 0, 0700);
    }
    make_dir(kPrivate, 0, 0, 0700);
    make_file(kPrivateImage, kCanonicalImage, 0, 0, 0700);
}

void install_packages_list() {
    make_dir("/data/system", 0, 0, 0755);
    make_file("/data/system/packages.list", kPackagesList, 0, 0, 0644);
}

int run_boot(int argc, char* argv[]) {
    return helper_run_boot(&kFakeOps, argc, argv);
}

void test_boot_success() {
    install_environment(1, 1);
    install_packages_list();
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    const int code = run_boot(1, argv);
    check(code == HELPER_EXIT_OK, "boot: exits 0");
    check(file_contains(kSafeFlag, "2"), "boot: safe flag committed to '2'");
    check(file_contains(kCompleted, "11111111-2222-3333-4444-555555555555\n"),
          "boot: completed receipt holds the boot id");
    check(file_contains(kWork, "11111111-2222-3333-4444-555555555555\n"),
          "boot: work receipt holds the boot id");
    check(file_contains(kDuplicate, "11111111-2222-3333-4444-555555555555\n"),
          "boot: duplicate guard holds the boot id");
    check(g_fs.policy_calls == 1 && text_equal(g_fs.policy_key, kKey),
          "boot: policy backend started with the in-process key");
    check(node_is_file("/data/ABCDEFGHIJKLMNOPA/u-00002711/su"),
          "boot: delivered copy for the allowed package");
    check(node_uid("/data/ABCDEFGHIJKLMNOPA/u-00002711/su") == 10001,
          "boot: delivered copy owned by the authorized UID");
    check(node_mode("/data/ABCDEFGHIJKLMNOPA/u-00002711") == 0710,
          "boot: delivery directory opened for traversal");
    check(file_contains("/data/ABCDEFGHIJKLMNOPA/u-00002711/su", kCanonicalImage),
          "boot: delivered copy matches the canonical image");
    check(node_is_file(kPrivateImage), "boot: canonical image kept private");
    check(node_mode(kPrivate) == 0700, "boot: private directory stays root-only");
    check(g_fs.shell_calls == 4, "boot: four property commands executed");
    check(g_fs.aborted == 0, "boot: no abort on the success path");
}

void test_boot_second_run_after_success() {
    install_environment(0, 1);
    install_packages_list();
    make_file(kSafeFlag, "2", 0, 0, 0600);
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    check(run_boot(1, argv) == HELPER_EXIT_OK, "boot: second run after success completes");
    check(file_contains(kSafeFlag, "2"), "boot: second run commits success again");
}

void test_boot_protection_gate() {
    install_environment(0, 1);
    make_file(kSafeFlag, "1", 0, 0, 0600);
    make_file(kProtect, "", 0, 0, 0600);
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    const int code = run_boot(1, argv);
    check(code == HELPER_EXIT_OK, "protection: protected boot exits 0");
    check(file_contains(kSafeFlag, "3"), "protection: safe flag rewritten to '3'");
    check(find_node(kWork) < 0, "protection: no work receipt published");
    check(find_node(kCompleted) < 0, "protection: no completion receipt published");
    check(file_contains(kDuplicate, "11111111-2222-3333-4444-555555555555\n"),
          "protection: duplicate guard written before the branch");
    const char expected_failure[] = "bootstrap last failed";
    const int expected_length = 21;
    int saw_last_failed = 0;
    for (int index = 0; index + expected_length <= g_fs.log_length; ++index) {
        int matches = 1;
        for (int position = 0; position < expected_length; ++position)
            if (g_fs.log[index + position] != expected_failure[position]) {
                matches = 0;
                break;
            }
        if (matches) saw_last_failed = 1;
    }
    check(saw_last_failed, "protection: failure is logged");
}

void test_boot_retry_when_protection_disabled() {
    install_environment(0, 1);
    make_file(kSafeFlag, "3", 0, 0, 0600);
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    check(run_boot(1, argv) == HELPER_EXIT_OK, "retry: unprotected retry completes");
    check(file_contains(kSafeFlag, "2"), "retry: retried session commits success");
}

void test_boot_previous_boot_receipt_is_not_protection() {
    install_environment(0, 1);
    make_file(kSafeFlag, "2", 0, 0, 0600);
    make_file(kDuplicate, "99999999-9999-9999-9999-999999999999\n", 0, 0, 0600);
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    check(run_boot(1, argv) == HELPER_EXIT_OK, "receipt: previous boot job is not protection");
    check(file_contains(kDuplicate, "11111111-2222-3333-4444-555555555555\n"),
          "receipt: duplicate guard overwritten for the current boot");
}

void test_boot_lock_failure_aborts() {
    install_environment(0, 1);
    g_fs.lock_fails = 1;
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    run_boot(1, argv);
    check(g_fs.aborted == 1, "lock: a second instance aborts");
    check(find_node(kWork) < 0, "lock: nothing is published on lock failure");
}

void test_boot_non_root_retains_protection() {
    install_environment(0, 1);
    g_fs.uid = 2000;
    g_fs.euid = 2000;
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    const int code = run_boot(1, argv);
    check(code == HELPER_EXIT_PROTECTED, "credentials: non-root boot fails closed");
    check(file_contains(kSafeFlag, "3"), "credentials: protection marker written");
    check(find_node(kWork) < 0, "credentials: no work receipt for a failed boot");
}

void test_boot_without_policy_backend() {
    install_environment(0, 0);
    char arg0[] = "init";
    char* argv[] = {arg0, 0};
    const int code = run_boot(1, argv);
    check(code == HELPER_EXIT_OK, "policy: missing backend does not abort the boot");
    check(g_fs.policy_calls == 0, "policy: start is not called without a backend");
    check(file_contains(kSafeFlag, "2"), "policy: boot still completes");
    check(g_fs.shell_calls == 4, "policy: property cleanup still runs");
}

void test_argument_modes() {
    install_environment(0, 1);
    char arg0[] = "init";
    char suicide[] = "--suicide";
    char* suicide_argv[] = {arg0, suicide, 0};
    g_fs.aborted = 0;
    run_boot(2, suicide_argv);
    check(g_fs.aborted == 1, "arguments: --suicide aborts");
    char other[] = "--unknown";
    char* other_argv[] = {arg0, other, 0};
    check(run_boot(2, other_argv) == HELPER_EXIT_USAGE, "arguments: unknown mode is a usage error");
}

// ----------------------------------------------------------- direct prims ---
struct helper_context make_context() {
    struct helper_context context;
    helper_memzero(&context, sizeof(context));
    context.ops = kFakeOps;
    text_copy(context.self_path, HELPER_PATH_MAX, kSelfPath);
    text_copy(context.env_dir, HELPER_PATH_MAX, kDataDir);
    text_copy(context.root_key, HELPER_KEY_LEN + 1, kKey);
    text_copy(context.module_id, HELPER_MODULE_LEN + 1, HELPER_MODULE_ID);
    context.lock_fd = -1;
    return context;
}

void test_su_write_delivery() {
    install_environment(0, 1);
    install_packages_list();
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    const int code = helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID);
    check(code == HELPER_OK, "su_write: delivery succeeds");
    check(node_is_file("/data/ABCDEFGHIJKLMNOPA/u-00002711/su"),
          "su_write: copy created for the resolved UID");
    check(node_uid("/data/ABCDEFGHIJKLMNOPA/u-00002711/su") == 10001,
          "su_write: copy owner is the authorized UID");
    check(node_gid("/data/ABCDEFGHIJKLMNOPA/u-00002711/su") == 10001,
          "su_write: copy group is the authorized UID");
    check(node_mode("/data/ABCDEFGHIJKLMNOPA/u-00002711") == 0710,
          "su_write: delivery directory opened exactly at the end");
    check(file_contains("/data/ABCDEFGHIJKLMNOPA/u-00002711/su", kCanonicalImage),
          "su_write: copy content matches the canonical image");
    check(node_mode("/data/ABCDEFGHIJKLMNOPA/u-00000000") == 0700,
          "su_write: private directory stays closed");
}

void test_su_write_revokes_stale_copy() {
    install_environment(0, 1);
    install_packages_list();
    make_dir(kDelivery10002, 0, 10002, 0710);
    make_file("/data/ABCDEFGHIJKLMNOPA/u-00002712/su", kCanonicalImage, 10002, 10002, 0700);
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    check(helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID) == HELPER_OK,
          "su_write: revoke delivery succeeds");
    check(find_node(kDelivery10002) < 0, "su_write: stale delivery directory removed");
    check(node_is_file("/data/ABCDEFGHIJKLMNOPA/u-00002711/su"),
          "su_write: authorized copy present after revoke");
}

void test_su_write_validation() {
    install_environment(0, 1);
    install_packages_list();
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    check(helper_su_write(&context, packages, 1, "short", HELPER_MODULE_ID) ==
              HELPER_SU_E_PARAM,
          "su_write: short key rejected");
    check(helper_su_write(&context, packages, 1, kKey, "short") == HELPER_SU_E_PARAM,
          "su_write: short module id rejected");
    check(helper_su_write(&context, 0, 1, kKey, HELPER_MODULE_ID) == HELPER_SU_E_PARAM,
          "su_write: missing package list rejected");
    g_fs.uid = 1000;
    check(helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID) ==
              HELPER_SU_E_PARAM,
          "su_write: non-root caller rejected");
    g_fs.uid = 0;
    char other_key[49];
    text_copy(other_key, sizeof(other_key), kKey);
    other_key[0] = 'Z';
    check(helper_su_write(&context, packages, 1, other_key, HELPER_MODULE_ID) ==
              HELPER_SU_E_PARAM,
          "su_write: foreign root key rejected");
}

void test_su_write_keeps_surface_closed_on_failure() {
    install_environment(0, 1);
    // No packages.list: UID resolution must fail after the delivery surface was
    // frozen, and the surface must end closed.
    make_dir(kDelivery10002, 0, 10002, 0710);
    make_file("/data/ABCDEFGHIJKLMNOPA/u-00002712/su", kCanonicalImage, 10002, 10002, 0700);
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    const int code = helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID);
    check(code == HELPER_SU_E_PACKAGES, "su_write: unresolved packages fail the transaction");
    check(node_mode(kDelivery10002) == 0700,
          "su_write: failed transaction leaves the delivery surface closed");
}

void test_su_write_missing_canonical_image() {
    install_environment(0, 1);
    install_packages_list();
    const int canonical = find_node(kPrivateImage);
    g_fs.nodes[canonical].used = 0;
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    check(helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID) ==
              HELPER_SU_E_CANONICAL,
          "su_write: missing canonical image rejected");
}

void test_su_exec() {
    install_environment(0, 1);
    install_packages_list();
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    check(helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID) == HELPER_OK,
          "su_exec: fixture delivery succeeded");
    char program[] = "/system/bin/sh";
    char argument[] = "-c";
    char command[] = "id";
    char* argv[] = {program, argument, command, 0};
    char path_variable[] = "PATH=/system/bin:/system/xbin";
    char other_variable[] = "HOME=/";
    char* envp[] = {path_variable, other_variable, 0};
    maplesu_helper_exec_request request;
    request.path = program;
    request.argv = argv;
    request.envp = envp;
    const int code = helper_su_exec(&context, &request, 10001, kKey, HELPER_MODULE_ID);
    check(code == HELPER_E_NOSYS, "su_exec: returns the exec failure");
    check(g_fs.exec_calls == 1, "su_exec: exec requested");
    check(text_equal(g_fs.exec_path, "/data/ABCDEFGHIJKLMNOPA/u-00002711/su"),
          "su_exec: executes only the delivered copy");
    check(text_equal(g_fs.exec_argv1, "-c"), "su_exec: argv preserved");
    check(text_equal(g_fs.exec_env0, "PATH=/data/ABCDEFGHIJKLMNOPA:/system/bin:/system/xbin"),
          "su_exec: delivered directory first on PATH");
    check(text_equal(g_fs.exec_env1, "HOME=/"), "su_exec: other environment entries preserved");
}

void test_su_exec_rejections() {
    install_environment(0, 1);
    install_packages_list();
    struct helper_context context = make_context();
    const char* packages[] = {"com.example.app"};
    check(helper_su_write(&context, packages, 1, kKey, HELPER_MODULE_ID) == HELPER_OK,
          "su_exec: rejection fixture delivery succeeded");
    char program[] = "/system/bin/sh";
    char* argv[] = {program, 0};
    maplesu_helper_exec_request request;
    request.path = program;
    request.argv = argv;
    request.envp = 0;
    check(helper_su_exec(&context, &request, 10002, kKey, HELPER_MODULE_ID) ==
              HELPER_SU_E_ENVIRONMENT,
          "su_exec: unknown authorized UID rejected");
    check(helper_su_exec(&context, &request, 0, kKey, HELPER_MODULE_ID) ==
              HELPER_SU_E_PARAM,
          "su_exec: missing control handle rejected");
    check(helper_su_exec(&context, 0, 10001, kKey, HELPER_MODULE_ID) == HELPER_SU_E_PARAM,
          "su_exec: missing request rejected");
    // A closed delivery directory is not executable.
    g_fs.nodes[find_node(kDelivery10001)].mode = 0700;
    check(helper_su_exec(&context, &request, 10001, kKey, HELPER_MODULE_ID) ==
              HELPER_SU_E_ENVIRONMENT,
          "su_exec: closed delivery surface rejected");
}

void test_session_receipt_order() {
    install_environment(0, 1);
    struct helper_context context = make_context();
    text_copy(context.boot_id, HELPER_BOOT_ID_LEN + 1, kBootId);
    int action = -1;
    check(helper_session_begin(&context, &action) == HELPER_OK && action == HELPER_SESSION_NORMAL,
          "session: fresh environment begins normally");
    check(file_contains(kSafeFlag, "1"), "session: safe flag marks initialising");
    check(file_contains(kDuplicate, "11111111-2222-3333-4444-555555555555\n"),
          "session: duplicate guard written at begin");
    check(find_node(kCompleted) < 0, "session: no completion receipt at begin");
    check(helper_session_finish(&context) == HELPER_OK, "session: finish succeeds");
    check(file_contains(kSafeFlag, "2"), "session: finish commits '2'");
    check(file_contains(kCompleted, "11111111-2222-3333-4444-555555555555\n"),
          "session: completion receipt written before the work receipt");
    check(file_contains(kWork, "11111111-2222-3333-4444-555555555555\n"),
          "session: work receipt published last");
}

void test_session_finish_rejects_replaced_flag() {
    install_environment(0, 1);
    struct helper_context context = make_context();
    text_copy(context.boot_id, HELPER_BOOT_ID_LEN + 1, kBootId);
    int action = -1;
    check(helper_session_begin(&context, &action) == HELPER_OK, "session: begin for replace test");
    g_fs.nodes[find_node(kSafeFlag)].nlink = 2;  // replaced/duplicated inode
    check(helper_session_finish(&context) == HELPER_E_INVAL,
          "session: finish rejects a replaced flag inode");
    check(find_node(kWork) < 0, "session: rejected finish publishes no work receipt");
}

}  // namespace

extern "C" int test_main() {
    g_failures = 0;
    g_checks = 0;
    append_report("=== helper host test ===");
    test_boot_success();
    test_boot_second_run_after_success();
    test_boot_protection_gate();
    test_boot_retry_when_protection_disabled();
    test_boot_previous_boot_receipt_is_not_protection();
    test_boot_lock_failure_aborts();
    test_boot_non_root_retains_protection();
    test_boot_without_policy_backend();
    test_argument_modes();
    test_su_write_delivery();
    test_su_write_revokes_stale_copy();
    test_su_write_validation();
    test_su_write_keeps_surface_closed_on_failure();
    test_su_write_missing_canonical_image();
    test_su_exec();
    test_su_exec_rejections();
    test_session_receipt_order();
    test_session_finish_rejects_replaced_flag();
    char summary[64];
    text_copy(summary, sizeof(summary), g_failures == 0 ? "RESULT PASS" : "RESULT FAIL");
    append_report(summary);
    test_report(g_report, g_report_length);
    return g_failures == 0 ? 0 : 1;
}
