#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <grp.h>
#include <iostream>
#include <vector>
#include <sys/wait.h>
#include <sys/xattr.h>
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_su_auth.h"
int test_fsetxattr(int, const char*, const void*, size_t, int) { return 0; }
ssize_t test_fgetxattr(int, const char*, void* out, size_t size) {
    const char value[] = "u:object_r:system_file:s0";
    assert(size >= sizeof(value)); memcpy(out, value, sizeof(value)); return sizeof(value);
}
#define fsetxattr test_fsetxattr
#define fgetxattr test_fgetxattr
#include "su_uid_copies.cpp"
#define Fd ExecFd
#include "su_exec_context.cpp"
#undef Fd
#include "su_auth_transaction.cpp"
#undef fsetxattr
#undef fgetxattr
namespace fs = std::filesystem;
static const char fixture_key[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl";
static const fs::path owner = fs::path("/data") / (std::string(fixture_key, 16) + fixture_key[0]);
static uint64_t live = 0;
static uint32_t old_table[] = {10001, 0};
static uint32_t new_table[] = {10001, 10002, 0};
static int behavior = 0;
namespace kernel_module {
KModErr read_kernel_mem(uint64_t address, void* output, uint32_t bytes) {
    memcpy(output, reinterpret_cast<void*>(address), bytes); return KModErr::OK;
}
KModErr write_kernel_rw_mem_atomic64(uint64_t address, uint64_t value) {
    *reinterpret_cast<uint64_t*>(address) = value; return KModErr::OK;
}
KModErr read_uint64_disk_storage(const char*, uint64_t& value) {
    value = reinterpret_cast<uint64_t>(&live); return KModErr::OK;
}
}
namespace maplesu::sdk { KModErr get_root(const char*) { return KModErr::OK; } }
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW() { return fixture_key; }
extern "C" KModErr maplesu_write_su_allowlist(const std::vector<std::string>&, const char*, bool) { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_get_su_allowlist(void (*)(const maplesu::sdk::su_auth_item*)) { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_add_su_allowlist(const char*) {
    auto result = maplesu_sync_su_copies(fixture_key, {10001,10002});
    if (is_failed(result)) return result;
    live = reinterpret_cast<uint64_t>(new_table);
    if (behavior == 1) return KModErr::ERR_MODULE_WRITE_FILE;
    if (behavior == 2) fs::remove(owner / "u-00002712/su");
    return KModErr::OK;
}
extern "C" KModErr maplesu_sdk_remove_su_allowlist(const char*) { return KModErr::OK; }
extern "C" KModErr maplesu_sdk_clear_su_allowlist() { return KModErr::OK; }
static void check(bool ok, const char* name) { if (!ok) { std::cerr << "FAIL " << name << '\n'; exit(1); } std::cout << "PASS " << name << '\n'; }
static mode_t mode(const fs::path& p) { struct stat st{}; assert(stat(p.c_str(),&st)==0); return st.st_mode & 07777; }
static void ordinary_probe(uint32_t uid, bool own_allowed) {
    pid_t pid=fork(); assert(pid>=0);
    if (!pid) {
        assert(setgroups(0,nullptr)==0 && setgid(uid)==0 && setuid(uid)==0);
        struct stat st{};
        assert(stat((owner/"u-00000000/su").c_str(),&st)==-1 && errno==EACCES);
        assert(open((owner/"u-00000000/su").c_str(),O_RDONLY)==-1 && errno==EACCES);
        assert(access((owner/"u-00000000/su").c_str(),X_OK)==-1);
        assert(execl((owner/"u-00000000/su").c_str(),"su",nullptr)==-1 && errno==EACCES);
        assert(opendir(owner.c_str())==nullptr);
        const auto own=owner/"u-00002711/su";
        if (own_allowed) { assert(stat(own.c_str(),&st)==0); assert(access(own.c_str(),X_OK)==0); execl(own.c_str(),"su",nullptr); _exit(101); }
        else { assert(stat(own.c_str(),&st)==-1 && errno==EACCES); assert(open(own.c_str(),O_RDONLY)==-1); assert(access(own.c_str(),X_OK)==-1); assert(execl(own.c_str(),"su",nullptr)==-1 && errno==EACCES); }
        _exit(0);
    }
    int status=0; assert(waitpid(pid,&status,0)==pid); check(WIFEXITED(status)&&WEXITSTATUS(status)==0,own_allowed?"authorized UID DAC access":"ordinary UID DAC isolation");
}
int main() {
    fs::create_directories(owner); chmod(owner.c_str(),0711);
    fs::copy_file("/bin/true",owner/"su"); chmod((owner/"su").c_str(),0700);
    check(is_ok(maplesu_prepare_su_exec(fixture_key)),"canonical migration");
    check(!fs::exists(owner/"su") && mode(owner/"u-00000000")==0700,"canonical private parent");
    check(is_ok(maplesu_prepare_su_exec(fixture_key)),"migration idempotent");
    check(is_ok(maplesu_sync_su_copies(fixture_key,{10001})),"prepare initial UID copy");
    ordinary_probe(10513,false); ordinary_probe(10001,true);
    live=reinterpret_cast<uint64_t>(old_table);
    check(is_ok(maplesu_freeze_su_copies(fixture_key)),"freeze"); ordinary_probe(10001,false);
    check(is_ok(maplesu_open_su_copies_from_control(fixture_key,reinterpret_cast<uint64_t>(&live))),"verify and open without copy");
    maplesu_thaw_su_copies();
    behavior=1;
    check(is_failed(default_modules::module_su_redirect::add_su_allowlist("fixture")),"persistence failure returned");
    check(live==reinterpret_cast<uint64_t>(old_table)&&!fs::exists(owner/"u-00002712")&&mode(owner/"u-00002711")==0710,"persistence rollback old only");
    behavior=2;
    check(to_num(default_modules::module_su_redirect::add_su_allowlist("fixture"))==-21001,"committed delivery status");
    check(live==reinterpret_cast<uint64_t>(new_table)&&mode(owner/"u-00002711")==0700&&mode(owner/"u-00002712")==0700,"committed failure closes all directories");
    behavior=0;
    check(is_ok(default_modules::module_su_redirect::add_su_allowlist("fixture")),"committed delivery retry");
    check(mode(owner/"u-00002711")==0710&&mode(owner/"u-00002712")==0710,"retry opens prepared live set");
    fs::create_directory(owner/"u-00002713"); chmod((owner/"u-00002713").c_str(),0700);
    std::ofstream(owner/"u-00002711/.su-123-1")<<"partial"; chmod((owner/"u-00002711/.su-123-1").c_str(),0600);
    check(is_ok(maplesu_sync_su_copies(fixture_key,{10001,10003})),"mkdir and temp crash recovery");
    check(!fs::exists(owner/"u-00002711/.su-123-1")&&!fs::exists(owner/"u-00002712"),"temp cleanup and revoke");
    fs::remove(owner/"u-00002713/su"); fs::create_symlink("/etc/passwd",owner/"u-00002713/su");
    check(is_failed(maplesu_sync_su_copies(fixture_key,{10001,10003})),"foreign symlink rejected");
    check(is_failed(maplesu_sync_su_copies(fixture_key,{10001}))&&mode(owner/"u-00002713")==0700,"failed stale UID cleanup stays closed");
    chown((owner/"u-00002713").c_str(),0,12345); chmod((owner/"u-00002713").c_str(),0710);
    check(is_failed(maplesu_freeze_su_copies(fixture_key))&&mode(owner/"u-00002713")==0700,"metadata error closes root-owned directory first");
    maplesu_thaw_su_copies();
    std::cout << "SELinux xattrs shimmed; kernel hook and device behavior require main acceptance\n";
}
