#include "module_policy_config.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <functional>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace maplesu::module_policy;
namespace {
const std::string BOOT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const std::string NEXT_BOOT = "11111111-2222-3333-4444-555555555555";
unsigned prepares = 0;
unsigned prepared_capabilities = 1;
Mode prepared_mode = Mode::Hide;
bool prepared_unverified = false;
Store* preparing_store = nullptr;
unsigned prepare(Mode mode, bool allow_unverified) {
    ++prepares;
    prepared_mode = mode;
    prepared_unverified = allow_unverified;
    // Publication must follow the backend, including on the initial boot.
    if (preparing_store) {
        assert(!preparing_store->read(BOOT).effective);
        assert(preparing_store->blocks_transactions(BOOT));
    }
    return prepared_capabilities;
}
unsigned hide_attempts = 0;
unsigned broken_hide(Mode mode, bool) {
    ++hide_attempts;
    if (mode == Mode::Hide) throw std::runtime_error("HOOK_INSTALL_FAILED");
    assert(mode == Mode::Load);
    return 1;
}
unsigned broken_backend(Mode, bool) { throw std::runtime_error("BACKEND_FAILED"); }
unsigned invalid_cancel(Mode mode, bool) {
    if (mode == Mode::Hide) throw std::runtime_error("PREPARE_FAILED");
    assert(mode == Mode::Load);
    return prepared_capabilities;
}
unsigned crashing_backend(Mode, bool) { _exit(23); }
bool fails(const std::function<void()>& action, const char* code) {
    try { action(); }
    catch (const std::runtime_error& e) { return std::string(e.what()) == std::string("MODULE_POLICY_CONFIG_") + code; }
    return false;
}
struct Case {
    std::string directory;
    Case() {
        char name[] = "/tmp/maplesu-policy-config-XXXXXX";
        char* result = mkdtemp(name);
        assert(result);
        directory = result;
    }
    ~Case() {
        for (const char* name : {"requested", "effective", "attempt", "hook", ".hook.tmp", "hook-pending", ".hook-pending.tmp", "activation", ".activation.tmp", "fallback", ".fallback.tmp", ".experimental.tmp", ".experimental-support.tmp", "experimental", "experimental-support", ".lock", ".requested.tmp", ".effective.tmp", ".attempt.tmp", "outside", ".diagnostics.lock", "compatibility.log", "compatibility.previous.log"})
            unlink((directory + "/" + name).c_str());
        assert(rmdir(directory.c_str()) == 0);
    }
    Store store() { return Store(open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)); }
    std::string text(const char* name) const {
        int fd = open((directory + "/" + name).c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        assert(fd >= 0);
        std::string result;
        char bytes[4096];
        for (;;) {
            ssize_t count = read(fd, bytes, sizeof(bytes));
            assert(count >= 0);
            if (!count) break;
            result.append(bytes, static_cast<size_t>(count));
        }
        close(fd);
        return result;
    }
    void file(const char* name, const std::string& text) {
        int fd = open((directory + "/" + name).c_str(), O_WRONLY | O_TRUNC | O_CREAT | O_NOFOLLOW, 0600);
        assert(fd >= 0 && write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size()));
        close(fd);
    }
};
}
int main() {
    assert(geteuid() == 0); // Production ownership checks also run in this fixture.
    unsigned tests = 0;
    {
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n");
        bool cancelled = false;
        try { s.prepare_boot(BOOT, broken_backend); }
        catch (const std::runtime_error& error) { cancelled = std::string(error.what()) == "BACKEND_FAILED"; }
        assert(cancelled);
        assert(!s.read(BOOT).effective && s.read(BOOT).requested == Mode::Hide);
        assert(s.blocks_transactions(BOOT, true));
        assert(access((c.directory + "/fallback").c_str(), F_OK) != 0);
        assert(c.text("compatibility.log").find("result=pending") != std::string::npos);
        prepares = 0; prepared_capabilities = 1;
        auto ready = s.prepare_boot(BOOT, prepare);
        assert(ready.mode == Mode::Load && prepares == 1 && prepared_mode == Mode::Load);
        assert(s.read(BOOT).hide_failed && !s.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        bool cancelled = false;
        try { s.prepare_boot(BOOT, broken_backend); }
        catch (const std::runtime_error& error) { cancelled = std::string(error.what()) == "BACKEND_FAILED"; }
        assert(cancelled && !s.read(BOOT).effective && s.blocks_transactions(BOOT, true));
        prepares = 0; prepared_capabilities = 1;
        assert(s.prepare_boot(BOOT, prepare).mode == Mode::Load);
        assert(prepares == 1 && prepared_mode == Mode::Load);
        ++tests;
    }
    {
        for (unsigned invalid : {0u, 2u, 4u}) {
            Case c; auto s = c.store();
            c.file("requested", "v1:3\n");
            prepared_capabilities = invalid;
            assert(fails([&] { s.prepare_boot(BOOT, invalid_cancel); }, "CANCEL_CAPABILITIES"));
            assert(!s.read(BOOT).effective && s.blocks_transactions(BOOT, true));
            assert(access((c.directory + "/fallback").c_str(), F_OK) != 0);
        }
        ++tests;
    }
    {
        Store absent(-1);
        assert(!absent.owns_hook(BOOT));
        assert(fails([&] { absent.owns_hook("invalid"); }, "BOOT_ID"));
        ++tests;
    }
    {
        for (Mode mode : {Mode::Block, Mode::Load, Mode::Hide}) {
            Case c; auto s = c.store();
            s.publish({mode, mode == Mode::Hide ? 3u : 1u, BOOT});
            assert(!s.owns_hook(BOOT));
            assert(s.read(BOOT).effective->mode == mode);
            assert(access((c.directory + "/hook").c_str(), F_OK) != 0);
        }
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("hook", "v1:" + NEXT_BOOT + "\n");
        assert(!s.owns_hook(BOOT) && s.owns_hook(NEXT_BOOT));
        c.file("hook", "v1:" + BOOT + "\n");
        c.file("hook-pending", "v1:" + BOOT + "\n");
        assert(s.owns_hook(BOOT) && !s.owns_hook(NEXT_BOOT));
        assert(!s.read(BOOT).effective);
        assert(c.text("hook") == "v1:" + BOOT + "\n");
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("hook", "broken");
        assert(fails([&] { s.owns_hook(BOOT); }, "ATTEMPT_RECORD"));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.prepare_hook(BOOT, Mode::Load);
        pid_t child = fork(); assert(child >= 0);
        if (!child) { s.prepare_hook(BOOT, Mode::Hide, crashing_backend); _exit(99); }
        int status = 0;
        assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 23);
        assert(!s.read(BOOT).effective && s.blocks_transactions(BOOT, true));
        assert(!s.read(NEXT_BOOT).effective && !s.blocks_transactions(NEXT_BOOT));
        prepares = 0; prepared_capabilities = 3; preparing_store = &s;
        assert(s.prepare_hook(BOOT, std::nullopt, prepare).mode == Mode::Hide);
        preparing_store = nullptr;
        assert(prepares == 1 && s.read(BOOT).effective->mode == Mode::Hide);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Load, 1, BOOT});
        c.file("fallback", "v1:" + BOOT + "\n");
        c.file("hook-pending", "v1:" + BOOT + "\n");
        assert(!s.read(BOOT).effective && s.blocks_transactions(BOOT));
        c.file("hook-pending", "broken");
        assert(fails([&] { s.read(BOOT); }, "ATTEMPT_RECORD"));
        assert(fails([&] { s.blocks_transactions(BOOT); }, "ATTEMPT_RECORD"));
        ++tests;
    }
    {
        Case c; auto s = c.store();prepares=0;prepared_capabilities=3;
        assert(s.prepare_hook(BOOT, Mode::Hide, prepare).mode==Mode::Hide);
        assert(prepares==1&&prepared_mode==Mode::Hide&&!prepared_unverified);
        assert(s.read(BOOT).effective->capabilities==3&&s.read(BOOT).can_try_unverified);
        assert(!s.blocks_transactions(BOOT,true));
        assert(s.prepare_hook(BOOT,std::nullopt,prepare).mode==Mode::Hide&&prepares==1);
        prepared_capabilities=1;
        assert(s.prepare_hook(BOOT,Mode::Load,prepare).mode==Mode::Load);
        assert(s.prepare_hook(BOOT,Mode::Block,prepare).mode==Mode::Block);
        assert(s.blocks_transactions(BOOT,true)&&prepares==3);
        ++tests;
    }
    {
        Case c;auto s=c.store();hide_attempts=0;
        auto ready=s.prepare_hook(BOOT,Mode::Hide,broken_hide);
        assert(ready.mode==Mode::Load&&hide_attempts==2);
        assert(s.read(BOOT).hide_failed&&!s.blocks_transactions(BOOT,true));
        prepared_capabilities=3;
        ready=s.prepare_hook(BOOT,Mode::Hide,prepare,true);
        assert(ready.mode==Mode::Hide&&prepared_unverified&&!s.read(BOOT).hide_failed);
        assert(s.read(BOOT).unverified_hide);
        ++tests;
    }
    {
        Case c;auto s=c.store();s.prepare_hook(BOOT,Mode::Load);prepares=0;
        assert(s.prepare_hook(BOOT,std::nullopt,prepare).mode==Mode::Load&&prepares==0);
        assert(s.read(BOOT).can_try_unverified);
        ++tests;
    }
    {
        Case c;auto s=c.store();
        const auto child=fork();assert(child>=0);
        if(!child){s.prepare_hook(BOOT,Mode::Hide,crashing_backend);_exit(99);}
        int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==23);
        assert(c.text("hook-pending")=="v1:"+BOOT+"\n"&&!s.read(BOOT).effective);
        prepared_capabilities=3;prepares=0;
        assert(s.prepare_hook(BOOT,std::nullopt,prepare).mode==Mode::Hide&&prepares==1);
        assert(access((c.directory+"/hook-pending").c_str(),F_OK)!=0);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        assert(s.prepare_hook(BOOT).mode == Mode::Block);
        assert(s.blocks_transactions(BOOT, true));
        assert(s.prepare_hook(BOOT, Mode::Load).mode == Mode::Load);
        assert(s.read(BOOT).requested == Mode::Load && s.read(BOOT).effective->mode == Mode::Load);
        assert(!s.blocks_transactions(BOOT, true));
        struct stat before{}, after{};
        assert(stat((c.directory + "/effective").c_str(), &before) == 0);
        assert(s.prepare_hook(BOOT).mode == Mode::Load);
        assert(stat((c.directory + "/effective").c_str(), &after) == 0 && before.st_ino == after.st_ino);
        assert(s.prepare_hook(BOOT, Mode::Block).mode == Mode::Block);
        assert(s.read(BOOT).requested == Mode::Block && s.blocks_transactions(BOOT, true));
        assert(!s.read(BOOT).can_try_unverified && s.read(BOOT).effective->capabilities == 1);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.prepare_hook(BOOT, Mode::Load);
        auto before = c.text("effective");
        assert(fails([&] { s.prepare_hook(BOOT, Mode::Hide); }, "HOOK_HIDE_UNSUPPORTED"));
        assert(c.text("effective") == before && s.read(BOOT).requested == Mode::Load);
        assert(s.prepare_hook(NEXT_BOOT).mode == Mode::Load);
        assert(!s.read(BOOT).effective && !s.blocks_transactions(NEXT_BOOT, true));
        ++tests;
    }
    {
        // A partial userspace-only gate publication can be resumed. There is
        // no kernel installation callback to replay and no baseline to fake.
        Case c; auto s = c.store();
        c.file("hook", "v1:" + BOOT + "\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        c.file("requested", "v1:1\n");
        assert(s.blocks_transactions(BOOT, true));
        assert(s.prepare_hook(BOOT).mode == Mode::Load);
        assert(!s.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n");
        c.file("experimental", "v1:1\n");
        auto ready = s.prepare_hook(BOOT);
        assert(ready.mode == Mode::Load && ready.capabilities == 1);
        assert(s.read(BOOT).hide_failed && s.read(BOOT).requested == Mode::Load);
        assert(!s.read(BOOT).unverified_hide && !s.blocks_transactions(BOOT, true));
        assert(c.text("compatibility.log").find("MODULE_POLICY_HOOK_HIDE_UNSUPPORTED") != std::string::npos);
        s.prepare_hook(BOOT, Mode::Block);
        assert(!s.read(BOOT).hide_failed && s.read(BOOT).effective->mode == Mode::Block);
        assert(s.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        for (unsigned caps : {1u, 3u}) {
            Case c; auto s = c.store();
            s.publish({Mode::Load, caps, BOOT});
            auto before = c.text("effective");
            assert(fails([&] { s.prepare_hook(BOOT, Mode::Block); }, "HOOK_BACKEND_IN_USE"));
            assert(c.text("effective") == before && s.read(BOOT).requested == Mode::Block);
        }
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("attempt", "v1:" + BOOT + "\n");
        assert(fails([&] { s.prepare_hook(BOOT); }, "HOOK_BACKEND_IN_USE"));
        assert(!s.read(BOOT).effective && s.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("activation", "v1:" + BOOT + ":ffff000000001000\n");
        assert(fails([&] { s.prepare_hook(BOOT); }, "HOOK_BACKEND_IN_USE"));
        assert(!s.read(BOOT).effective);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        int fd = open((c.directory + "/.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        assert(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
        assert(fails([&] { s.prepare_hook(BOOT, Mode::Load); }, "BUSY"));
        assert(!s.read(BOOT).effective && s.read(BOOT).requested == Mode::Block);
        close(fd);
        assert(s.prepare_hook(BOOT, Mode::Load).mode == Mode::Load);
        ++tests;
    }
    {
        Store absent(-1);
        auto state = absent.read(BOOT);
        assert(state.requested == Mode::Block && !state.effective);
        assert(json(state) == "{\"schemaVersion\":1,\"requested\":0,\"effective\":null,\"capabilities\":0,\"unverifiedHide\":false,\"canTryUnverified\":false,\"hideFailed\":false}");
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.request(Mode::Load, BOOT);
        auto state = s.read(BOOT);
        assert(state.requested == Mode::Load && !state.effective);
        assert(!state.can_try_unverified && !state.unverified_hide);
        assert(s.blocks_transactions(BOOT, true));
        assert(!s.blocks_transactions(BOOT)); // Preserve the untouched legacy boot.
        assert(fails([&] { s.request(Mode::Hide, BOOT); }, "BACKEND_NOT_READY"));
        assert(s.read(BOOT).requested == Mode::Load);
        s.request(Mode::Block, BOOT);
        assert(s.read(BOOT).requested == Mode::Block && !s.read(BOOT).effective);
        assert(access((c.directory + "/effective").c_str(), F_OK) != 0);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.request(Mode::Load, BOOT);
        prepares = 0; prepared_capabilities = 1;
        auto ready = s.prepare_boot(NEXT_BOOT, prepare);
        assert(prepares == 1 && prepared_mode == Mode::Load);
        assert(ready.mode == Mode::Load && ready.boot_id == NEXT_BOOT);
        assert(!s.read(BOOT).effective && s.read(NEXT_BOOT).effective->mode == Mode::Load);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Block, 1, BOOT});
        s.request(Mode::Load, BOOT);
        auto state = s.read(BOOT);
        assert(state.requested == Mode::Load && state.effective->mode == Mode::Block);
        s.request(Mode::Block, BOOT);
        assert(s.read(BOOT).requested == Mode::Block);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Load, 1, BOOT}); s.request(Mode::Load, BOOT);
        assert(fails([&] { s.request(Mode::Hide, BOOT); }, "HIDE_UNSUPPORTED"));
        assert(s.read(BOOT).requested == Mode::Load);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        prepared_capabilities = 1;
        s.prepare_boot(BOOT, prepare, true);
        assert(s.read(BOOT).can_try_unverified && !s.read(NEXT_BOOT).can_try_unverified);
        s.request(Mode::Hide, BOOT, true);
        assert(s.read(BOOT).requested == Mode::Hide && s.read(BOOT).unverified_hide);
        assert(s.read(BOOT).effective->mode == Mode::Block);
        assert(c.text("requested") == "v1:3\n"); // Legacy record stays compatible.
        prepared_capabilities = 3;
        auto ready = s.prepare_boot(NEXT_BOOT, prepare, true);
        assert(prepared_mode == Mode::Hide && prepared_unverified && ready.mode == Mode::Hide);
        s.request(Mode::Load, NEXT_BOOT);
        assert(!s.read(NEXT_BOOT).unverified_hide && s.read(NEXT_BOOT).effective->mode == Mode::Hide);
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0;
        s.publish({Mode::Load, 1, BOOT});
        s.request(Mode::Load, BOOT);
        // Migrating a capable backend must repair a missing support record,
        // without reapplying a pending preference or installing hooks twice.
        assert(s.prepare_boot(BOOT, prepare, true).mode == Mode::Load);
        assert(prepares == 0 && s.read(BOOT).can_try_unverified);
        s.request(Mode::Hide, BOOT, true);
        assert(s.read(BOOT).requested == Mode::Hide && s.read(BOOT).unverified_hide);
        assert(s.prepare_boot(BOOT, prepare, true).mode == Mode::Load);
        assert(prepares == 0 && s.read(BOOT).effective->capabilities == 1);
        assert(!s.read(NEXT_BOOT).can_try_unverified);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Load, 1, BOOT});
        s.prepare_boot(BOOT, nullptr, true);
        assert(!s.read(BOOT).can_try_unverified);
        s.prepare_boot(BOOT, prepare, false);
        assert(!s.read(BOOT).can_try_unverified);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Load, 1, BOOT});
        assert(fails([&] { s.request(Mode::Hide, BOOT, true); }, "EXPERIMENTAL_UNSUPPORTED"));
        assert(s.read(BOOT).requested == Mode::Block && !s.read(BOOT).unverified_hide);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n"); c.file("experimental", "v1:1\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        s.request(Mode::Load, BOOT);
        assert(!s.read(BOOT).unverified_hide && s.read(BOOT).requested == Mode::Load);
        assert(s.blocks_transactions(BOOT)); // Cancellation never hot-unloads.
        prepared_capabilities = 1;
        assert(s.prepare_boot(NEXT_BOOT, prepare).mode == Mode::Load && !prepared_unverified);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Load, 3, BOOT});
        c.file("requested", "v1:1\n"); c.file("experimental", "v1:1\n");
        assert(!s.read(BOOT).unverified_hide);
        s.request(Mode::Hide, BOOT);
        assert(!s.read(BOOT).unverified_hide && c.text("experimental") == "v1:0\n");
        ++tests;
    }
    {
        Case c; auto s = c.store();
        s.publish({Mode::Block, 3, BOOT}); s.request(Mode::Hide, BOOT);
        auto state = s.read(BOOT);
        assert(state.requested == Mode::Hide && state.effective->mode == Mode::Block);
        s.publish({state.requested, 3, NEXT_BOOT});
        state = s.read(NEXT_BOOT);
        assert(state.effective->mode == Mode::Hide && state.requested == Mode::Hide);
        s.request(Mode::Block, NEXT_BOOT);
        assert(s.read(NEXT_BOOT).effective->mode == Mode::Hide);
        ++tests;
    }
    {
        Case c; auto s = c.store(); s.publish({Mode::Load, 3, BOOT});
        auto state = s.read(NEXT_BOOT);
        assert(!state.effective);
        assert(fails([&] { s.request(Mode::Hide, NEXT_BOOT); }, "BACKEND_NOT_READY"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0; prepared_capabilities = 1;
        preparing_store = &s;
        auto ready = s.prepare_boot(BOOT, prepare);
        preparing_store = nullptr;
        assert(prepares == 1 && prepared_mode == Mode::Block);
        assert(ready.mode == Mode::Block && ready.capabilities == 1 && ready.boot_id == BOOT);
        assert(s.blocks_transactions(BOOT));
        s.request(Mode::Load, BOOT);
        ready = s.prepare_boot(BOOT, prepare);
        assert(prepares == 1 && ready.mode == Mode::Block);
        assert(s.read(BOOT).requested == Mode::Load);
        ready = s.prepare_boot(NEXT_BOOT, prepare);
        assert(prepares == 2 && prepared_mode == Mode::Load && ready.mode == Mode::Load);
        assert(!s.blocks_transactions(NEXT_BOOT));
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0; prepared_capabilities = 3;
        c.file("requested", "v1:3\n");
        auto ready = s.prepare_boot(BOOT, prepare);
        assert(prepares == 1 && prepared_mode == Mode::Hide && ready.mode == Mode::Hide);
        assert(ready.capabilities == 3 && !s.blocks_transactions(BOOT));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        assert(!s.activation(BOOT));
        constexpr uint64_t address = 0xffff800040010000ULL;
        s.remember_activation(BOOT, address);
        assert(s.activation(BOOT) == address && !s.activation(NEXT_BOOT));
        assert(fails([&] { s.remember_activation(BOOT, 0); }, "ACTIVATION_RECORD"));
        assert(fails([&] { s.remember_activation(BOOT, address + 1); }, "ACTIVATION_RECORD"));
        c.file("activation", "v1:" + BOOT + ":0000000040010000\n");
        assert(fails([&] { s.activation(BOOT); }, "ACTIVATION_RECORD"));
        c.file("activation", "v1:" + BOOT + ":ffff80004001000x\n");
        assert(fails([&] { s.activation(BOOT); }, "ACTIVATION_RECORD"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); hide_attempts = 0;
        c.file("requested", "v1:3\n"); c.file("experimental", "v1:1\n");
        auto ready = s.prepare_boot(BOOT, broken_hide, true);
        assert(ready.mode == Mode::Load && ready.capabilities == 1);
        assert(hide_attempts == 2 && !s.blocks_transactions(BOOT, true));
        auto state = s.read(BOOT);
        assert(state.requested == Mode::Load && state.effective->mode == Mode::Load);
        assert(!state.unverified_hide && state.hide_failed && state.can_try_unverified);
        assert(c.text("fallback") == "v1:" + BOOT + "\n");
        assert(c.text("compatibility.log").find("HOOK_INSTALL_FAILED") != std::string::npos);
        assert(s.prepare_boot(BOOT, broken_hide, true).mode == Mode::Load && hide_attempts == 2);
        assert(!s.read(NEXT_BOOT).hide_failed);
        s.request(Mode::Hide, BOOT, true);
        assert(s.read(BOOT).hide_failed && s.read(BOOT).requested == Mode::Hide);
        ++tests;
    }
    {
        Case c; auto s = c.store(); hide_attempts = 0;
        c.file("requested", "v1:3\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        assert(s.prepare_boot(BOOT, broken_hide, true).mode == Mode::Load);
        assert(hide_attempts == 1 && !s.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        Case c; auto s = c.store(); hide_attempts = 0;
        c.file("requested", "v1:3\n");
        c.file("outside", "unpublished");
        assert(symlink("outside", (c.directory + "/effective").c_str()) == 0);
        // Publication failure after preparation is covered separately below;
        // an untrusted pre-existing record must retain validation.
        assert(fails([&] { s.prepare_boot(BOOT, broken_hide); }, "OPEN"));
        assert(hide_attempts == 0);
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0; prepared_capabilities = 1;
        c.file("requested", "v1:3\n");
        assert(s.prepare_boot(BOOT, prepare).mode == Mode::Load);
        assert(prepares == 2 && s.read(BOOT).hide_failed && !s.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        prepares = 0;
        for (unsigned caps : {0U, 2U, 4U}) {
            Case c; auto s = c.store();
            prepared_capabilities = caps;
            assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "BOOT_RECORD"));
            assert(!s.read(BOOT).effective);
        }
        assert(prepares == 3);
        ++tests;
    }
    {
        Case c; auto s = c.store(); s.publish({Mode::Load, 1, NEXT_BOOT});
        try { s.prepare_boot(BOOT, broken_backend); assert(false); }
        catch (const std::runtime_error& e) { assert(std::string(e.what()) == "BACKEND_FAILED"); }
        assert(!s.read(BOOT).effective && s.read(NEXT_BOOT).effective->mode == Mode::Load);
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0; c.file("requested", "broken");
        assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "RECORD"));
        assert(prepares == 0 && access((c.directory + "/effective").c_str(), F_OK) != 0);
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0; prepared_capabilities = 1;
        c.file(".lock", "");
        int held = open((c.directory + "/.lock").c_str(), O_RDWR | O_CLOEXEC);
        assert(held >= 0 && flock(held, LOCK_EX | LOCK_NB) == 0);
        assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "BUSY"));
        assert(prepares == 0 && !s.read(BOOT).effective);
        close(held);
        assert(s.prepare_boot(BOOT, prepare).mode == Mode::Block && prepares == 1);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        assert(fails([&] { s.prepare_boot(BOOT, nullptr); }, "BACKEND_NOT_READY"));
        assert(!s.read(BOOT).effective);
        s.publish({Mode::Load, 1, BOOT});
        assert(s.prepare_boot(BOOT, nullptr).mode == Mode::Load);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        assert(fails([&] { s.publish({Mode::Hide, 1, BOOT}); }, "BOOT_RECORD"));
        assert(fails([&] { s.publish({Mode::Block, 0, BOOT}); }, "BOOT_RECORD"));
        assert(fails([&] { s.publish({static_cast<Mode>(2), 3, BOOT}); }, "MODE"));
        assert(fails([&] { s.read("wrong-boot"); }, "BOOT_ID"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); c.file("requested", "v1:2\n");
        assert(fails([&] { s.read(BOOT); }, "RECORD"));
        c.file("requested", "v1:1\ntrailing");
        assert(fails([&] { s.read(BOOT); }, "RECORD"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); c.file("requested", "v1:0\n");
        assert(chmod((c.directory + "/requested").c_str(), 0666) == 0);
        assert(fails([&] { s.read(BOOT); }, "FILE"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); c.file("outside", "v1:1\n");
        assert(symlink((c.directory + "/outside").c_str(), (c.directory + "/requested").c_str()) == 0);
        assert(fails([&] { s.read(BOOT); }, "OPEN"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); c.file("outside", "v1:1\n");
        assert(link((c.directory + "/outside").c_str(), (c.directory + "/requested").c_str()) == 0);
        assert(fails([&] { s.read(BOOT); }, "FILE"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); assert(mkfifo((c.directory + "/requested").c_str(), 0600) == 0);
        assert(fails([&] { s.read(BOOT); }, "FILE"));
        ++tests;
    }
    {
        Case c; auto s = c.store(); s.publish({Mode::Block, 3, BOOT});
        c.file(".requested.tmp", "incomplete");
        assert(s.read(BOOT).requested == Mode::Block);
        s.request(Mode::Load, BOOT);
        assert(s.read(BOOT).requested == Mode::Load);
        assert(access((c.directory + "/.requested.tmp").c_str(), F_OK) != 0);
        ++tests;
    }
    {
        Store absent(-1);
        assert(!absent.blocks_transactions(BOOT));
        assert(absent.blocks_transactions(BOOT, true));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        assert(!s.blocks_transactions(BOOT) && s.blocks_transactions(BOOT, true));
        s.publish({Mode::Load, 1, BOOT});
        assert(!s.blocks_transactions(BOOT, true) && s.blocks_transactions(NEXT_BOOT, true));
        s.request(Mode::Block, BOOT);
        assert(!s.blocks_transactions(BOOT, true));
        c.file("attempt", "v1:" + BOOT + "\n");
        assert(s.blocks_transactions(NEXT_BOOT, true));
        ++tests;
    }
    {
        Case c; auto s = c.store(); s.publish({Mode::Block, 3, BOOT});
        assert(s.blocks_transactions(BOOT));
        s.request(Mode::Load, BOOT);
        assert(s.blocks_transactions(BOOT));
        assert(!s.blocks_transactions(NEXT_BOOT));
        s.publish({Mode::Load, 3, NEXT_BOOT});
        s.request(Mode::Block, NEXT_BOOT);
        assert(!s.blocks_transactions(NEXT_BOOT));
        s.publish({Mode::Hide, 3, NEXT_BOOT});
        assert(!s.blocks_transactions(NEXT_BOOT));
        ++tests;
    }
    {
        Case c; auto s = c.store(); s.publish({Mode::Load, 3, BOOT});
        c.file("requested", "broken request");
        assert(!s.blocks_transactions(BOOT));
        c.file("effective", "broken boot state");
        assert(fails([&] { s.blocks_transactions(BOOT); }, "BOOT_RECORD"));
        ++tests;
    }
    {
        Case c; auto s = c.store();
        try { s.prepare_boot(BOOT, broken_backend); assert(false); }
        catch (const std::runtime_error& e) { assert(std::string(e.what()) == "BACKEND_FAILED"); }
        // A failed initializer may already own live kernel hooks. Missing
        // effective state must not reopen the legacy module-policy path.
        assert(s.blocks_transactions(BOOT));
        prepares = 0;
        assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "PREPARATION_INTERRUPTED"));
        assert(prepares == 0 && !s.read(BOOT).effective);
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0; prepared_capabilities = 1;
        c.file("attempt", "v1:" + BOOT + "\n");
        assert(s.blocks_transactions(BOOT) && !s.blocks_transactions(NEXT_BOOT));
        assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "PREPARATION_INTERRUPTED"));
        assert(prepares == 0);
        c.file("requested", "v1:1\n");
        assert(s.prepare_boot(NEXT_BOOT, prepare).mode == Mode::Load && prepares == 1);
        assert(!s.blocks_transactions(NEXT_BOOT));
        ++tests;
    }
    {
        Case c; auto s = c.store(); prepares = 0;
        c.file("attempt", "broken");
        assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "ATTEMPT_RECORD"));
        assert(fails([&] { s.blocks_transactions(BOOT); }, "ATTEMPT_RECORD"));
        assert(prepares == 0 && !s.read(BOOT).effective);
        ++tests;
    }
    {
        Case c; auto s = c.store(); c.file("attempt", "v1:" + BOOT + "\n");
        s.publish({Mode::Load, 1, BOOT});
        assert(!s.blocks_transactions(BOOT));
        assert(s.prepare_boot(BOOT, broken_backend).mode == Mode::Load);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        pid_t pid = fork();
        assert(pid >= 0);
        if (pid == 0) { s.prepare_boot(BOOT, crashing_backend); _exit(99); }
        int status = 0;
        assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 23);
        assert(s.blocks_transactions(BOOT) && !s.read(BOOT).effective);
        prepares = 0;
        assert(fails([&] { s.prepare_boot(BOOT, prepare); }, "PREPARATION_INTERRUPTED"));
        assert(prepares == 0);
        prepared_capabilities = 1;
        assert(s.prepare_boot(NEXT_BOOT, prepare).mode == Mode::Block && prepares == 1);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        const std::string report = "schema=1 operation=preflight boot=" + BOOT +
            "\nresult=failed reason=MODULE_POLICY_LOADER_IMAGE_UNVERIFIED\nEND\n";
        s.record_compatibility(report);
        s.record_compatibility(report);
        assert(c.text("compatibility.log") == report + report);
        struct stat st{};
        assert(stat((c.directory + "/compatibility.log").c_str(), &st) == 0);
        assert(st.st_uid == 0 && (st.st_mode & 0777) == 0600 && st.st_nlink == 1);
        assert(!s.read(BOOT).effective && s.read(BOOT).requested == Mode::Block);
        ++tests;
    }
    {
        Case c; auto s = c.store();
        const std::string record(8192, 'a');
        for (unsigned i = 0; i < 8; ++i) s.record_compatibility(record);
        assert(c.text("compatibility.log") == std::string(65536, 'a'));
        assert(access((c.directory + "/compatibility.previous.log").c_str(), F_OK) != 0);
        s.record_compatibility("next\nEND\n");
        assert(c.text("compatibility.previous.log") == std::string(65536, 'a'));
        assert(c.text("compatibility.log") == "next\nEND\n");
        s.record_compatibility(std::string(8193, 'b'));
        s.record_compatibility("");
        assert(c.text("compatibility.log") == "next\nEND\n");
        ++tests;
    }
    {
        Case c; auto s = c.store();
        c.file(".lock", "");
        int held = open((c.directory + "/.lock").c_str(), O_RDWR | O_CLOEXEC);
        assert(held >= 0 && flock(held, LOCK_EX | LOCK_NB) == 0);
        s.record_compatibility("independent\nEND\n");
        assert(c.text("compatibility.log") == "independent\nEND\n");
        close(held);
        c.file(".diagnostics.lock", "");
        held = open((c.directory + "/.diagnostics.lock").c_str(), O_RDWR | O_CLOEXEC);
        assert(held >= 0 && flock(held, LOCK_EX | LOCK_NB) == 0);
        s.record_compatibility("busy\nEND\n");
        assert(c.text("compatibility.log") == "independent\nEND\n");
        close(held);
        s.record_compatibility("after\nEND\n");
        assert(c.text("compatibility.log") == "independent\nEND\nafter\nEND\n");
        ++tests;
    }
    for (unsigned type : {0U, 1U, 2U, 3U}) {
        Case c; auto s = c.store(); c.file("outside", "unchanged");
        auto log = c.directory + "/compatibility.log";
        if (type == 0) assert(symlink((c.directory + "/outside").c_str(), log.c_str()) == 0);
        if (type == 1) assert(link((c.directory + "/outside").c_str(), log.c_str()) == 0);
        if (type == 2) assert(mkfifo(log.c_str(), 0600) == 0);
        if (type == 3) {
            c.file("compatibility.log", "unchanged");
            assert(chmod(log.c_str(), 0666) == 0);
        }
        s.record_compatibility("ignored\nEND\n");
        assert(c.text("outside") == "unchanged");
        assert(!s.read(BOOT).effective);
        ++tests;
    }
    {
        Store absent(-1);
        absent.record_compatibility("ignored\nEND\n");
        ++tests;
    }
    {
        // A panic/process death leaves an attempt without the same boot's
        // publication. The next kernel boot must load normally before retry.
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        prepares = 0; prepared_capabilities = 3;
        const auto ready = s.prepare_boot(NEXT_BOOT, prepare, true);
        assert(ready.mode == Mode::Load && ready.capabilities == 1 && prepares == 1);
        assert(prepared_mode == Mode::Load && !prepared_unverified);
        const auto observed = s.read(NEXT_BOOT);
        assert(observed.hide_failed && observed.requested == Mode::Load);
        assert(!s.blocks_transactions(NEXT_BOOT, true));
        assert(c.text("compatibility.log").find("PREVIOUS_BOOT_INTERRUPTED") != std::string::npos);
        ++tests;
    }
    {
        // A completed previous boot is not mistaken for an interrupted attempt.
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        s.publish({Mode::Hide, 3, BOOT});
        prepares = 0; prepared_capabilities = 3;
        assert(s.prepare_boot(NEXT_BOOT, prepare, true).mode == Mode::Hide && prepares == 1);
        assert(prepared_mode == Mode::Hide && !s.read(NEXT_BOOT).hide_failed);
        ++tests;
    }
    for (const bool hook : {false, true}) {
        // A late-boot Hide panic leaves hook-pending even when an older Load
        // result exists. The next boot must not repeat that hidden install.
        Case c; auto s = c.store();
        c.file("requested", "v1:3\n");
        c.file("attempt", "v1:" + BOOT + "\n");
        c.file("hook-pending", "v1:" + BOOT + "\n");
        s.publish({Mode::Load, 1, BOOT});
        prepares = 0; prepared_capabilities = 3;
        const auto ready = hook ? s.prepare_hook(NEXT_BOOT, {}, prepare) : s.prepare_boot(NEXT_BOOT, prepare);
        assert(ready.mode == Mode::Load && ready.capabilities == 1);
        assert(prepares == 1 && prepared_mode == Mode::Load && !prepared_unverified);
        assert(s.read(NEXT_BOOT).hide_failed && s.read(NEXT_BOOT).requested == Mode::Load);
        assert(!s.blocks_transactions(NEXT_BOOT, true));
        assert(c.text("compatibility.log").find("PREVIOUS_BOOT_INTERRUPTED") != std::string::npos);
        ++tests;
    }
    printf("PASS %u module policy configuration cases\n", tests);
}
