#include "maplesu_module_environment_private.h"
#include <cstdio>
#include <cstdlib>
#include <map>
#include <sys/wait.h>

namespace {
std::string directory;
KModErr scope_error = KModErr::OK;
int checks;
#define CHECK(value) do { ++checks; if (!(value)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #value); std::exit(1); } } while (0)
void write_mode(const char* text, mode_t mode = 0600) {
    const std::string path = directory + "/install.mode";
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    CHECK(fd >= 0);
    CHECK(write(fd, text, std::strlen(text)) == static_cast<ssize_t>(std::strlen(text)));
    CHECK(!close(fd) && !chmod(path.c_str(), mode));
}
std::map<std::string, std::string> values(maplesu::module_environment::Environment& environment) {
    std::map<std::string, std::string> result;
    for (char* const* item = environment.data(); *item; ++item) {
        const std::string value(*item);
        CHECK(result.emplace(value.substr(0, value.find('=')), value.substr(value.find('=') + 1)).second);
    }
    return result;
}
}

namespace maplesu::storage {
KModErr current_kernel_directory(std::string& out) { out = directory + "/"; return scope_error; }
}

int main() {
    CHECK(getuid() == 0);
    directory = "/tmp/module-environment-" + std::to_string(getpid());
    CHECK(!mkdir(directory.c_str(), 0700));
    const std::string path = directory + "/install.mode";
    char* inherited[] = {const_cast<char*>("PATH=/usr/bin:/bin"), const_cast<char*>("KEEP=original"),
        const_cast<char*>("KSU_VER=forged"), const_cast<char*>("KSU_VER_CODE=99999"),
        const_cast<char*>("KSU_KERNEL_VER_CODE=32650"), const_cast<char*>("KSU_UAPI_VER=7"),
        const_cast<char*>("KSU_RUNTIME_MODE=built-in"), const_cast<char*>("KSU_LATE_LOAD=1"),
        const_cast<char*>("KSU_MODULE=forged"), const_cast<char*>("MAPLESU_KSU_COMPAT=forged"),
        const_cast<char*>("MAPLESU_RUNTIME_MODE=forged"), nullptr};
    maplesu::module_environment::Environment environment;
    auto capture = [&] { return static_cast<int64_t>(maplesu::module_environment::capture(5, 2, 1, inherited, environment)); };
    write_mode("boot");
    CHECK(capture() == 0);
    auto facts = values(environment);
    CHECK(facts["KSU_VER"] == "MapleSU 5.2.1" && facts["KSU_VER_CODE"] == "50201");
    CHECK(facts["KSU_KERNEL_VER_CODE"] == "0" && facts["KSU_UAPI_VER"] == "0");
    CHECK(facts["KSU_RUNTIME_MODE"] == "lkm" && facts["MAPLESU_RUNTIME_MODE"] == "boot");
    CHECK(facts["MAPLESU_KSU_COMPAT"] == "1" && facts["KEEP"] == "original");
    CHECK(!facts.count("KSU_LATE_LOAD") && !facts.count("KSU_MODULE"));
    CHECK(!std::getenv("KSU_VER"));
    const pid_t apply_child = fork(); CHECK(apply_child >= 0);
    if (!apply_child) {
        setenv("KSU_LATE_LOAD", "1", 1); setenv("KSU_MODULE", "forged", 1);
        {
            maplesu::module_environment::Environment local;
            if (is_failed(maplesu::module_environment::capture(5, 2, 1, environ, local)) ||
                is_failed(local.apply())) _exit(98);
        }
        setenv("AFTER_MODULE_SETENV", "owned", 1);
        _exit(!getenv("KSU_LATE_LOAD") && !getenv("KSU_MODULE") &&
            !strcmp(getenv("KSU_VER"), "MapleSU 5.2.1") && !strcmp(getenv("KSU_RUNTIME_MODE"), "lkm") ? 0 : 1);
    }
    int status = 0;
    CHECK(waitpid(apply_child, &status, 0) == apply_child && WIFEXITED(status) && !WEXITSTATUS(status));
    write_mode("hotload");
    CHECK(capture() == 0);
    facts = values(environment);
    CHECK(facts["KSU_RUNTIME_MODE"] == "late-load" && facts["KSU_LATE_LOAD"] == "1" &&
        facts["MAPLESU_RUNTIME_MODE"] == "hotload");
    const pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        char* args[] = {const_cast<char*>("/bin/sh"), const_cast<char*>("-c"),
            const_cast<char*>("test \"$KSU_VER_CODE:$KSU_KERNEL_VER_CODE:$KSU_UAPI_VER:$KSU_RUNTIME_MODE:$KSU_LATE_LOAD:$KEEP\" = 50201:0:0:late-load:1:original"), nullptr};
        execve(args[0], args, environment.data());
        _exit(99);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    write_mode("invalid"); CHECK(capture() == -EINVAL && !*environment.data());
    write_mode("boot\n"); CHECK(capture() == -EINVAL);
    write_mode("boot", 0666); CHECK(capture() == -EINVAL);
    write_mode("boot");
    CHECK(!link(path.c_str(), (path + ".link").c_str())); CHECK(capture() == -EINVAL);
    CHECK(!unlink((path + ".link").c_str()) && !unlink(path.c_str()));
    CHECK(!symlink("missing", path.c_str())); CHECK(capture() == -ELOOP);
    CHECK(!unlink(path.c_str())); CHECK(capture() == -ENOENT);
    CHECK(!mkdir(path.c_str(), 0700)); CHECK(capture() == -EINVAL); CHECK(!rmdir(path.c_str()));
    write_mode("boot"); CHECK(!chmod(directory.c_str(), 0777)); CHECK(capture() == -EACCES);
    CHECK(!chmod(directory.c_str(), 0700));
    scope_error = KModErr::ERR_MODULE_ROOT_KEY;
    CHECK(capture() == static_cast<int64_t>(scope_error) && !*environment.data());
    scope_error = KModErr::OK;
    const pid_t ordinary = fork(); CHECK(ordinary >= 0);
    if (!ordinary) { if (setuid(65534)) _exit(99); _exit(capture() == -EACCES ? 0 : 1); }
    CHECK(waitpid(ordinary, &status, 0) == ordinary && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(!unlink(path.c_str()) && !rmdir(directory.c_str()));
    std::printf("PASS module environment: %d checks, protected facts and real child exec\n", checks);
}
