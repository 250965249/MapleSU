// MapleSU module install implementation.
//
#include "miss_a_native_private.h"
#include "module_state_private.h"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <vector>
#include "zip.h"

// forked mutation worker through the module-control bridge instead of calling
// `default_modules::module_root::set_current_root` / `_exit` directly.
// .text+0x810 and .text+0xd54 -> maplesu_lock_module_root; +0x270, +0xb7c
// (exit code 127) and +0x13e0 (exit code 0) -> maplesu_module_worker_exit;
extern "C" KModErr maplesu_lock_module_root(bool allow);
extern "C" [[noreturn]] void maplesu_module_worker_exit(int code);

namespace file_utils {
enum class SelinuxFileFlag : int { System = 0, Kernel = 1 };
static bool file_exists(const std::filesystem::path& path) {
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}
static bool delete_path(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    return !file_exists(path);
}
static bool create_directory_if_not_exists(const char* path) {
    if (!file_exists(path)) {
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
    }
    return file_exists(path);
}
static bool set_file_selinux_access_mode(const char* path, SelinuxFileFlag flag) {
    if (chmod(path, 0777) != 0) return false;
    const char* context = flag == SelinuxFileFlag::System
        ? "u:object_r:system_file:s0" : "u:object_r:kernel:s0";
    return setxattr(path, "security.selinux", context, strlen(context) + 1, 0) == 0;
}
static bool read_text_file(const char* path, std::string& text) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    file.seekg(0, std::ios::end);
    std::streamoff size = file.tellg();
    if (size < 0) return false;
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes;
    bytes.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(bytes.data()), size)) return false;
    text.assign(bytes.begin(), bytes.end());
    return true;
}
}

namespace maplesu::sdk {
KModErr find_module_elf_in_zip(const char*, module_desc&, std::string&);
KModErr unsafe_reset_autorun_bootstrap_safe_flag();
KModErr unsafe_uninstall_module(const char*, bool);
namespace features::callback {
KModErr invoke_module_on_install(const std::string&, std::string&);
KModErr invoke_module_on_uninstall(const std::string&);
}

// repeating the first byte selects the system directory.
static std::string get_kernel_file_dir_name() {
    return std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW()).substr(0, 16);
}
static std::string get_kernel_file_dir_path() {
    char path[1024] = {};
    snprintf(path, sizeof(path), "/data/%s/", get_kernel_file_dir_name().c_str());
    return path;
}
static std::string get_system_file_dir_path() {
    std::string head = get_kernel_file_dir_name();
    char path[1024] = {};
    snprintf(path, sizeof(path), "/data/%s/", (head + head[0]).c_str());
    return path;
}
static std::string get_module_private_dir_path(const char* id) {
    return (std::filesystem::path((std::filesystem::path(get_system_file_dir_path()) / "modules" / "").string()) / id / "").string();
}

KModErr unsafe_uninstall_module(const char* id, bool callback) {
    RETURN_IF_ERROR(maplesu_lock_module_root(true));
    if (callback) features::callback::invoke_module_on_uninstall(std::string(id));
    std::string module_path = get_module_private_dir_path(id);
    std::string storage_path = (std::filesystem::path((std::filesystem::path(get_system_file_dir_path()) / "storage" / "").string()) / id / "").string();
    if (!file_utils::delete_path(module_path) || !file_utils::delete_path(storage_path))
        return KModErr::ERR_MODULE_DEL_DIR;
    RETURN_IF_ERROR(unsafe_reset_autorun_bootstrap_safe_flag());
    RETURN_IF_ERROR(maplesu::module_state::add(maplesu::module_state::List::Removed, std::string(id)));
    RETURN_IF_ERROR(maplesu::module_state::remove(maplesu::module_state::List::PendingRunOnce, std::string(id)));
    return maplesu::module_state::remove(maplesu::module_state::List::FinishedRunOnce, std::string(id));
}

// parent waits even when its error-code frame could not be read.
KModErr safe_uninstall_module(const char* id) {
    fork_pipe_info pipe;
    KModErr err = KModErr::OK;
    if (fork_pipe_child_process(pipe)) {
        err = unsafe_uninstall_module(id, true);
        write_errcode_from_child(pipe, err);
        pipe.close_all();
        maplesu_module_worker_exit(0);
    }
    if (!read_errcode_from_child(pipe, err)) err = KModErr::ERR_READ_CHILD_ERRCODE;
    int status = 0;
    waitpid(pipe.child_pid, &status, 0);
    return err;
}

// before the writer callback; directory entries (a terminal '/') are skipped.
static KModErr unzip_module_file(const char* archive_path, const module_desc& desc, const char* elf_name) {
    KModErr err = KModErr::OK;
    std::string archive_name(archive_path);
    std::function<bool(const std::string&, std::vector<uint8_t>&&)> writer =
        [&err, &desc, elf_name](const std::string& name, std::vector<uint8_t>&& bytes) {
        std::string destination;
        if (name == elf_name) {
            // itself; spelling the pointer out keeps both objects' template
            // instantiation sets equal.
            const char* id32 = desc.id32;
            destination = strlen(desc.id32) == 0 ? std::string()
                : (std::filesystem::path(get_module_private_dir_path(id32)) / id32).string();
        } else {
            destination = get_module_private_dir_path(desc.id32);
            destination.append(name);
        }
        const char* path = destination.c_str();
        std::filesystem::path file_path(path);
        std::filesystem::path parent = file_path.parent_path();
        if (!parent.empty()) {
            if (!file_utils::create_directory_if_not_exists(parent.string().c_str())) {
                err = KModErr::ERR_MODULE_CREATE_DIR; return false;
            }
            if (!file_utils::set_file_selinux_access_mode(parent.string().c_str(), file_utils::SelinuxFileFlag::System)) {
                err = KModErr::ERR_SET_FILE_SELINUX; return false;
            }
        }
        if (!file_utils::delete_path(file_path)) { err = KModErr::ERR_MODULE_DEL_FILE; return false; }
        std::ofstream output(path, std::ios::out | std::ios::binary);
        if (!output.is_open()) { err = KModErr::ERR_MODULE_OPEN_FILE; return false; }
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.close();
        err = file_utils::set_file_selinux_access_mode(path, file_utils::SelinuxFileFlag::System)
            ? KModErr::OK : KModErr::ERR_SET_FILE_SELINUX;
        return err == KModErr::OK;
    };
    int zip_error = 0;
    zip_t* archive = zip_open(archive_name.c_str(), 0, &zip_error);
    if (!archive) {
        char message[128];
        zip_error_to_str(message, sizeof(message), zip_error, errno);
        std::cerr << "Failed to open archive: " << message << std::endl;
        return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
    }
    zip_file_t* input = nullptr;
    try {
        zip_int64_t count = zip_get_num_entries(archive, 0);
        for (zip_uint64_t i = 0; i != static_cast<zip_uint64_t>(count); ++i) {
            zip_stat_t stat;
            if (zip_stat_index(archive, i, 0, &stat) != 0) {
                std::cerr << "zip_stat_index failed at index " << i << ": " << zip_strerror(archive) << std::endl;
                zip_close(archive); return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
            }
            const char* raw_name = zip_get_name(archive, i, 0);
            if (!raw_name) {
                std::cerr << "zip_get_name failed at index " << i << ": " << zip_strerror(archive) << std::endl;
                zip_close(archive); return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
            }
            std::string name(raw_name);
            if (!name.empty() && name.back() == '/') continue;
            input = zip_fopen_index(archive, i, 0);
            if (!input) {
                std::cerr << "Failed to open file " << name << ": " << zip_strerror(archive) << std::endl;
                zip_close(archive); return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
            }
            std::vector<uint8_t> bytes;
            bytes.reserve(stat.size);
            uint8_t buffer[8192];
            zip_int64_t n;
            while ((n = zip_fread(input, buffer, sizeof(buffer))) > 0)
                bytes.insert(bytes.end(), buffer, buffer + n);
            if (n < 0) {
                std::cerr << "Failed to read file " << name << ": " << zip_file_strerror(input) << std::endl;
                zip_fclose(input); input = nullptr;
                zip_close(archive); return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
            }
            int closed = zip_fclose(input); input = nullptr;
            if (closed != 0) {
                std::cerr << "Failed to close file " << name << ": " << zip_strerror(archive) << std::endl;
                zip_close(archive); return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
            }
            if (!writer(name, std::move(bytes))) { zip_close(archive); return err; }
        }
        zip_close(archive);
    } catch (...) {
        if (input) zip_fclose(input);
        zip_close(archive);
        throw;
    }
    return err;
}

// It never expands variables or interprets metacharacters; execution status is ignored.
static void run_single_module_command(const char* command) {
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        if (!command || !*command) maplesu_module_worker_exit(127);
        char* text = strdup(command);
        if (!text) maplesu_module_worker_exit(127);
        size_t count = 0, capacity = 8;
        char** args = static_cast<char**>(calloc(capacity + 1, sizeof(char*)));
        if (!args) { free(text); maplesu_module_worker_exit(127); }
        char* p = text;
        while (*p) {
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') ++p;
            if (!*p) break;
            if (count == capacity) {
                size_t next = capacity * 2;
                char** resized = static_cast<char**>(realloc(args, (next + 1) * sizeof(char*)));
                if (!resized) { free(args); free(text); maplesu_module_worker_exit(127); }
                memset(resized + capacity, 0, (next + 1 - capacity) * sizeof(char*));
                args = resized; capacity = next;
            }
            args[count++] = p;
            if (*p == '\'' || *p == '"') {
                char quote = *p++;
                args[count - 1] = p;
                while (*p && *p != quote) ++p;
                if (*p) *p++ = 0;
            } else {
                while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') ++p;
                if (*p) *p++ = 0;
            }
        }
        if (count) { args[count] = nullptr; execve(args[0], args, environ); }
        free(args); free(text); maplesu_module_worker_exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
}

// state-list updates. Only an explicit install rejection invokes uninstall rollback.
KModErr safe_install_module(const char* archive, bool run_once, std::string& reason) {
    fork_pipe_info pipe;
    KModErr err = KModErr::OK;
    if (fork_pipe_child_process(pipe)) {
        err = [&]() -> KModErr {
            RETURN_IF_ERROR(maplesu_lock_module_root(true));
            module_desc desc;
            std::string elf_name;
            RETURN_IF_ERROR(find_module_elf_in_zip(archive, desc, elf_name));
            MapleSUSdkVersion version = get_sdk_version(), minimum;
            sscanf("4.0.5", "%u.%u.%u", &minimum.major, &minimum.minor, &minimum.patch);
            if (version < desc.min_sdk_ver) return KModErr::ERR_MODULE_REQUIRE_MIN_SDK;
            if (desc.min_sdk_ver < minimum) return KModErr::ERR_MODULE_SDK_TOO_OLD;
            {
                std::string path = get_module_private_dir_path(desc.id32);
                if (!file_utils::create_directory_if_not_exists(path.c_str())) return KModErr::ERR_MODULE_CREATE_DIR;
                if (!file_utils::set_file_selinux_access_mode(path.c_str(), file_utils::SelinuxFileFlag::System))
                    return KModErr::ERR_SET_FILE_SELINUX;
            }
            RETURN_IF_ERROR(unzip_module_file(archive, desc, elf_name.c_str()));
            std::string path = get_module_private_dir_path(desc.id32);
            std::filesystem::path root(path);
            chmod(root.c_str(), 0777);
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) chmod(entry.path().c_str(), 0777);
            KModErr result = features::callback::invoke_module_on_install(std::string(desc.id32), reason);
            if (result == KModErr::ERR_MODULE_REJECT_INSTALL) {
                unsafe_uninstall_module(desc.id32, false);
                return result;
            }
            if (result != KModErr::OK) return result;
            RETURN_IF_ERROR(unsafe_reset_autorun_bootstrap_safe_flag());
            RETURN_IF_ERROR(maplesu::module_state::remove(maplesu::module_state::List::FinishedRunOnce, std::string(desc.id32)));
            if (run_once) {
                RETURN_IF_ERROR(maplesu::module_state::add(maplesu::module_state::List::PendingRunOnce, std::string(desc.id32)));
            } else {
                RETURN_IF_ERROR(maplesu::module_state::remove(maplesu::module_state::List::PendingRunOnce, std::string(desc.id32)));
            }
            RETURN_IF_ERROR(maplesu_lock_module_root(true));
            std::string mode_path = (std::filesystem::path(get_kernel_file_dir_path()) / "install.mode").string();
            if (!file_utils::file_exists(mode_path)) return KModErr::ERR_MODULE_FILE_NOT_EXIST;
            std::string mode;
            if (!file_utils::read_text_file(mode_path.c_str(), mode)) return KModErr::ERR_MODULE_READ_FILE;
            if (mode != "hotload") return KModErr::OK;
            std::vector<std::string> removed;
            RETURN_IF_ERROR(maplesu::module_state::read(maplesu::module_state::List::Removed, removed));
            if (std::find(removed.begin(), removed.end(), desc.id32) == removed.end()) {
                std::string command = (std::filesystem::path(get_kernel_file_dir_path()) / "init").string()
                    + " --load-single-module " + desc.id32;
                run_single_module_command(command.c_str());
            }
            return KModErr::OK;
        }();
        write_errcode_from_child(pipe, err);
        write_string_from_child(pipe, reason);
        pipe.close_all();
        maplesu_module_worker_exit(0);
    }
    if (!read_errcode_from_child(pipe, err)) err = KModErr::ERR_READ_CHILD_ERRCODE;
    if (!read_string_from_child(pipe, reason)) err = KModErr::ERR_READ_CHILD_STRING;
    int status = 0;
    waitpid(pipe.child_pid, &status, 0);
    return err;
}

}  // namespace maplesu::sdk
