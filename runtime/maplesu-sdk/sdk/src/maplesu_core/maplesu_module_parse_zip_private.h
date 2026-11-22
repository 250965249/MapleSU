#pragma once
// Member 57 private declarations -- maplesu_module_parse_zip.o
//
// The vendor compiled this TU against three private headers that are not part
// native ELF member 3fb3e1d5c2b72195422f91adf70fc23bee64a7819df2e020d3da6b8544cb04e6:
//
//   %"struct.maplesu::sdk::module_desc"      = { [1024 x i8], [1024 x i8],
//                                              [4096 x i8], [1024 x i8],
//                                              [1024 x i8], [1024 x i8],
//                                              i8,
//                                              %"struct.maplesu::sdk::MapleSUSdkVersion" }
//   %"struct.maplesu::sdk::MapleSUSdkVersion" = { i32, i32, i32 }
//   %"class.maplesu::sdk::fork_base_info"    = { i32, i32, i32, i32, i32, i32 }
//   %"class.maplesu::sdk::fork_pipe_info"    = { %"class.maplesu::sdk::fork_base_info" }
//
//   _ZN15default_modules11module_root16set_current_rootEb

#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

// 9220), exactly like member 54/58/60 do.  Keep the packed spellings out of
// the way while the umbrella header is parsed, then define the natural layout.
#define module_desc public_packed_module_desc
#define module_record public_packed_module_record
#include "kernel_module_kit_umbrella.h"
#undef module_desc
#undef module_record

namespace default_modules::module_root {
KModErr set_current_root(bool enabled);
}  // namespace default_modules::module_root

namespace maplesu::sdk {

struct module_desc {
    char name[1024] = {};
    char version[1024] = {};
    char desc[4096] = {};
    char author[1024] = {};
    char id32[1024] = {};
    char update_json[1024] = {};
    bool web_ui = false;
    MapleSUSdkVersion min_sdk_ver = {};
};
static_assert(sizeof(module_desc) == 9232, "unexpected layout size");
static_assert(alignof(module_desc) == 4, "layout constraint violated");
static_assert(offsetof(module_desc, name) == 0, "layout constraint violated");
static_assert(offsetof(module_desc, version) == 1024, "layout constraint violated");
static_assert(offsetof(module_desc, desc) == 2048, "layout constraint violated");
static_assert(offsetof(module_desc, author) == 6144, "layout constraint violated");
static_assert(offsetof(module_desc, id32) == 7168, "layout constraint violated");
static_assert(offsetof(module_desc, update_json) == 8192, "layout constraint violated");
static_assert(offsetof(module_desc, web_ui) == 9216, "layout constraint violated");
static_assert(offsetof(module_desc, min_sdk_ver) == 9220, "layout constraint violated");

//     %"class.maplesu::sdk::fork_pipe_info" = { %fork_base_info }
// the TU keeps emitting the same weak definitions and the same getpid/close
class fork_base_info {
public:
    int fd_parent_to_child_read = -1;
    int fd_parent_to_child_write = -1;
    int fd_child_to_parent_read = -1;
    int fd_child_to_parent_write = -1;
    int self_pid = -1;
    int child_pid = -1;

    fork_base_info() { reset(); }
    ~fork_base_info() { close_all(); }

    static void safe_close(int& fd) {
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
    }

    void close_all() {
        safe_close(fd_parent_to_child_read);
        safe_close(fd_parent_to_child_write);
        safe_close(fd_child_to_parent_read);
        safe_close(fd_child_to_parent_write);
    }

    void reset() {
        close_all();
        fd_parent_to_child_read = -1;
        fd_parent_to_child_write = -1;
        fd_child_to_parent_read = -1;
        fd_child_to_parent_write = -1;
        self_pid = getpid();
        child_pid = 0;
    }
};
class fork_pipe_info : public fork_base_info {};
static_assert(sizeof(fork_base_info) == 24, "layout constraint violated");
static_assert(alignof(fork_base_info) == 4, "layout constraint violated");
static_assert(sizeof(fork_pipe_info) == 24, "layout constraint violated");
static_assert(offsetof(fork_base_info, child_pid) == 20, "layout constraint violated");

// installer member (see manifest 0056); only the prototypes live here.
bool fork_pipe_child_process(fork_pipe_info& info);
bool write_errcode_from_child(const fork_pipe_info& info, KModErr err);
bool read_errcode_from_child(const fork_pipe_info& info, KModErr& err);
bool write_transfer_data_from_child(const fork_pipe_info& info,
                                    const std::vector<uint8_t>& data);
bool read_transfer_data_from_child(fork_pipe_info& info, std::vector<uint8_t>& data);

KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>& elf_bytes,
                                         module_desc& out_desc);

std::vector<uint8_t> serialize_module_descs(const std::vector<module_desc>& descs);
std::vector<module_desc> deserialize_module_descs(const std::vector<uint8_t>& data);

// member, i.e. linkable inside the consumer DSO but not re-exported from it).
__attribute__((visibility("hidden")))
KModErr find_module_elf_in_zip(const char* module_zip_path, module_desc& out_desc,
                               std::string& out_elf_name);
__attribute__((visibility("hidden")))
KModErr safe_parse_module_desc_from_zip_file(const char* module_zip_path,
                                             module_desc& out_desc);

}  // namespace maplesu::sdk
