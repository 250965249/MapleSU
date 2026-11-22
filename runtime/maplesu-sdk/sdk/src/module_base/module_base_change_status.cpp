// module base change status implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "private_file_utils.h"
#include "private_maple_runtime.h"
#include "private_maplesu_paths.h"
#include "../maplesu/compat/module_status_exports_legacy_abi.h"

namespace kernel_module {

//   std::vector<maplesu::sdk::module_record> modules;            (memset 0)
//   maplesu::sdk::unsafe_get_all_modules(modules);               (返回值丢弃)
//   for (it = begin; it != end; ++it) {
//       id32 = __get_current_module_id32_...();                (每轮都取)
//       if (strcmp(it->desc.id32, id32) == 0) return it->state;
//   }
//   return 0;                                                  (NotRunning)
//
// module_record 的字节布局来自 maplesu_sdk/maplesu_module.h（packed），
maplesu::sdk::ModuleRunState get_current_module_run_state() {
    std::vector<maplesu::sdk::module_record> modules;
    (void)maplesu::sdk::unsafe_get_all_modules(modules);

    for (const maplesu::sdk::module_record& record : modules) {
        const char* current_id32 = __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c();
        if (strcmp(record.desc.id32, current_id32) == 0) {
            return record.state;
        }
    }

    // 未找到当前模块：按枚举 0（ModuleRunState::NotRunning）返回。
    return static_cast<maplesu::sdk::ModuleRunState>(0);
}

//   const char* id32 = __get_current_module_id32_...();
//   std::filesystem::path dir  = maplesu::sdk::get_system_file_dir_path();
//   std::string out_path       = dir / "modules_new_state" / id32;
//   errno = 0;
//   if (out_path.c_str() != nullptr) {
//       std::ofstream ofs(out_path.c_str(), 52);   // out|trunc|binary
//       if ((ofs.rdstate() & (badbit|failbit)) == 0) {      // (state & 5) == 0
//           ofs.write(&new_state, 4);
//           ok = ofs.good();                                // state == 0
//       }
//   }
//   if (ok) { file_utils::set_file_selinux_access_mode(out_path.c_str(), ...); return; }
//   printf("[MapleSU] set_current_module_run_state failed: id32=%s, state=%u, errno=%d (%s)\n",
//          id32 ? id32 : "(null)", (unsigned)new_state, errno,
//          errno ? strerror(errno) : "unknown");
//
// 立即数实参（basic_ofstream ctor 第二参数 i32 52）。
void set_current_module_run_state(maplesu::sdk::ModuleRunState new_state) {
    const char* id32 = __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c();

    std::filesystem::path state_dir = maplesu::sdk::get_system_file_dir_path();
    std::filesystem::path state_file = state_dir / "modules_new_state" / id32;
    std::string out_path = state_file;  // path -> string（libc++ path 内嵌 string）

    errno = 0;

    bool written = false;
    const char* out_cstr = out_path.c_str();
    if (out_cstr != nullptr) {
        std::ofstream ofs(out_cstr, std::ios::out | std::ios::trunc | std::ios::binary);
        if ((ofs.rdstate() & (std::ios::badbit | std::ios::failbit)) == 0) {
            const uint32_t state_value = static_cast<uint32_t>(new_state);
            ofs.write(reinterpret_cast<const char*>(&state_value), sizeof(state_value));
            written = ofs.good();
        }
    }

    if (written) {
        // 写完立刻修权限 + SELinux 标签，避免下次启动读到半成品。
        file_utils::set_file_selinux_access_mode(out_cstr, file_utils::SelinuxFileFlag::Default);
        return;
    }

    const int saved_errno = errno;
    printf("[MapleSU] set_current_module_run_state failed: id32=%s, state=%u, errno=%d (%s)\n",
           id32 != nullptr ? id32 : "(null)",
           static_cast<unsigned>(new_state),
           saved_errno,
           saved_errno != 0 ? strerror(saved_errno) : "unknown");
}

//   std::string desc;                                  (默认空串)
//   if (new_description != nullptr) desc.assign(new_description);
//   const char* id32 = __get_current_module_id32_...();
//   std::filesystem::path dir = maplesu::sdk::get_system_file_dir_path();
//   std::string out_path      = dir / "modules_new_desc" / id32;
//   if (out_path.c_str() != nullptr) {
//       std::ofstream ofs(out_path.c_str(), 48);       // out|trunc（文本模式）
//       if (ofs.rdbuf() == nullptr)  -> 失败日志
//       else {
//           if (ofs.good()) -> set_file_selinux_access_mode(); return;
//           else            -> 失败日志
//       }
//   } else 失败日志
//
// 48 == std::ios::out(16) | std::ios::trunc(32)；与运行态不同，描述按文本写。
// 传入 nullptr 或 "" 时写入空内容（头文件注释所说的“恢复默认描述”由读取侧
void set_current_module_description_with_str(const char* new_description) {
    std::string description;
    if (new_description != nullptr) {
        description.assign(new_description);
    }

    const char* id32 = __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c();

    std::filesystem::path desc_dir = maplesu::sdk::get_system_file_dir_path();
    std::filesystem::path desc_file = desc_dir / "modules_new_desc" / id32;
    std::string out_path = desc_file;

    std::string_view body(description);

    bool written = false;
    const char* out_cstr = out_path.c_str();
    if (out_cstr != nullptr) {
        std::ofstream ofs(out_cstr, std::ios::out | std::ios::trunc);
        if (ofs.rdbuf() == nullptr) {
            written = false;
        } else {
            ofs << body;
            written = ofs.good();
        }
    }

    if (written) {
        file_utils::set_file_selinux_access_mode(out_path.c_str(),
                                                file_utils::SelinuxFileFlag::Default);
        return;
    }

    const int saved_errno = errno;
    printf("[MapleSU] set_current_module_description failed: id32=%s, errno=%d (%s)\n",
           id32 != nullptr ? id32 : "(null)",
           saved_errno,
           saved_errno != 0 ? strerror(saved_errno) : "unknown");
}

}  // namespace kernel_module

namespace maplesu::compat {
void set_current_module_run_state_legacy(sdk::ModuleRunState state) {
    kernel_module::set_current_module_run_state(state);
}
} // namespace maplesu::compat
