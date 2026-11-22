// MapleSU module list implementation.
//
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <new>
#include <set>
#include <string>
#include <vector>

#include "kernel_module_kit_umbrella.h"

#include "maplesu_module_list_private.h"
#include "module_state_private.h"

//     parse_module_meta_from_elf_bytes 的 module_desc& = dereferenceable(9232)，
//     __split_buffer<Item> 一次 new 92480 B / 10 = 9248 B = sizeof(Item)。
//   * 随包 include/ 树实测（本机 clang 17.0.2 打印 sizeof/alignof/offsetof）：
//     sizeof(module_desc)=9232 alignof=4 offsetof(min_sdk_ver)=9220
//     sizeof(module_record)=9236。
// 这些常量决定本成员与 maplesu_module_elf_meta.o / maplesu_module_control.o 的
// 二进制接口，必须钉死；布局漂移时这里先失败，而不是运行期越界。
static_assert(sizeof(maplesu::sdk::module_desc) == 9232, "unexpected layout size");
static_assert(alignof(maplesu::sdk::module_desc) == 4, "layout constraint violated");
static_assert(offsetof(maplesu::sdk::module_desc, min_sdk_ver) == 9220,
              "unexpected layout size");
static_assert(sizeof(maplesu::sdk::module_record) == 9236, "unexpected layout size");

namespace file_utils {

// 读整个文件到字节数组。失败返回 false（不改动 out_bytes）。
//     seekg(0,end) -> tellg()<0 检查 -> seekg(0,beg) -> resize(size) ->
//     read(buf,size) -> !fail()
static bool read_file_bytes(const char* file_path, std::vector<uint8_t>& out_bytes) {
    std::ifstream file_stream(file_path, std::ios::binary);
    if (!file_stream) {
        return false;
    }
    file_stream.seekg(0, std::ios::end);
    const std::streamoff file_size = file_stream.tellg();
    if (file_size < 0) {
        return false;
    }
    file_stream.seekg(0, std::ios::beg);
    out_bytes.resize(static_cast<size_t>(file_size));
    file_stream.read(reinterpret_cast<char*>(out_bytes.data()), file_size);
    return !file_stream.fail();
}

// 读文本文件到 std::string；读取失败返回 false。
static bool read_text_file(const char* file_path, std::string& out_text) {
    std::vector<uint8_t> file_bytes;
    const bool is_read_ok = read_file_bytes(file_path, file_bytes);
    if (is_read_ok) {
        out_text.assign(file_bytes.begin(), file_bytes.end());
    }
    return is_read_ok;
}

// 路径是否存在（不抛异常重载）。
static bool file_exists(const std::filesystem::path& path) {
    std::error_code error_code;
    return std::filesystem::exists(path, error_code);
}

}  // namespace file_utils

namespace maplesu::sdk {

// std::vector<std::string> -> std::set<std::string>（去重，供状态清单查表）
static std::set<std::string> v_to_s(const std::vector<std::string>& value_list) {
    std::set<std::string> value_set;
    for (const std::string& value : value_list) {
        value_set.insert(value);
    }
    return value_set;
}

// MapleSU 根目录名：当前模块 ROOT 密钥文本的前 16 个字符。
// 多个调用点共用同一份实现，不内联。
static __attribute__((noinline)) std::string get_kernel_file_dir_name() {
    const std::string root_key_text = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    return root_key_text.substr(0, 16);
}

// 目录名 = 前 16 字符 + 首字符（首字符重复一次）。
static std::string get_system_file_dir_name() {
    const std::string folder_head = get_kernel_file_dir_name();
    return folder_head + folder_head[0];
}

// MapleSU 系统文件目录:  "/data/<16 字符根密钥><根密钥首字符>/"
static std::string get_system_file_dir_path() {
    char path_buffer[1024] = {0};
    snprintf(path_buffer, sizeof(path_buffer), "/data/%s/", get_system_file_dir_name().c_str());
    return std::string(path_buffer);
}

// 模块清单目录:  <system>/modules/
static std::string get_module_list_dir_path() {
    return (std::filesystem::path(get_system_file_dir_path()) / "modules" / "").string();
}

// 某个模块的安装目录:  <module_list_dir>/<module_name>/
static std::string get_module_dir_path(const char* module_name) {
    return (std::filesystem::path(get_module_list_dir_path()) / module_name / "").string();
}

// 某个模块的 ELF 文件:  <module_list_dir>/<module_name>/<module_name>
//   （内层 !80 作用域）(path(get_module_list_dir_path()) / d_name / "")
//   （外层 !77 作用域）(path(内层结果) / d_name)
//   0x374-0x380 -> x1 = [sp+0x4958] = d_name ；0x3e0-0x3ec -> x1 = [sp+0x48b0] = d_name。
// 这两处是 5.0.5/5.2.0 共有的实现细节，按证据原样复刻，不做"修正"。
static std::string get_module_desc_file_path(const char* module_name) {
    if (strlen(module_name) == 0) {
        return std::string();
    }
    const std::string module_dir_path = get_module_dir_path(module_name);
    return (std::filesystem::path(module_dir_path) / module_name).string();
}

// std::vector<T> <-> 字节流（fork 父子进程之间传模块记录用）
// 因此这里用内部链接的模板实现，不产生额外导出符号。
namespace {

// 序列化：把 vector<T> 的裸字节放进 vector<uint8_t>。
template <typename T>
std::vector<uint8_t> records_to_bytes(const std::vector<T>& records) {
    std::vector<uint8_t> bytes(records.size() * sizeof(T));
    if (!bytes.empty()) {
        memcpy(bytes.data(), records.data(), bytes.size());
    }
    return bytes;
}

// 反序列化：字节数是 sizeof(T) 整数倍才接受，否则返回空 vector。
template <typename T>
std::vector<T> bytes_to_records(const std::vector<uint8_t>& bytes) {
    if (bytes.size() % sizeof(T) != 0) {
        return std::vector<T>();
    }
    std::vector<T> records(bytes.size() / sizeof(T));
    if (!records.empty()) {
        memcpy(records.data(), bytes.data(), records.size() * sizeof(T));
    }
    return records;
}

}  // namespace

// 枚举全部已安装模块（不做 root_key 校验的原始通道；由 safe_ 版在子进程里调用）
//
//   1. module_root::set_current_root(true)，失败直接返回该错误码
//   2. 读三份全局状态清单 -> std::set（running / abnormal / removed_pending_reboot）
//   3. opendir(<system>/modules/)；失败返回 ERR_MODULE_OPEN_DIR
//   4. 遍历目录项：跳过 "."、".."、非目录项
//        路径 = <modules>/<name>/<name>（见 get_module_desc_file_path 的实测说明）
//        不存在 / 读失败 / 解析失败 -> 跳过该项
//        parse_module_meta_from_elf_bytes 填 module_record.desc
//        状态清单命中 -> record.state = 1/2/3（未命中保持 NotRunning=0）
//        读 <system>/modules_new_state/<name>（4 字节）覆盖 state
//        读 <system>/modules_new_desc/<name>（文本）填 record.desc.desc
//        record.modify_time = stat(路径).st_mtime
//   5. closedir；按修改时间升序 std::sort；把 record 依次搬进 out_list
KModErr unsafe_get_all_modules(std::vector<module_record>& out_list) {
    const KModErr set_root_err = default_modules::module_root::set_current_root(true);
    if (is_failed(set_root_err)) {
        return set_root_err;
    }

    std::set<std::string> running_mod_list;              // 运行中
    std::set<std::string> abnormal_mod_list;             // 运行异常
    std::set<std::string> removed_pending_reboot_mod_list;  // 已删除待重启

    {
        std::vector<std::string> module_name_list;
        RETURN_IF_ERROR(maplesu::module_state::read(maplesu::module_state::List::Running, module_name_list));
        running_mod_list = v_to_s(module_name_list);
    }
    {
        std::vector<std::string> module_name_list;
        RETURN_IF_ERROR(maplesu::module_state::read(maplesu::module_state::List::Abnormal, module_name_list));
        abnormal_mod_list = v_to_s(module_name_list);
    }
    {
        std::vector<std::string> module_name_list;
        RETURN_IF_ERROR(maplesu::module_state::read(maplesu::module_state::List::Removed, module_name_list));
        removed_pending_reboot_mod_list = v_to_s(module_name_list);
    }

    // 3. 打开模块清单目录
    const std::string module_list_dir_path = get_module_list_dir_path();
    DIR* const module_list_dir = opendir(module_list_dir_path.c_str());
    if (module_list_dir == nullptr) {
        return KModErr::ERR_MODULE_OPEN_DIR;
    }

    // 目录项的中间结果：修改时间 + 已填好的模块记录。
    // 即它是本函数内的局部类型；sizeof == 8 + sizeof(module_record) + 对齐。
    struct Item {
        int64_t       modify_time;  // stat().st_mtime，排序键
        module_record record;       // 解析出来的模块记录
    };
    static_assert(sizeof(Item) == 9248, "unexpected layout size");

    std::vector<Item> module_items;
    module_items.reserve(10);

    // 4. 遍历目录
    for (struct dirent* dir_entry = readdir(module_list_dir);
         dir_entry != nullptr;
         dir_entry = readdir(module_list_dir)) {
        // 跳过 "." 与 ".."
        if (dir_entry->d_name[0] == '.' &&
            (dir_entry->d_name[1] == '\0' || (dir_entry->d_name[1] == '.' && dir_entry->d_name[2] == '\0'))) {
            continue;
        }
        // 只处理目录项
        if (dir_entry->d_type != DT_DIR) {
            continue;
        }

        // 之后所有 path(...) 构造都用"指针"重载（pathC2IPKcvE），而不是 char[256] 数组重载。
        const char* const module_name = dir_entry->d_name;

        const std::string module_desc_file_path = get_module_desc_file_path(module_name);
        if (!file_utils::file_exists(std::filesystem::path(module_desc_file_path))) {
            continue;
        }

        std::vector<uint8_t> module_elf_bytes;
        if (!file_utils::read_file_bytes(module_desc_file_path.c_str(), module_elf_bytes)) {
            continue;
        }

        module_record module_record_item{};
        if (is_failed(parse_module_meta_from_elf_bytes(module_elf_bytes, module_record_item.desc))) {
            continue;
        }

        // 4.1 按状态清单给出运行状态（removed > abnormal > running > NotRunning）
        if (removed_pending_reboot_mod_list.contains(module_name)) {
            module_record_item.state = ModuleRunState::RemovedPendingReboot;
        } else if (abnormal_mod_list.contains(module_name)) {
            module_record_item.state = ModuleRunState::Abnormal;
        } else if (running_mod_list.contains(module_name)) {
            module_record_item.state = ModuleRunState::Running;
        }

        // 4.2 <system>/modules_new_state/<name>：4 字节原始状态，覆盖上面的结果
        const std::string state_file_path =
            (std::filesystem::path(get_system_file_dir_path()) / "modules_new_state" / module_name).string();
        std::vector<uint8_t> state_bytes;
        if (file_utils::read_file_bytes(state_file_path.c_str(), state_bytes) && state_bytes.size() == 4) {
            module_record_item.state = *reinterpret_cast<const ModuleRunState*>(state_bytes.data());
        }

        // 4.3 <system>/modules_new_desc/<name>：模块描述文本（按 desc 容量截断并保留 NUL）
        const std::string desc_text_file_path =
            (std::filesystem::path(get_system_file_dir_path()) / "modules_new_desc" / module_name).string();
        std::string desc_text;
        if (file_utils::read_text_file(desc_text_file_path.c_str(), desc_text) && !desc_text.empty()) {
            memset(module_record_item.desc.desc, 0, sizeof(module_record_item.desc.desc));
            const size_t copy_size = std::min(desc_text.size(), sizeof(module_record_item.desc.desc) - 1);
            strncpy(module_record_item.desc.desc, desc_text.c_str(), copy_size);
            module_record_item.desc.desc[copy_size] = '\0';
        }

        // 4.4 目录项修改时间作为排序键
        int64_t modify_time = 0;
        {
            struct stat file_stat = {};
            if (stat(module_desc_file_path.c_str(), &file_stat) == 0) {
                modify_time = file_stat.st_mtime;
            }
        }

        module_items.push_back(Item{modify_time, module_record_item});
    }

    closedir(module_list_dir);

    // 5. 按修改时间升序排序，再按顺序把 record 搬到 out_list
    std::sort(module_items.begin(), module_items.end(), [](const Item& lhs, const Item& rhs) {
        return lhs.modify_time < rhs.modify_time;
    });

    out_list.reserve(module_items.size());
    for (const Item& module_item : module_items) {
        out_list.push_back(module_item.record);
    }
    return KModErr::OK;
}

// 安全通道：fork 出子进程跑 unsafe_get_all_modules，把 (错误码, 序列化记录)
// 通过 fork 管道回传父进程，父进程反序列化后写回 out_list。
//   子进程: unsafe_get_all_modules(out_list) -> write_errcode_from_child
//           -> records_to_bytes(out_list) -> write_transfer_data_from_child
//           -> close_all() -> _exit(0)
//   父进程: read_errcode_from_child(失败 -> ERR_READ_CHILD_ERRCODE)
//           read_transfer_data_from_child(失败 -> ERR_READ_CHILD_DATA)
//           bytes_to_records -> out_list = move(...)
//           waitpid(child_pid, &status, 0)
//           return err
KModErr safe_get_all_modules(std::vector<module_record>& out_list) {
    fork_base_info pipe_info;
    KModErr        result_err = KModErr::OK;

    if (fork_pipe_child_process(pipe_info)) {
        // ---- 子进程 ----
        const KModErr child_err = unsafe_get_all_modules(out_list);
        write_errcode_from_child(pipe_info, child_err);

        const std::vector<uint8_t> serialized_records = records_to_bytes(out_list);
        write_transfer_data_from_child(pipe_info, serialized_records);

        pipe_info.close_all();
        _exit(0);
    }

    // ---- 父进程 ----
    if (!read_errcode_from_child(pipe_info, result_err)) {
        result_err = KModErr::ERR_READ_CHILD_ERRCODE;
    }

    std::vector<uint8_t> serialized_records;
    if (!read_transfer_data_from_child(pipe_info, serialized_records)) {
        result_err = KModErr::ERR_READ_CHILD_DATA;
    }

    std::vector<module_record> restored_records = bytes_to_records<module_record>(serialized_records);
    out_list = std::move(restored_records);

    int child_status = 0;
    waitpid(pipe_info.child_pid, &child_status, 0);
    return result_err;
}

}  // namespace maplesu::sdk

// 5.2.0 新增 helper allowlist 导出：把 <system>/modules/ 目录路径写进调用方
// 提供的 std::string 槽位。
//     240c: aa0003e8   mov  x8, x0          ; 槽位指针 -> sret 寄存器
//     2410: 17fffbd0   b    get_system_file_dir_path   ; 尾调用（0x1350）
// 即"在调用方给的槽位上就地构造返回值"。与下面这行 C++ 的 -Oz 代码生成逐字节一致
// （已用同版本 clang 验证：lvalue 引用形参 + placement new 就地产出
//   mov x8, x0; b ... ，符号大小 8）：
//   new (static_cast<void*>(&out)) std::string(get_system_file_dir_path());
// 消费方 maplesu_module_control.o 先零初始化 std::string 再 add x0,&slot; bl，
// 与本实现在空串槽位上就地构造的语义一致。
extern "C" __attribute__((visibility("hidden"))) void maplesu_system_directory(std::string& out) {
    new (static_cast<void*>(&out)) std::string(maplesu::sdk::get_system_file_dir_path());
}
