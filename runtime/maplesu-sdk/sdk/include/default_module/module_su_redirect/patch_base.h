// patch base implementation.
//
#pragma once

#include <cstdint>
#include <string>

#include "kernel_module_kit_umbrella.h"

namespace default_modules::module_su_redirect {

class PatchBase {
public:
    PatchBase(uint32_t task_cred_offset, uint32_t cred_uid_offset, uint32_t cred_euid_offset,
              const char* fake_su_path);
    PatchBase(const PatchBase& other);
    ~PatchBase();

    std::string get_fake_su_path();
    int get_cred_atomic_usage_size();

    // 生成"判断当前进程是否允许 su"的汇编，结果写入 x10
    KModErr emit_check_current_allow_su_to_x10_checked(asmjit::a64::Assembler* a, uint64_t arg);
    void emit_check_current_allow_su_to_x10(Assembler* a, uint64_t arg);
    // 生成"判断用户态调用方给出的文件名是否为 su 路径"的汇编
    void emit_check_user_filename_is_su(Assembler* a, KModErr& err, GpX user_path);
    // 生成"把用户态字符串安全拷进内核栈缓冲"的汇编
    void emit_dynamic_copy_string_from_user(Assembler* a, KModErr& err, GpX dst, GpX src,
                                            uint64_t max_len);

    // 在目标函数入口/出口安装 hook（a 为已生成好的补丁体）
    KModErr patch_kernel_before_hook(uint64_t kaddr, const Assembler* a);
    KModErr patch_kernel_after_hook(uint64_t kaddr, const Assembler* a);

private:
    uint32_t field0_;                  // +0: task_struct.cred offset
    uint32_t cred_atomic_usage_size_;  // +4: cred.uid offset; legacy member/getter name
    uint32_t field2_;                  // +8: cred.euid offset
    std::string fake_su_path_;         // +16

    friend struct PatchBaseLayoutProbe;
};

// 布局锁（用 friend 探针在类外取 offsetof / sizeof）
struct PatchBaseLayoutProbe {
    static_assert(sizeof(PatchBase) == 40,
                  "layout constraint violated");
    static_assert(offsetof(PatchBase, cred_atomic_usage_size_) == 4,
                  "unexpected layout size");
    static_assert(offsetof(PatchBase, fake_su_path_) == 16, "layout constraint violated");
};

}  // namespace default_modules::module_su_redirect
