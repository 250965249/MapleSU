// patch mtk hbt filldir64 implementation.
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core01/patch_base_module_root.h"

namespace kernel_module { struct OwnedHookActor; }

namespace default_modules {
namespace module_root {

/***************************************************************************
 * 用于在受 KCFI 保护的 hbt:filldir64 上"另建一个类型签名正确"的假函数：
 * 生成的机器码按目录名逐字节比对，命中即提前返回（隐藏目录项），
 * 未命中则尾跳回原始 hbt:filldir64。
 ***************************************************************************/
class PatchMtkHbtFilldir64 : public PatchBase {
public:
    PatchMtkHbtFilldir64(const PatchBase& patch_base, uint64_t hbt_filldir64_kaddr);
    ~PatchMtkHbtFilldir64();

    // 生成假函数并安装，成功时把可调用地址写入 out_func_kaddr。
    KModErr generate_hook_fake_filldir64(const std::vector<std::string>& hide_names,
                                        uint64_t& out_func_kaddr);
    KModErr generate_hook_fake_filldir64_owned(const std::vector<std::string>& hide_names,
        uint64_t& out_func_kaddr, kernel_module::OwnedHookActor& actor);

    // 在 kaddr 前 4 字节复制原函数的 KCFI type-id，随后拷入代码并改成可执行。
    KModErr create_kcfi_kernel_function(uint64_t kaddr,
                                       const std::vector<uint8_t>& code,
                                       uint64_t& out_func_kaddr);

private:
    KModErr generate_hook_fake_filldir64_impl(const std::vector<std::string>& hide_names,
        uint64_t& out_func_kaddr, kernel_module::OwnedHookActor* actor);
    KModErr create_kcfi_kernel_function(uint64_t kaddr, const std::vector<uint8_t>& code,
        uint64_t& out_func_kaddr, kernel_module::OwnedHookActor* actor);
    uint64_t m_hbt_filldir64 = 0;  // 原始 hbt:filldir64 的内核地址
};

static_assert(sizeof(PatchMtkHbtFilldir64) == 24,
              "PatchMtkHbtFilldir64 必须为 PatchBase(16) + u64 = 24 字节");

}  // namespace module_root
}  // namespace default_modules
