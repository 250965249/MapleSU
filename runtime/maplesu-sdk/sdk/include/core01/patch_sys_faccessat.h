// patch sys faccessat implementation.
//
#pragma once

#include <cstdint>

#include "core01/patch_base_su_redirect.h"

namespace default_modules {
namespace module_su_redirect {

/***************************************************************************
 * sys_faccessat 的 before-hook 生成器。
 *
 *   1. arm64_before_hook_start(a)
 *   2. Emit the full real-UID allowlist decision into x10; cbz keeps the original path.
 *   3. 取得用户态 filename 指针（pt_regs 形态下从 x1+8 取）
 *   4. 判断文件名是否为 su 提权路径，是则直接返回 0（伪装成功）
 *   5. arm64_before_hook_end() 并安装 hook
 ***************************************************************************/
class PatchSysFaccessat : public PatchBase {
public:
    PatchSysFaccessat(const PatchBase& patch_base, uint64_t sys_faccessat_kaddr);
    ~PatchSysFaccessat();

    // 参数原样透传给 PatchBase::emit_check_current_allow_su_to_x10。
    KModErr patch_sys_faccessat(uint64_t check_arg);

private:
    uint64_t m_sys_faccessat = 0;  // 被测 sys_faccessat 的内核地址
};

static_assert(sizeof(PatchSysFaccessat) == 48,
              "PatchSysFaccessat 必须为 PatchBase(40) + u64 = 48 字节");

}  // namespace module_su_redirect
}  // namespace default_modules
