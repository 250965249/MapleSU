// patch sys statx implementation.
//
#include "patch_sys_stat_access.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace default_modules {
namespace module_su_redirect {

PatchSysStatx::PatchSysStatx(const PatchBase& patch_base, uint64_t patch_kaddr)
    : PatchBase(patch_base), m_patch_kaddr(patch_kaddr) {}

PatchSysStatx::~PatchSysStatx() = default;

KModErr PatchSysStatx::patch_sys_statx(uint64_t check_arg) {
    // statx(dfd, filename, flags, mask, statxbuf)：
    // statxbuf 在 x4，syscall 参数帧里位于 +32（regs[4]）。
    MAPLESU_EMIT_STAT_ACCESS_PATCH(x4, 32)
}

}  // namespace module_su_redirect
}  // namespace default_modules
