// patch sys newfstatat implementation.
//
#include "patch_sys_stat_access.h"

using namespace asmjit;
using namespace asmjit::a64;

namespace default_modules {
namespace module_su_redirect {

PatchSysNewfstatat::PatchSysNewfstatat(const PatchBase& patch_base, uint64_t patch_kaddr)
    : PatchBase(patch_base), m_patch_kaddr(patch_kaddr) {}

PatchSysNewfstatat::~PatchSysNewfstatat() = default;

KModErr PatchSysNewfstatat::patch_sys_newfstatat(uint64_t check_arg) {
    // newfstatat(dfd, filename, statbuf, flags)：
    // statbuf 在 x2，syscall 参数帧里位于 +16（regs[2]）。
    MAPLESU_EMIT_STAT_ACCESS_PATCH(x2, 16)
}

}  // namespace module_su_redirect
}  // namespace default_modules

// Private compat stat/lstat entry: the public PatchBase/class layouts stay fixed.
namespace default_modules::module_su_redirect {
namespace {
class CompatStatPatch : public PatchBase {
public:
    CompatStatPatch(const PatchBase& base, uint64_t entry) : PatchBase(base), m_patch_kaddr(entry) {}
    KModErr install(uint64_t check_arg) {
        MAPLESU_EMIT_PATH_STAT_ACCESS_PATCH(x0, 0, x1, 8, true)
    }
private:
    uint64_t m_patch_kaddr;
};
}
KModErr maplesu_patch_compat_stat(const PatchBase& base, uint64_t entry, uint64_t control) {
    return CompatStatPatch(base, entry).install(control);
}
} // namespace default_modules::module_su_redirect
