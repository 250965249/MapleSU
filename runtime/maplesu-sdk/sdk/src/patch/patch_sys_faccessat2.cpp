// patch sys faccessat2 implementation.
//
#include "kernel_module_kit_umbrella.h"

#include "default_module/module_su_redirect/patch_sys_faccessat2.h"

namespace default_modules::module_su_redirect {

PatchSysFaccessat2::PatchSysFaccessat2(const PatchBase& base, uint64_t kaddr)
    : PatchSysFaccessat(base, kaddr) {}

PatchSysFaccessat2::~PatchSysFaccessat2() = default;

//        （!type !21 也说明它和基类的 patch_sys_faccessat 是同一成员函数类型
//          KModErr (PatchBase::*)(unsigned long)）
KModErr PatchSysFaccessat2::patch_sys_faccessat2(uint64_t kaddr) {
    return patch_sys_faccessat(kaddr);
}

}  // namespace default_modules::module_su_redirect
