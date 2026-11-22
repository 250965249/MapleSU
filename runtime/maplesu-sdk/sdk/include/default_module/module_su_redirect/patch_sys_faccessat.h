// patch sys faccessat implementation.
//
#pragma once

#include <cstdint>

#include "default_module/module_su_redirect/patch_base.h"

namespace default_modules::module_su_redirect {

class PatchSysFaccessat : public PatchBase {
public:
    PatchSysFaccessat(const PatchBase& base, uint64_t kaddr);
    ~PatchSysFaccessat();

    KModErr patch_sys_faccessat(uint64_t kaddr);

private:
    // 真正定义在 #87 patch_sys_faccessat.cpp 里。此处占位以钉住 ABI。
    uint64_t patch_state_;
};

static_assert(sizeof(PatchSysFaccessat) == 48,
              "layout constraint violated");

}  // namespace default_modules::module_su_redirect
