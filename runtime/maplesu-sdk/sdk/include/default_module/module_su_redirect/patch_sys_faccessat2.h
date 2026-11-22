// patch sys faccessat2 implementation.
//
#pragma once

#include <cstdint>

#include "default_module/module_su_redirect/patch_sys_faccessat.h"

namespace default_modules::module_su_redirect {

// faccessat2 的补丁入口和 faccessat 完全一致（内核里两者共享同一套
// "是否允许 su 通过"判定），所以这里只是把 patch 逻辑转交给基类，
class PatchSysFaccessat2 : public PatchSysFaccessat {
public:
    PatchSysFaccessat2(const PatchBase& base, uint64_t kaddr);
    ~PatchSysFaccessat2();

    KModErr patch_sys_faccessat2(uint64_t kaddr);
};

static_assert(sizeof(PatchSysFaccessat2) == 48, "layout constraint violated");

}  // namespace default_modules::module_su_redirect
