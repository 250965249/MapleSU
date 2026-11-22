// ARM EABI discovery targets, resolved completely before any Hook publication.
#pragma once
namespace default_modules::module_su_redirect {
KModErr maplesu_patch_compat_stat(const PatchBase&, uint64_t, uint64_t);
struct CompatSuHooks { uint64_t addresses[8] = {}; bool native_access_alias = false; };
inline KModErr resolve_compat_su_hooks(const KernelSymbolOffset& native, CompatSuHooks& hooks) {
    const uint64_t addresses[] = {native.execve.kaddr, native.sys_newfstatat_kaddr,
        native.sys_faccessat_kaddr, native.sys_statx_kaddr, native.sys_faccessat2_kaddr};
    const unsigned native_shape[] = {4, 1, 2, 3, 2};
    for (size_t i = 0; i < 5; ++i) {
        if (!addresses[i] && i >= 3) continue;
        if (!addresses[i] || (addresses[i] & 3)) return KModErr::ERR_MODULE_PARAM;
        for (size_t j = 0; j < i; ++j) if (addresses[i] == addresses[j]) {
            if (native_shape[i] != native_shape[j]) return KModErr::ERR_MODULE_PARAM;
            hooks.native_access_alias = true;
        }
    }
    uint64_t table = 0;
    auto error = kernel_module::kallsyms_lookup_name("compat_sys_call_table", table);
    if (error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) return KModErr::OK;
    if (is_failed(error)) return error;
    if (!table || (table & 7) || table > UINT64_MAX - 439 * sizeof(uint64_t))
        return KModErr::ERR_MODULE_PARAM;
    uint64_t absent = 0;
    error = kernel_module::kallsyms_lookup_name("__arm64_sys_ni_syscall", absent);
    if (error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
        error = kernel_module::kallsyms_lookup_name("sys_ni_syscall", absent);
    if (is_failed(error) && error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) return error;
    uint64_t installed[12] = {native.sys_newfstatat_kaddr, native.sys_faccessat_kaddr,
        native.sys_statx_kaddr, native.sys_faccessat2_kaddr};
    const unsigned shape[] = {0, 0, 0, 0, 1, 2, 3, 2};
    unsigned installed_shape[12] = {1, 2, 3, 2};
    size_t count = 4;
    const unsigned number[] = {106, 107, 195, 196, 327, 334, 397, 439};
    for (size_t i = 0; i < 8; ++i) {
        if ((i == 6 && !native.sys_statx_kaddr) || (i == 7 && !native.sys_faccessat2_kaddr)) continue;
        uint64_t entry = 0;
        error = kernel_module::read_kernel_mem(table + number[i] * sizeof(entry), &entry, sizeof(entry));
        if (is_failed(error)) return error;
        if (!entry || (entry & 3)) return KModErr::ERR_MODULE_PARAM;
        if (absent && entry == absent) continue;
        size_t j = 0;
        for (; j < count; ++j) if (installed[j] == entry) break;
        if (j != count) {
            if (installed_shape[j] != shape[i]) return KModErr::ERR_MODULE_PARAM;
            continue;
        }
        hooks.addresses[i] = entry;
        installed[count] = entry; installed_shape[count++] = shape[i];
    }
    return KModErr::OK;
}
inline KModErr install_compat_su_hooks(const PatchBase& base, const CompatSuHooks& hooks,
    uint64_t control) {
    for (size_t i = 0; i < 8; ++i) {
        const auto entry = hooks.addresses[i];
        if (!entry) continue;
        KModErr error;
        if (i < 4) error = maplesu_patch_compat_stat(base, entry, control);
        else if (i == 4) error = PatchSysNewfstatat(base, entry).patch_sys_newfstatat(control);
        else if (i == 6) error = PatchSysStatx(base, entry).patch_sys_statx(control);
        else if (i == 5) error = PatchSysFaccessat(base, entry).patch_sys_faccessat(control);
        else error = PatchSysFaccessat2(base, entry).patch_sys_faccessat2(control);
        if (is_failed(error)) return error;
    }
    return KModErr::OK;
}
} // namespace default_modules::module_su_redirect
