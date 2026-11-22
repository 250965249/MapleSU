// SPDX-License-Identifier: GPL-3.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include "native_sdk.h"
#include "native_lookup.h"
#include "native_imports.h"
#include "legacy_hook_private.h"

/* These real typed forwarding functions supply this compiler's reference CFI
 * IDs; only runtime-resolved matching native addresses enter the producer. */
#define REF_RETURN(result, name, declaration, arguments) \
    static result (*target_##name) declaration; \
    static noinline result reference_##name declaration { return target_##name arguments; }
#define REF_VOID(name, declaration, arguments) \
    static void (*target_##name) declaration; \
    static noinline void reference_##name declaration { target_##name arguments; }
REF_RETURN(long, copy_from_user_nofault, (void *to, const void __user *from, size_t size), (to, from, size))
REF_RETURN(long, copy_to_user_nofault, (void __user *to, const void *from, size_t size), (to, from, size))
REF_RETURN(long, copy_from_kernel_nofault, (void *to, const void *from, size_t size), (to, from, size))
REF_RETURN(long, copy_to_kernel_nofault, (void *to, const void *from, size_t size), (to, from, size))
REF_RETURN(void *, vmalloc, (unsigned long bytes), (bytes))
REF_RETURN(void *, vmalloc_user, (unsigned long bytes), (bytes))
REF_RETURN(void *, vmalloc_range, (unsigned long size, unsigned long align,
    unsigned long start, unsigned long end, gfp_t gfp, pgprot_t prot,
    unsigned long flags, int node, const void *caller), (size, align, start, end, gfp, prot, flags, node, caller))
REF_VOID(vfree, (const void *address), (address))
REF_VOID(cache, (unsigned long start, unsigned long end), (start, end))
REF_RETURN(struct cred *, prepare_creds, (void), ())
REF_RETURN(int, commit_creds, (struct cred *cred), (cred))
REF_RETURN(const struct cred *, get_task_cred, (struct task_struct *task), (task))
REF_VOID(__put_cred, (struct cred *cred), (cred))
REF_RETURN(long, execve, (const struct pt_regs *regs), (regs))
REF_RETURN(int, maplesu_legacy_hook_provider_get,
    (const struct maplesu_legacy_hook_provider **provider, void **lease), (provider, lease))
REF_VOID(maplesu_legacy_hook_provider_put, (void *lease), (lease))
#undef REF_RETURN
#undef REF_VOID

#define MATCH_NATIVE(name) _Static_assert(__builtin_types_compatible_p( \
    typeof(&reference_##name), typeof(&name)), "native SDK prototype: " #name)
MATCH_NATIVE(copy_from_user_nofault);
MATCH_NATIVE(copy_to_user_nofault);
MATCH_NATIVE(copy_from_kernel_nofault);
MATCH_NATIVE(copy_to_kernel_nofault);
MATCH_NATIVE(vfree);
MATCH_NATIVE(prepare_creds);
MATCH_NATIVE(commit_creds);
MATCH_NATIVE(get_task_cred);
MATCH_NATIVE(__put_cred);
MATCH_NATIVE(maplesu_legacy_hook_provider_get);
MATCH_NATIVE(maplesu_legacy_hook_provider_put);
#undef MATCH_NATIVE
#ifdef vmalloc
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc), typeof(&vmalloc_noprof)), "native vmalloc prototype");
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc_range), typeof(&__vmalloc_node_range_noprof)), "native range allocator prototype");
#else
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc), typeof(&vmalloc)), "native vmalloc prototype");
_Static_assert(__builtin_types_compatible_p(typeof(&reference_vmalloc_range), typeof(&__vmalloc_node_range)), "native range allocator prototype");
#endif
_Static_assert(__builtin_types_compatible_p(typeof(&reference_cache),
    typeof(&caches_clean_inval_pou)), "native instruction cache prototype");

struct msu_native_sdk_symbol {
    const char *name;
    const void *reference;
    unsigned long address;
};

static struct msu_native_sdk_symbol sdk_symbols[] = {
    { "copy_from_user_nofault", reference_copy_from_user_nofault },
    { "copy_to_user_nofault", reference_copy_to_user_nofault },
    { "copy_from_kernel_nofault", reference_copy_from_kernel_nofault },
    { "copy_to_kernel_nofault", reference_copy_to_kernel_nofault },
    { "vfree", reference_vfree },
    { "prepare_creds", reference_prepare_creds },
    { "commit_creds", reference_commit_creds },
    { "get_task_cred", reference_get_task_cred },
    { "__put_cred", reference___put_cred },
    { "__arm64_sys_execve", reference_execve },
    { "maplesu_legacy_hook_provider_get", reference_maplesu_legacy_hook_provider_get },
    { "maplesu_legacy_hook_provider_put", reference_maplesu_legacy_hook_provider_put },
};

unsigned long msu_init_bridge_checked_lookup(const char *name)
{
    const void *reference = NULL;
    unsigned long address = 0;
    unsigned int i;

    if (!name) return 0;
    for (i = 0; i < ARRAY_SIZE(sdk_symbols); ++i)
        if (!strcmp(name, sdk_symbols[i].name)) {
            if (!sdk_symbols[i].address && msu_init_bridge_resolve_cfi(name,
                    sdk_symbols[i].reference, &sdk_symbols[i].address)) return 0;
            return sdk_symbols[i].address;
        }
    if (!strcmp(name, "vmalloc") || !strcmp(name, "vmalloc_noprof")) reference = reference_vmalloc;
    if (!strcmp(name, "vmalloc_user") || !strcmp(name, "vmalloc_user_noprof")) reference = reference_vmalloc_user;
    if (!strcmp(name, "__vmalloc_node_range") || !strcmp(name, "__vmalloc_node_range_noprof")) reference = reference_vmalloc_range;
    if (!strcmp(name, "caches_clean_inval_pou") || !strcmp(name, "__flush_icache_range")) reference = reference_cache;
    if (reference)
        return msu_init_bridge_resolve_cfi(name, reference, &address) ? 0 : address;
    if (!strcmp(name, "set_memory_ro")) reference = msu_native_set_memory_ro;
    if (!strcmp(name, "set_memory_rw")) reference = msu_native_set_memory_rw;
    if (!strcmp(name, "set_memory_x")) reference = msu_native_set_memory_x;
    if (!strcmp(name, "set_memory_nx")) reference = msu_native_set_memory_nx;
    if (reference)
        return msu_init_bridge_resolve_cfi(name, reference, &address) ? 0 : address;
#if MSU_INIT_BRIDGE_CFI_LEGACY && defined(MODULE)
    if (!strcmp(name, "kallsyms_lookup_name"))
        return msu_init_bridge_resolve_cfi(name, (void *)msu_init_bridge_lookup,
            &address) ? 0 : address;
#endif
    /* These are address-only inputs. No unchecked native indirect call is
     * made through them here; environment ABI qualification stays separate. */
    if (!strcmp(name, "_text") || !strcmp(name, "kallsyms_lookup_name") ||
        !strcmp(name, "do_execveat_common") || !strcmp(name, "filldir64") ||
        !strcmp(name, "slow_avc_audit") || !strcmp(name, "avc_denied"))
        return msu_init_bridge_lookup(name);
    return 0;
}
