// SPDX-License-Identifier: GPL-3.0-only
/* Keep the native status read/mmap ABI and validation. Selecting at use time
 * covers root-opened FDs without replacing a shared file's private_data. */
#include "policy_view_internal.h"

ssize_t maplesu_policy_view_status_read(struct file *file, char __user *buf,
                                      size_t count, loff_t *position)
{
    (void)file;
    return simple_read_from_buffer(buf, count, position,
                                  page_address(maplesu_view.status),
                                  sizeof(struct selinux_kernel_status));
}

int maplesu_policy_view_status_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long size = PV_FIELD(vma, vm_area_struct, vm_end) - PV_FIELD(vma, vm_area_struct, vm_start);
    (void)file;

    if (PV_FIELD(vma, vm_area_struct, vm_pgoff) > 0 || size != PAGE_SIZE)
        return -EIO;
    if (PV_FIELD(vma, vm_area_struct, vm_flags) & VM_WRITE)
        return -EPERM;
#if defined(MAPLESU_POLICY_HAS_VM_FLAGS_CLEAR)
    *(unsigned long *)&PV_FIELD(vma, vm_area_struct, vm_flags) &= ~VM_MAYWRITE;
#else
    PV_FIELD(vma, vm_area_struct, vm_flags) &= ~VM_MAYWRITE;
#endif
    return remap_pfn_range(vma, PV_FIELD(vma, vm_area_struct, vm_start),
                           page_to_pfn(maplesu_view.status), size,
                           PV_FIELD(vma, vm_area_struct, vm_page_prot));
}
