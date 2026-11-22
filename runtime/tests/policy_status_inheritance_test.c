/* Exercise real view selection at open, read and mmap across UID/FD ownership.
 * Native fallbacks below reproduce Linux selinuxfs status page selection;
 * this is a host regression, not proof of Android VMA inheritance behavior. */
#define main snapshot_fixture_main
#include "policy_view_boot_test.c"
#undef main

static int open_status(struct file *file)
{
    if (maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_OPEN, NULL, NULL))
        return maplesu_policy_view_status_open(NULL, file);
    file->private_data = selinux_kernel_status_page();
    return file->private_data ? 0 : -ENOMEM;
}

static struct selinux_kernel_status read_status(struct file *file)
{
    struct selinux_kernel_status status;
    loff_t position = 0;
    ssize_t size;
    if (maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_READ, NULL, NULL))
        size = maplesu_policy_view_status_read(file, (char *)&status, sizeof(status), &position);
    else
        size = simple_read_from_buffer(&status, sizeof(status), &position,
                                      page_address((struct page *)file->private_data), sizeof(status));
    assert(size == sizeof(status) && position == sizeof(status));
    return status;
}

static unsigned long mmap_status(struct file *file)
{
    struct vm_area_struct vma = {.vm_start = 0x10000, .vm_end = 0x10000 + PAGE_SIZE};
    if (maplesu_policy_view_handles(MAPLESU_POLICY_STATUS_MMAP, NULL, NULL))
        assert(!maplesu_policy_view_status_mmap(file, &vma));
    else
        assert(!remap_pfn_range(&vma, vma.vm_start,
                               page_to_pfn((struct page *)file->private_data), PAGE_SIZE, vma.vm_page_prot));
    return vma.mapped_pfn;
}

int main(void)
{
    const struct {
        u32 sequence, policyload, generation;
    } baselines[] = {{0, 0, 1}, {4, 1, 1}, {16, 5, 5}, {0xfffffffe, 0xffffffff, 0xffffffff}};
    bool passed = true;
    unsigned cases = 0;
    for (unsigned b = 0; b < sizeof(baselines) / sizeof(baselines[0]); ++b) {
        struct file root_opened = {0}, app_opened = {0};
        reset();
        struct selinux_kernel_status *live_status = (void *)original_status.data;
        live_status->sequence = baselines[b].sequence;
        live_status->policyload = baselines[b].policyload;
        live.latest_granting = baselines[b].generation;
        struct selinux_kernel_status captured = *live_status;
        captured.sequence = expected_sequence;
        captured.policyload = expected_policyload;
        assert(!maplesu_policy_view_prepare());
        assert(maplesu_view.policy->latest_granting == baselines[b].generation);
        assert(!open_status(&root_opened));
        live_status->sequence += 2;
        live_status->policyload = live.latest_granting = 99;
        fixture_uid = 10123;
        assert(!open_status(&app_opened));
        struct file *files[] = {&root_opened, &app_opened};
        const char *owners[] = {"root-opened", "app-opened"};
        for (unsigned i = 0; i < 2; ++i) {
            for (fixture_uid = 10123; fixture_uid <= 110123; fixture_uid += 100000) {
                struct selinux_kernel_status status = read_status(files[i]);
                bool ok = !memcmp(&status, &captured, sizeof(status)) &&
                          files[i]->private_data == &original_status &&
                          mmap_status(files[i]) == page_to_pfn(maplesu_view.status);
                printf("%s app uid=%u %s status read/mmap sequence=%u policyload=%u\n",
                       ok ? "PASS" : "FAIL", fixture_uid, owners[i], status.sequence, status.policyload);
                passed &= ok;
                ++cases;
            }
            fixture_uid = 0;
            struct selinux_kernel_status status = read_status(files[i]);
            bool ok = !memcmp(&status, live_status, sizeof(status)) &&
                      mmap_status(files[i]) == page_to_pfn(&original_status);
            printf("%s root %s status read/mmap sequence=%u policyload=%u\n",
                   ok ? "PASS" : "FAIL", owners[i], status.sequence, status.policyload);
            passed &= ok;
            ++cases;
        }
        printf("BASELINE sequence=%u policyload=%u generation=%u\n",
               captured.sequence, captured.policyload, maplesu_view.policy->latest_granting);
    }
    reset();
    printf("%s %u status read/mmap cases across captured native baselines\n", passed ? "PASS" : "FAIL", cases);
    return passed ? 0 : 1;
}
