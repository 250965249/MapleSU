/* Execute the production snapshot code and the saved detector's status rules. */
#define main snapshot_fixture_main
#include "policy_view_boot_test.c"
#undef main

static void accepted(struct selinux_kernel_status *status)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
    assert(status->sequence == 4 && status->policyload == 1);
#else
    assert(status->sequence == 0 && status->policyload == 0);
#endif
    assert(status->enforcing == 1 && status->version == 1);
}

int main(void)
{
    reset();
    /* The helper and resident jailbreak bridge load after the platform policy.
     * Their captured policy generation must not leak into the app status ABI. */
    assert(!maplesu_policy_view_prepare());
    struct page *page = maplesu_view.status;
    accepted((void *)page->data);
    assert(live.latest_granting == 5);
    assert(((struct selinux_kernel_status *)original_status.data)->sequence == 16);
    assert(((struct selinux_kernel_status *)original_status.data)->policyload == 5);
    for (unsigned generation = 6; generation < 40; ++generation) {
        live.latest_granting = generation;
        ((struct selinux_kernel_status *)original_status.data)->sequence += 2;
        ((struct selinux_kernel_status *)original_status.data)->policyload = generation;
        assert(!maplesu_policy_view_reload(0, 0));
        assert(!maplesu_policy_view_reload(1, 24));
        assert(maplesu_view.status == page);
        assert(maplesu_view.policy->latest_granting == generation);
        accepted((void *)page->data);
        /* Test fixture bounds ownership records; release unused record slots. */
        unsigned retained = 0;
        for (unsigned i = 0; i < owned_count; ++i)
            if (owned[i]) owned[retained++] = owned[i];
        owned_count = retained;
    }
    reset();
    puts("PASS detector status contract across 34 policy reloads; live policy unchanged");
    return 0;
}
