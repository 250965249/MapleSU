// SPDX-License-Identifier: GPL-3.0-only
#ifndef MAPLESU_POLICY_VIEW_H
#define MAPLESU_POLICY_VIEW_H
#ifdef MAPLESU_POLICY_PIC
/* Assembly ABI veneers keep BTI intact when dynamic SCS rewrites PACIASP in
 * the C implementation. Internal direct calls retain normal Kbuild checking. */
#define maplesu_policy_view_prepare maplesu_policy_view_prepare_impl
#define maplesu_policy_view_handles maplesu_policy_view_handles_impl
#define maplesu_policy_view_context maplesu_policy_view_context_impl
#define maplesu_policy_view_access maplesu_policy_view_access_impl
#define maplesu_policy_view_setprocattr maplesu_policy_view_setprocattr_impl
#define maplesu_policy_view_status_open maplesu_policy_view_status_open_impl
#define maplesu_policy_view_status_read maplesu_policy_view_status_read_impl
#define maplesu_policy_view_status_mmap maplesu_policy_view_status_mmap_impl
#define maplesu_policy_view_filter maplesu_policy_view_filter_impl
#define maplesu_policy_view_creds_changed maplesu_policy_view_creds_changed_impl
#define maplesu_policy_view_receive maplesu_policy_view_receive_impl
#define maplesu_policy_view_transition maplesu_policy_view_transition_impl
#define maplesu_policy_view_fork_guard maplesu_policy_view_fork_guard_impl
#define maplesu_policy_view_module_write maplesu_policy_view_module_write_impl
#define maplesu_policy_view_policyload maplesu_policy_view_policyload_impl
#define maplesu_policy_view_reload maplesu_policy_view_reload_impl
#endif
/* Kernel payload ABI, called by the environment-owned SDK bridge. The bridge
 * calls handles() first and executes the original entry when it returns zero.
 * Payload, policy and status page live until reboot once any hook is installed.
 * No live toggling or unload is supported. */
enum maplesu_policy_operation {
    MAPLESU_POLICY_CONTEXT,
    MAPLESU_POLICY_ACCESS,
    MAPLESU_POLICY_SETPROCATTR,
    MAPLESU_POLICY_STATUS_OPEN,
    MAPLESU_POLICY_STATUS_READ,
    MAPLESU_POLICY_STATUS_MMAP,
    MAPLESU_POLICY_NOTIFY_FILTER,
    MAPLESU_POLICY_CRED_COMMIT,
    MAPLESU_POLICY_NOTIFY_RECEIVE
};
#ifndef MAPLESU_POLICY_VIEW_HOST_TEST
int maplesu_policy_view_prepare(void);
struct sock;
struct sk_buff;
int maplesu_policy_view_handles(unsigned int operation, const void *first,
                                const void *second);
ssize_t maplesu_policy_view_context(struct file *file, char *buf, size_t size);
ssize_t maplesu_policy_view_access(struct file *file, char *buf, size_t size);
int maplesu_policy_view_setprocattr(const char *name, void *value, size_t size);
int maplesu_policy_view_status_open(struct inode *inode, struct file *file);
ssize_t maplesu_policy_view_status_read(struct file *file, char __user *buf,
                                      size_t count, loff_t *position);
int maplesu_policy_view_status_mmap(struct file *file, struct vm_area_struct *vma);
int maplesu_policy_filter_selected(const struct sock *sk, const struct sk_buff *skb);
int maplesu_policy_view_filter(struct sock *sk, struct sk_buff *skb, unsigned int cap);
void maplesu_policy_view_creds_changed(void);
int maplesu_policy_view_transition(unsigned enabled);
void maplesu_policy_view_fork_guard(unsigned phase);
int maplesu_policy_view_module_write(unsigned phase);
int maplesu_policy_view_policyload(u32 sequence);
int maplesu_policy_view_reload(unsigned phase, long result);
struct sk_buff *maplesu_policy_view_receive(struct sock *sk, struct sk_buff *skb,
                                          unsigned int flags);
#endif
#endif
