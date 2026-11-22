#include "module_err_def.h"
#include <linux/capability.h>
#include <sys/syscall.h>
#include <unistd.h>

// The legacy kernel channel writes its reply into current->cred's saved IDs.
// Threads and fork children initially share that object. A raw capset commits
// a private copy for this task, even when the capabilities are unchanged.
// Do this for every request: fork can share the credentials again afterwards.
extern "C" __attribute__((visibility("hidden")))
int64_t maplesu_prepare_kernel_request() noexcept {
    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[2]{};
    if (syscall(SYS_capget, &header, data) != 0)
        return static_cast<int64_t>(KModErr::ERR_MODULE_GET_CAPS);
    if (syscall(SYS_capset, &header, data) != 0)
        return static_cast<int64_t>(KModErr::ERR_MODULE_CRED_DANGER);
    return 0;
}
