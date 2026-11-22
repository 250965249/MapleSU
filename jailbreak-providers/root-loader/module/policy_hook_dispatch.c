/* SPDX-License-Identifier: GPL-3.0-only */
#include "policy_hook_dispatch.h"

typedef unsigned long long (*policy_fn)(unsigned long long, unsigned long long,
    unsigned long long, unsigned long long, unsigned long long, unsigned long long);

MSU_PH_NOCFI unsigned long long msu_policy_dispatch(
    const struct msu_policy_hook_dispatch *hook, const unsigned long long args[6])
{
    policy_fn predicate = (policy_fn)(unsigned long)hook->predicate;
    policy_fn handler = (policy_fn)(unsigned long)hook->handler;
    const unsigned int *activation = (const void *)(unsigned long)hook->activation;
    unsigned long long first = 0, second = 0, result;
    unsigned int attempts;
    /* The fork guard brackets native copy_process even while the query gate
     * changes. It never runs in kprobe context and preserves native errors. */
    if (hook->operation == 9) {
        (void)handler(0, 0, 0, 0, 0, 0);
        result = msu_policy_call_original(hook->target, args);
        (void)handler(1, 0, 0, 0, 0, 0);
        return result;
    }
    if (hook->operation != 7 && (!activation || !__atomic_load_n(activation, __ATOMIC_ACQUIRE)))
        return msu_policy_call_original(hook->target, args);
    if (hook->operation == 10) {
        /* Record a module epoch before native multicast delivery. The native
         * notifier is always executed, including allocation/error paths. */
        int error = (int)handler(args[0], 0, 0, 0, 0, 0);
        if (error) msu_policy_backend_note_error(error);
        return msu_policy_call_original(hook->target, args);
    }
    if (hook->operation == 11) {
        int error;
        (void)handler(0, 0, 0, 0, 0, 0);
        result = msu_policy_call_original(hook->target, args);
        error = (int)handler(1, result, 0, 0, 0, 0);
        if (error) msu_policy_backend_note_error(error);
        /* The payload has released its epoch/policy locks at this point. */
        msu_policy_backend_reconcile();
        return result;
    }
    if (hook->operation == 6) { first = args[0]; second = args[1]; }
    else if (hook->operation == 2 || hook->operation == 7 || hook->operation == 8)
        first = args[0];
    if (!predicate(hook->operation, first, second, 0, 0, 0))
        return msu_policy_call_original(hook->target, args);
    if (hook->operation == 7) {
        /* commit_creds is never skipped or replayed; remapping follows commit. */
        result = msu_policy_call_original(hook->target, args);
        (void)handler(0, 0, 0, 0, 0, 0);
        return result;
    }
    if (hook->operation == 8) {
        for (attempts = 0; attempts < 8; ++attempts) {
            result = msu_policy_call_original(hook->target, args);
            if (!result) return 0;
            result = handler(args[0], result, args[2], 0, 0, 0);
            if (result) return result;
        }
        /* Do not restart __skb_recv_datagram's native blocking/timeout loop. */
        *(int *)(unsigned long)args[4] = -11; /* -EAGAIN, as the native ABI */
        return 0;
    }
    return handler(args[0], args[1], args[2], args[3], args[4], args[5]);
}
