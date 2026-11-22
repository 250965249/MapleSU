#include "kernel_policy_gate.h"
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
#include "kernel_payload_loader.h"
#endif
#include <stdexcept>

namespace maplesu::module_policy {
unsigned prepare_kernel_policy(Mode mode, bool allow_unverified) {
    if (!valid_mode(static_cast<unsigned>(mode)))
        throw std::runtime_error("MODULE_POLICY_KERNEL_MODE_UNSUPPORTED");
    if (mode == Mode::Hide) {
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
        return prepare_hidden_kernel_policy(allow_unverified);
#else
        (void)allow_unverified;
        throw std::runtime_error("MODULE_POLICY_KERNEL_HIDE_UNSUPPORTED");
#endif
    }
    unsigned capabilities = 1;
#ifdef MAPLESU_POLICY_HIDE_PAYLOAD
    try { cancel_hidden_kernel_policy(); }
    catch (const std::exception& error) {
        // A failed cancellation is not proof of ordinary loading. Preserve the
        // error so the caller keeps recovery pending instead of publishing it.
        try { Store::open(false).record_compatibility(
            "schema=1 operation=hide-cancel boot=" + current_boot_id() +
            "\nresult=failed reason=" + error.what() + "\nEND\n"); }
        catch (...) { }
        throw;
    }
    if (hidden_kernel_policy_supported()) capabilities |= 2;
#endif
    // Block is enforced at the standard module-policy transaction entries.
    // Both Block and Load preserve legacy SDK primitives and native module
    // startup. Neither mode installs kernel hooks; the optional preflight only
    // reports whether Hide can be requested for the next boot.
    return capabilities;
}
}
