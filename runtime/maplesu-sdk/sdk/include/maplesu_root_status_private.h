#pragma once
#include "maplesu_request_private.h"
#include <sys/types.h>

namespace maplesu::sdk {
enum class RootStatusPhase : int { None, Fork, Root, Credentials, Receipt, Wait, Complete };

struct RootProcessFacts {
    uint32_t ruid = 0, euid = 0, suid = 0, rgid = 0, egid = 0, sgid = 0;
    uint32_t fsuid = 0, fsgid = 0;
    uint64_t inheritable = 0, permitted = 0, effective = 0, bounding = 0, ambient = 0;
    uint64_t capability_mask = 0;
    int cap_last_cap = -1;
    int uid_error = 0, gid_error = 0, fsuid_error = 0, fsgid_error = 0;
    int caps_errno = 0, cap_limit_error = 0, securebits_error = 0;
    KModErr caps_error = KModErr::OK;
    int securebits = 0;
    bool uid_observed = false, gid_observed = false, fsids_observed = false, caps_observed = false;
    bool ambient_present = false, cap_limit_observed = false, securebits_observed = false;
    bool matches_root = false;
};

inline bool root_process_facts_match(const RootProcessFacts& facts) noexcept {
    const uint64_t mask = facts.capability_mask;
    return facts.uid_observed && facts.gid_observed && facts.fsids_observed &&
        facts.ruid == 0 && facts.euid == 0 && facts.suid == 0 &&
        facts.rgid == 0 && facts.egid == 0 && facts.sgid == 0 && facts.fsuid == 0 && facts.fsgid == 0 &&
        facts.caps_observed && is_ok(facts.caps_error) && facts.ambient_present && facts.cap_limit_observed &&
        facts.cap_last_cap >= 0 && facts.cap_last_cap <= 63 &&
        mask == (facts.cap_last_cap == 63 ? UINT64_MAX : (UINT64_C(1) << (facts.cap_last_cap + 1)) - 1) &&
        facts.inheritable == mask && facts.permitted == mask && facts.effective == mask &&
        facts.bounding == mask && facts.ambient == mask && facts.securebits_observed && facts.securebits == 0;
}

// Snapshot of this worker's existing get_root diagnostics, not a new ROOT call.
struct RootStatusCredentialFacts {
    bool command_observed = false, root_attempted = false, root_returned = false;
    bool root_report_received = false, credentials_attempted = false, owner_mode = false;
    bool environment_completed = false, task_state_attempted = false;
    pid_t process = 0;
    int command_phase = 0, transition_phase = 0;
    KModErr command_error = KModErr::OK, credentials_error = KModErr::OK;
    KModErr transition_error = KModErr::OK, task_state_error = KModErr::OK;
    int command_errno = 0, transition_errno = 0;
    kernel_module::RequestManagementReply credentials{}, task_state{};
};

struct RootStatusResult {
    KModErr error = KModErr::ERR_MODULE_TEST_CHANNEL;
    KModErr root_error = KModErr::ERR_MODULE_TEST_CHANNEL;
    RootStatusPhase phase = RootStatusPhase::None;
    int system_error = 0, root_errno = 0, transport_error = 0, wait_error = 0;
    pid_t process = 0, child_pid = 0;
    int child_status = -1;
    bool child_status_valid = false, receipt_complete = false;
    bool root_attempted = false, root_returned = false, root_verified = false;
    RootProcessFacts facts{};
    RootStatusCredentialFacts root_credentials{};
};

// Call immediately after get_root_status_report on the same thread/process.
// Nonempty legacy text proves only report availability. False/incomplete facts
// stay unknown; neither this result nor a failed receipt permits replay.
// error==OK alone is not a Root proof; root_verified also checks actual facts.
__attribute__((visibility("hidden"))) RootStatusResult current_root_status_result();
}
