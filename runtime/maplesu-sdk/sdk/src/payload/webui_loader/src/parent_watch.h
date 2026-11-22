// webui_loader -- owner-process watchdog.
//
// The kit starts the loader for one WebUI session and records the pid of the
// process that requested it.  The HTTP endpoint must not outlive that owner: a
// module's UI is only meaningful while the manager (or helper) that asked for it
// is still connected.  The watchdog therefore blocks until the owner is gone and
// then lets the module decide whether the process should exit or keep serving.
//
#pragma once

namespace maplesu::payload::webui {

// True while the owner process is still reachable: either it is still this
// process's parent, or it is still alive after a reparent (the kernel module
// helper forks the loader, so only the pid is authoritative).
bool owner_alive(int caller_pid);

// Blocks until the owner process has exited.  Sleeps one second between checks.
void wait_for_owner_exit(int caller_pid);

}  // namespace maplesu::payload::webui
