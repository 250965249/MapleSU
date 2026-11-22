// webui_loader -- owner-process watchdog implementation.
//
#include "parent_watch.h"

#include <cerrno>
#include <ctime>

#include <signal.h>
#include <unistd.h>

namespace maplesu::payload::webui {
namespace {

constexpr long kPollSeconds = 1;

void sleep_one_second() {
    struct timespec request {};
    request.tv_sec = kPollSeconds;
    request.tv_nsec = 0;
    while (::nanosleep(&request, &request) != 0 && errno == EINTR) {
        // keep waiting: a signal must not shorten the poll interval
    }
}

}  // namespace

bool owner_alive(int caller_pid) {
    if (caller_pid <= 0) return false;
    if (::getppid() == static_cast<pid_t>(caller_pid)) return true;
    // The loader may have been reparented (the kit helper forks it); the recorded
    // pid is still the session owner, so probe it without delivering a signal.
    if (::kill(static_cast<pid_t>(caller_pid), 0) == 0) return true;
    return errno == EPERM;
}

void wait_for_owner_exit(int caller_pid) {
    while (owner_alive(caller_pid)) sleep_one_second();
}

}  // namespace maplesu::payload::webui
