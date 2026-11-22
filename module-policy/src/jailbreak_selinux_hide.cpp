#include "../../jailbreak-providers/root-loader/selinux_hide_abi.h"
#include "jailbreak_status_layout.h"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {
std::vector<uint8_t> read_bounded(const char* path, size_t limit) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) throw std::system_error(errno, std::generic_category(), "JAILBREAK_SELINUX_OPEN");
    std::vector<uint8_t> result;
    std::array<uint8_t, 65536> buffer;
    for (;;) {
        auto count = read(fd, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            const int error = errno;
            close(fd);
            // Some kernels allow open but deny read. Preserve errno so the
            // same verified-anchor fallback handles both permission boundaries.
            throw std::system_error(error, std::generic_category(), "JAILBREAK_SELINUX_READ");
        }
        if (static_cast<size_t>(count) > limit - result.size()) {
            close(fd);
            throw std::runtime_error("JAILBREAK_SELINUX_READ");
        }
        if (!count) break;
        result.insert(result.end(), buffer.begin(), buffer.begin() + count);
    }
    close(fd);
    return result;
}

void control(msu_selinux_hide& packet) {
    packet.acknowledged = 0;
    // The kernel answers in the packet. PR_SET_DUMPABLE deliberately rejects
    // op=2; its syscall return value is never a kernel capability receipt.
    (void)prctl(4, static_cast<unsigned long>(MSU_STATUS_OP),
        static_cast<unsigned long>(MSU_STATUS_TAG_LO),
        static_cast<unsigned long>(MSU_STATUS_TAG_HI), &packet);
    if (packet.acknowledged != MSU_STATUS_ACK) throw std::runtime_error("JAILBREAK_SELINUX_BACKEND_UNAVAILABLE");
    if (packet.result) throw std::runtime_error("JAILBREAK_SELINUX_KERNEL:" + std::to_string(packet.result));
}
}

int jailbreak_selinux_hide(int argc, char** argv) {
    if (getuid() || geteuid()) throw std::runtime_error("JAILBREAK_SELINUX_ROOT_REQUIRED");
    if (argc != 2 && argc != 4) throw std::runtime_error("usage: maplesu-policy jailbreak-hide [BASELINE|default|set 0|1]");
    if (argc == 4 && strcmp(argv[3], "0") && strcmp(argv[3], "1"))
        throw std::runtime_error("JAILBREAK_SELINUX_REQUEST");
    const bool changing = argc == 4;
    const unsigned requested = changing ? static_cast<unsigned>(argv[3][0] - '0') : 0;
    int btf_read_errno = 0;
    int baseline_read_errno = 0;
    msu_selinux_hide packet{};
    packet.version = MSU_STATUS_VERSION;
    control(packet);
    if (changing && !packet.initialized) {
        if (!strcmp(argv[2], "set")) throw std::runtime_error("JAILBREAK_SELINUX_NOT_INITIALIZED");
        if (!packet.available) throw std::runtime_error("JAILBREAK_SELINUX_BACKEND_UNAVAILABLE");
        using namespace maplesu::module_policy;
        auto page_bytes = static_cast<uint32_t>(sysconf(_SC_PAGESIZE));
        try {
            auto btf = read_bounded("/sys/kernel/btf/vmlinux", 64 << 20);
            packet.layout = resolve_jailbreak_status_layout(btf, page_bytes);
        } catch (const std::system_error& error) {
            btf_read_errno = error.code().value();
            if (btf_read_errno != ENOENT && btf_read_errno != ENOTDIR &&
                btf_read_errno != EACCES && btf_read_errno != EPERM) throw;
            // Protected sysfs BTF is not a layout mismatch. The independent
            // live anchors are rederived and confirmed by the kernel backend.
            packet.layout = resolve_jailbreak_status_anchors(packet.anchors, page_bytes);
        }
        // A default is explicit in the receipt and uses the verified live page
        // under status_lock. Never turn App EACCES into an invented stock capture.
        packet.allow_default = 1;
        packet.baseline_kind = MSU_STATUS_BASELINE_DEFAULT;
        if (strcmp(argv[2], "default")) {
            try {
                auto baseline = read_bounded(argv[2], sizeof(msu_selinux_window_file));
                if (baseline.size() == sizeof(msu_selinux_status)) {
                    memcpy(&packet.baseline, baseline.data(), sizeof(packet.baseline));
                    packet.baseline_kind = MSU_STATUS_BASELINE_SNAPSHOT;
                } else if (baseline.size() == sizeof(msu_selinux_window_file)) {
                    msu_selinux_window_file window{};
                    memcpy(&window, baseline.data(), sizeof(window));
                    packet.baseline = window.start;
                    packet.window_end = window.end;
                    packet.restore_from = window.restore_from;
                    packet.restore_to = window.restore_to;
                    packet.baseline_kind = MSU_STATUS_BASELINE_WINDOW;
                } else baseline_read_errno = EINVAL;
            } catch (const std::system_error& error) {
                baseline_read_errno = error.code().value();
            } catch (const std::runtime_error&) {
                baseline_read_errno = EINVAL;
            }
        }
        packet.command = MSU_STATUS_INITIALIZE;
        packet.requested = requested;
        control(packet);
    } else if (changing && packet.effective != requested) {
        if (!(packet.available & MSU_STATUS_CAN_SET))
            throw std::runtime_error("JAILBREAK_SELINUX_SWITCH_UNSUPPORTED");
        packet.command = MSU_STATUS_SET;
        packet.requested = requested;
        control(packet);
    }
    // Read the actual shared status page on every query, not just a retained
    // initialization receipt. This is also the process-context application step.
    msu_selinux_status observed{};
    bool stable = false;
    for (unsigned retry = 0; retry < 4; ++retry) {
        auto first = read_bounded("/sys/fs/selinux/status", sizeof(observed));
        auto second = read_bounded("/sys/fs/selinux/status", sizeof(observed));
        if (first.size() != sizeof(observed) || second.size() != sizeof(observed))
            throw std::runtime_error("JAILBREAK_SELINUX_STATUS_SIZE");
        memcpy(&observed, first.data(), sizeof(observed));
        if (observed.version == 1 && !(observed.sequence & 1u) && first == second) {
            stable = true;
            break;
        }
    }
    if (!stable) throw std::runtime_error("JAILBREAK_SELINUX_STATUS_UNSTABLE");
    if (changing && !packet.initialized) {
        // Acquire status_lock in the read's normal process context, after the
        // prctl pre-handler queued the authenticated one-time request.
        packet.command = MSU_STATUS_QUERY;
        control(packet);
        if (!packet.initialized) throw std::runtime_error("JAILBREAK_SELINUX_INITIALIZATION_PENDING");
    }
    if (changing && packet.effective != requested)
        throw std::runtime_error("JAILBREAK_SELINUX_REQUEST_NOT_APPLIED");
    printf("{\"available\":%s,\"initialized\":%s,\"effective\":%s,"
        "\"baselineSequence\":%u,\"beforeSequence\":%u,\"afterSequence\":%u,\"policyload\":%u,"
        "\"abiVersion\":%u,\"layoutSource\":%u,\"stateBytes\":%u,\"statusLock\":%u,"
        "\"mutexBytes\":%u,\"pageBytes\":%u,\"statusPageArguments\":%u,\"btfReadErrno\":%d,\"toggleSupported\":%s,\"observedSequence\":%u,\"observedPolicyload\":%u,\"observedEnforcing\":%u,"
        "\"baselineSource\":\"%s\",\"baselineReadErrno\":%d,\"windowEndSequence\":%u,\"windowEndPolicyload\":%u}\n",
        packet.available ? "true" : "false", packet.initialized ? "true" : "false",
        packet.effective ? "true" : "false", packet.baseline.sequence, packet.before.sequence,
        packet.after.sequence, packet.after.policyload, packet.version, packet.layout.source,
        packet.layout.state_size, packet.layout.status_lock, packet.layout.mutex_size,
        packet.layout.page_bytes, packet.layout.status_page_abi, btf_read_errno,
        packet.available & MSU_STATUS_CAN_SET ? "true" : "false",
        observed.sequence, observed.policyload, observed.enforcing,
        packet.baseline_kind == MSU_STATUS_BASELINE_WINDOW ? "root-window" :
            packet.baseline_kind == MSU_STATUS_BASELINE_DEFAULT ? "normalized-default" : "pre-entry",
        baseline_read_errno, packet.window_end.sequence, packet.window_end.policyload);
    return 0;
}
