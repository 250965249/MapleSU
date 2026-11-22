// SPDX-License-Identifier: GPL-3.0-only
// Shared image/layout selection: SDK and temporary Hook use one qualifier.
#include "kernel_payload_loader.h"
#include "module_policy_config.h"
#include <array>
#include <cerrno>
#include <ctime>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <zlib.h>

namespace maplesu::module_policy {
namespace {
std::vector<uint8_t> read_file(const char* path, size_t limit, bool optional) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        if (optional && errno == ENOENT) return {};
        throw std::runtime_error("MODULE_POLICY_KERNEL_METADATA_OPEN");
    }
    std::vector<uint8_t> bytes;
    try {
        struct stat st{};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode)) throw std::runtime_error("MODULE_POLICY_KERNEL_METADATA_TYPE");
        std::array<uint8_t, 65536> buffer;
        for (;;) {
            auto length = ::read(fd, buffer.data(), buffer.size());
            if (length < 0 && errno == EINTR) continue;
            if (length < 0) throw std::runtime_error("MODULE_POLICY_KERNEL_METADATA_READ");
            if (!length) break;
            if (size_t(length) > limit - bytes.size()) throw std::runtime_error("MODULE_POLICY_KERNEL_METADATA_SIZE");
            bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + length);
        }
        close(fd);
    } catch (...) { close(fd); throw; }
    return bytes;
}
std::string kernel_config() {
    auto compressed = read_file("/proc/config.gz", 2 << 20, false);
    std::string config(4 << 20, '\0');
    z_stream stream{};
    stream.next_in = compressed.data();
    stream.avail_in = compressed.size();
    stream.next_out = reinterpret_cast<Bytef*>(config.data());
    stream.avail_out = config.size();
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK)
        throw std::runtime_error("MODULE_POLICY_KERNEL_CONFIG_INIT");
    auto result = inflate(&stream, Z_FINISH);
    auto size = stream.total_out;
    bool complete = result == Z_STREAM_END && !stream.avail_in;
    inflateEnd(&stream);
    if (!complete) throw std::runtime_error("MODULE_POLICY_KERNEL_CONFIG_GZIP");
    config.resize(size);
    return config;
}
}
unsigned prepare_policy_view_with(PolicyKernelIo& io, bool preflight_only, bool allow_unverified) {
    if (getuid() || geteuid()) throw std::runtime_error("MODULE_POLICY_SDK_ROOT_REQUIRED");
    struct utsname current{};
    std::string diagnostic = "schema=1 time=" + std::to_string(time(nullptr)) +
        " operation=" + (preflight_only ? "preflight" : "install") + "\n";
    if (!uname(&current)) diagnostic += std::string("kernel=") + current.release + "\n";
    auto persist = [&] {
        try {
            auto record = diagnostic;
            if (record.size() > 7800)
                record = record.substr(0, 3800) + "\nTRUNCATED_MIDDLE\n" + record.substr(record.size() - 3800);
            Store::open(false).record_compatibility(record + "boot=" + current_boot_id() + "\nEND\n");
        } catch (...) { }
    };
    diagnostic += std::string("result=started userConfirmedUnverified=") + (allow_unverified ? "1\n" : "0\n");
    persist();
    try {
    std::string id;
    std::vector<uint8_t> btf;
    try { id = kernel_build_id(read_file("/sys/kernel/notes", 65536, false)); }
    catch (const std::runtime_error& error) {
        diagnostic += std::string("notesUnavailable=") + error.what() + "\n";
    }
    try { btf = read_file("/sys/kernel/btf/vmlinux", 64 << 20, true); }
    catch (const std::runtime_error& error) {
        if (!allow_unverified) throw;
        diagnostic += std::string("btfUnavailable=") + error.what() + "\n";
    }
    auto page_size = static_cast<uint32_t>(sysconf(_SC_PAGESIZE));
    diagnostic += "buildId=" + id + " pageSize=" + std::to_string(page_size) +
        " btfBytes=" + std::to_string(btf.size()) + "\n";
    const KernelPolicyBundle* selected = nullptr;
    for (const auto& bundle : kernel_policy_bundles()) {
        if (id.empty() || bundle.build_id != id || bundle.page_size != page_size) continue;
        if (selected) throw std::runtime_error("MODULE_POLICY_LOADER_IMAGE_AMBIGUOUS");
        selected = &bundle;
    }
    std::string release, config;
    std::string rejection;
    bool already_checked = false;
    if (!selected && !btf.empty()) {
        if (uname(&current)) throw std::runtime_error("MODULE_POLICY_KERNEL_RELEASE");
        release = current.release;
        try { config = kernel_config(); }
        catch (const std::runtime_error& error) {
            diagnostic += std::string("configUnavailable=") + error.what() + "\n";
        }
        for (const auto& bundle : kernel_policy_bundles()) {
            auto series = bundle.kernel_series.empty() && bundle.compatibility ?
                std::string_view(bundle.compatibility->kernel_series) : bundle.kernel_series;
            if (!bundle.compatibility || bundle.page_size != page_size ||
                series.empty() || !release.starts_with(std::string(series) + ".")) continue;
            try { preflight_policy_view(bundle, id, page_size, btf, io, release, config); }
            catch (const std::runtime_error& error) {
                rejection = error.what();
                if (diagnostic.size() < 6000)
                    diagnostic += "candidate=" + std::string(bundle.build_id) + " rejected=" + rejection + "\n";
                continue;
            }
            if (selected) throw std::runtime_error("MODULE_POLICY_LOADER_IMAGE_AMBIGUOUS");
            selected = &bundle;
            already_checked = true;
        }
    }
    if (!selected) throw std::runtime_error(rejection.empty() ? "MODULE_POLICY_LOADER_IMAGE_UNVERIFIED" : rejection);
    diagnostic += "selected=" + std::string(selected->build_id) + "\n";
    if (preflight_only) {
        if (!already_checked) preflight_policy_view(*selected, id, page_size, btf, io);
        diagnostic += "result=compatible hooksInstalled=0\n";
        persist();
        return 3;
    }
    diagnostic += "phase=install-selected\n";
    persist();
    auto result = install_policy_view(*selected, id, page_size, btf, io, release, config, allow_unverified);
    diagnostic += "result=installed capabilities=" + std::to_string(result) + "\n";
    persist();
    return result;
    } catch (const std::exception& error) {
        diagnostic += std::string("result=failed reason=") + error.what() + "\n";
        persist();
        throw;
    }
}
}
