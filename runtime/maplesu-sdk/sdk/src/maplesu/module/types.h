#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace maplesu::module {
struct SdkVersion {
    uint32_t major = 0, minor = 0, patch = 0;
};

constexpr bool operator<(const SdkVersion& a, const SdkVersion& b) {
    if (a.major != b.major) return a.major < b.major;
    if (a.minor != b.minor) return a.minor < b.minor;
    return a.patch < b.patch;
}

struct Descriptor {
    char name[1024] = {}, version[1024] = {}, desc[4096] = {}, author[1024] = {};
    char id32[1024] = {}, update_json[1024] = {};
    bool web_ui = false;
    SdkVersion min_sdk_ver = {};
};

enum class RunState : uint32_t {
    NotRunning = 0,
    Running = 1,
    Abnormal = 2,
    RemovedPendingReboot = 3,
};

struct Record {
    Descriptor desc;
    RunState state = RunState::NotRunning;
};

static_assert(sizeof(SdkVersion) == 12 && alignof(SdkVersion) == 4);
static_assert(offsetof(SdkVersion, major) == 0 && offsetof(SdkVersion, minor) == 4 &&
              offsetof(SdkVersion, patch) == 8);
static_assert(sizeof(Descriptor) == 9232 && alignof(Descriptor) == 4);
static_assert(offsetof(Descriptor, name) == 0 && offsetof(Descriptor, version) == 1024);
static_assert(offsetof(Descriptor, desc) == 2048 && offsetof(Descriptor, author) == 6144);
static_assert(offsetof(Descriptor, id32) == 7168 && offsetof(Descriptor, update_json) == 8192);
static_assert(offsetof(Descriptor, web_ui) == 9216 && offsetof(Descriptor, min_sdk_ver) == 9220);
static_assert(sizeof(RunState) == 4);
static_assert(sizeof(Record) == 9236 && alignof(Record) == 4);
static_assert(offsetof(Record, desc) == 0 && offsetof(Record, state) == 9232);
static_assert(std::is_standard_layout_v<Descriptor> && std::is_trivially_copyable_v<Descriptor>);
static_assert(std::is_standard_layout_v<Record> && std::is_trivially_copyable_v<Record>);
}  // namespace maplesu::module
