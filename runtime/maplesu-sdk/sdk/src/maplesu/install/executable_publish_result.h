#pragma once
#include <cstddef>
#include <cstdint>

namespace maplesu::install {

enum class PublishErrorSource : uint8_t { None, Posix, Condition };
enum class PublishCondition : int64_t {
    InvalidArgument = 1,
    InvalidPath,
    DirectoryOwner,
    DestinationType,
    DestinationOwner,
    DestinationLinks,
    StagingNamesExhausted,
    ZeroWrite,
    SizeMismatch,
};
enum class PublishPhase : uint8_t {
    Input,
    DirectoryOpen,
    DirectoryStat,
    DirectoryOwner,
    DestinationStat,
    DestinationValidate,
    StagingOpen,
    Write,
    Mode,
    Context,
    OutputStat,
    OutputSize,
    FileSync,
    FileClose,
    Rename,
    DirectorySync,
    Complete,
};

// Posix codes are errno captured at the failing call; Condition codes are
// PublishCondition values. Published remains true after rename even if the
// following directory fsync fails. This is an in-process result, not a wire ABI.
struct PublishResult {
    PublishErrorSource source;
    int64_t code;
    PublishPhase phase;
    bool published;
};

__attribute__((visibility("hidden")))
PublishResult publish_executable_result(const char* path, const void* bytes,
                                        size_t size, const char* context);
__attribute__((visibility("hidden")))
PublishResult publish_version_result(const char* path, const void* bytes,
                                     size_t size, const char* context);

}  // namespace maplesu::install
