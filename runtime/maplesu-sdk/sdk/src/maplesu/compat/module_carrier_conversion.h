#pragma once

#include "../module/types.h"
#include <cstring>

namespace maplesu::compat {
template <typename Destination, typename Source>
static inline void copy_module_descriptor_fields(unsigned char* to, const unsigned char* from) {
    static_assert(sizeof(Destination::name) == sizeof(Source::name));
    static_assert(sizeof(Destination::version) == sizeof(Source::version));
    static_assert(sizeof(Destination::desc) == sizeof(Source::desc));
    static_assert(sizeof(Destination::author) == sizeof(Source::author));
    static_assert(sizeof(Destination::id32) == sizeof(Source::id32));
    static_assert(sizeof(Destination::update_json) == sizeof(Source::update_json));
    static_assert(sizeof(Destination::web_ui) == sizeof(Source::web_ui));
    const auto copy = [&](std::size_t destination, std::size_t source, std::size_t size) {
        std::memcpy(to + destination, from + source, size);
    };
    copy(offsetof(Destination, name), offsetof(Source, name), sizeof(Destination::name));
    copy(offsetof(Destination, version), offsetof(Source, version), sizeof(Destination::version));
    copy(offsetof(Destination, desc), offsetof(Source, desc), sizeof(Destination::desc));
    copy(offsetof(Destination, author), offsetof(Source, author), sizeof(Destination::author));
    copy(offsetof(Destination, id32), offsetof(Source, id32), sizeof(Destination::id32));
    copy(offsetof(Destination, update_json), offsetof(Source, update_json), sizeof(Destination::update_json));
    copy(offsetof(Destination, web_ui), offsetof(Source, web_ui), sizeof(Destination::web_ui));
    constexpr std::size_t to_begin = offsetof(Destination, web_ui) + sizeof(Destination::web_ui);
    constexpr std::size_t from_begin = offsetof(Source, web_ui) + sizeof(Source::web_ui);
    constexpr std::size_t to_padding = offsetof(Destination, min_sdk_ver) - to_begin;
    constexpr std::size_t from_padding = offsetof(Source, min_sdk_ver) - from_begin;
    constexpr std::size_t padding = to_padding < from_padding ? to_padding : from_padding;
    if constexpr (to_padding > from_padding) std::memset(to + to_begin, 0, to_padding);
    if constexpr (padding != 0) copy(to_begin, from_begin, padding);
    using DestinationVersion = decltype(Destination::min_sdk_ver);
    using SourceVersion = decltype(Source::min_sdk_ver);
    static_assert(sizeof(DestinationVersion::major) == sizeof(SourceVersion::major));
    static_assert(sizeof(DestinationVersion::minor) == sizeof(SourceVersion::minor));
    static_assert(sizeof(DestinationVersion::patch) == sizeof(SourceVersion::patch));
    copy(offsetof(Destination, min_sdk_ver) + offsetof(DestinationVersion, major),
         offsetof(Source, min_sdk_ver) + offsetof(SourceVersion, major), sizeof(DestinationVersion::major));
    copy(offsetof(Destination, min_sdk_ver) + offsetof(DestinationVersion, minor),
         offsetof(Source, min_sdk_ver) + offsetof(SourceVersion, minor), sizeof(DestinationVersion::minor));
    copy(offsetof(Destination, min_sdk_ver) + offsetof(DestinationVersion, patch),
         offsetof(Source, min_sdk_ver) + offsetof(SourceVersion, patch), sizeof(DestinationVersion::patch));
}

template <typename Destination, typename Source>
static inline void copy_module_descriptor(Destination& to, const Source& from) {
    copy_module_descriptor_fields<Destination, Source>(reinterpret_cast<unsigned char*>(&to),
        reinterpret_cast<const unsigned char*>(&from));
}

template <typename Destination, typename Source>
static inline void copy_module_record(Destination& to, const Source& from) {
    copy_module_descriptor_fields<decltype(Destination::desc), decltype(Source::desc)>(
        reinterpret_cast<unsigned char*>(&to) + offsetof(Destination, desc),
        reinterpret_cast<const unsigned char*>(&from) + offsetof(Source, desc));
    static_assert(sizeof(Destination::state) == sizeof(Source::state));
    std::memcpy(reinterpret_cast<unsigned char*>(&to) + offsetof(Destination, state),
        reinterpret_cast<const unsigned char*>(&from) + offsetof(Source, state), sizeof(Destination::state));
}
}  // namespace maplesu::compat
