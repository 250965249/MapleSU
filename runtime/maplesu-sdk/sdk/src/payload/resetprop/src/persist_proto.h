// resetprop -- protobuf codec for the persistent property record list.
//
// The record list is the platform's own proto2 schema (see persist.h).  The codec
// lives in its own header so the host contract tests can round-trip it without
// the Android filesystem layer.
//
#pragma once

#include <algorithm>
#include <string>
#include <vector>

namespace maplesu::payload::resetprop {

struct PersistentRecord {
    bool has_name = false;
    bool has_value = false;
    std::string name;
    std::string value;
};

namespace persist_detail {

inline void append_varint(std::string& out, uint64_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<char>((value & 0x7fu) | 0x80u));
        value >>= 7;
    }
    out.push_back(static_cast<char>(value));
}

inline void append_tag(std::string& out, uint32_t field, uint32_t wire) {
    append_varint(out, (static_cast<uint64_t>(field) << 3) | wire);
}

inline void append_string_field(std::string& out, uint32_t field,
                                const std::string& value) {
    append_tag(out, field, 2);
    append_varint(out, value.size());
    out.append(value);
}

inline bool read_varint(const std::string& bytes, size_t& offset, uint64_t& value) {
    value = 0;
    int shift = 0;
    while (offset < bytes.size()) {
        const unsigned char byte = static_cast<unsigned char>(bytes[offset++]);
        value |= static_cast<uint64_t>(byte & 0x7fu) << shift;
        if ((byte & 0x80u) == 0) return true;
        shift += 7;
        if (shift > 63) return false;
    }
    return false;
}

inline bool read_length_delimited(const std::string& bytes, size_t& offset,
                                  std::string& out) {
    uint64_t length = 0;
    if (!read_varint(bytes, offset, length)) return false;
    if (length > bytes.size() - offset) return false;
    out.assign(bytes, offset, static_cast<size_t>(length));
    offset += static_cast<size_t>(length);
    return true;
}

inline bool skip_field(const std::string& bytes, size_t& offset, uint32_t wire) {
    switch (wire) {
        case 0: {
            uint64_t ignored = 0;
            return read_varint(bytes, offset, ignored);
        }
        case 1:
            if (bytes.size() - offset < 8) return false;
            offset += 8;
            return true;
        case 2: {
            std::string ignored;
            return read_length_delimited(bytes, offset, ignored);
        }
        case 5:
            if (bytes.size() - offset < 4) return false;
            offset += 4;
            return true;
        default:
            return false;
    }
}

inline bool decode_record(const std::string& bytes, PersistentRecord& record) {
    size_t offset = 0;
    while (offset < bytes.size()) {
        uint64_t tag = 0;
        if (!read_varint(bytes, offset, tag)) return false;
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 0x7u);
        if (wire == 2 && (field == 1 || field == 2)) {
            std::string value;
            if (!read_length_delimited(bytes, offset, value)) return false;
            if (field == 1) {
                record.name = std::move(value);
                record.has_name = true;
            } else {
                record.value = std::move(value);
                record.has_value = true;
            }
        } else if (!skip_field(bytes, offset, wire)) {
            return false;
        }
    }
    return true;
}

inline bool record_less(const PersistentRecord& left, const PersistentRecord& right) {
    return left.name < right.name;
}

}  // namespace persist_detail

inline bool decode_persistent_properties(const std::string& bytes,
                                         std::vector<PersistentRecord>& records) {
    using namespace persist_detail;
    records.clear();
    size_t offset = 0;
    while (offset < bytes.size()) {
        uint64_t tag = 0;
        if (!read_varint(bytes, offset, tag)) return false;
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const uint32_t wire = static_cast<uint32_t>(tag & 0x7u);
        if (wire == 2 && field == 1) {
            std::string payload;
            if (!read_length_delimited(bytes, offset, payload)) return false;
            PersistentRecord record;
            if (!decode_record(payload, record)) return false;
            records.push_back(std::move(record));
        } else if (!skip_field(bytes, offset, wire)) {
            return false;
        }
    }
    // The platform keeps the record list name-ordered so lookups can binary
    // search; restore that invariant after decoding.
    std::sort(records.begin(), records.end(), record_less);
    return true;
}

inline std::string encode_persistent_properties(
    const std::vector<PersistentRecord>& records) {
    using namespace persist_detail;
    std::vector<const PersistentRecord*> ordered;
    ordered.reserve(records.size());
    for (const auto& record : records) ordered.push_back(&record);
    std::sort(ordered.begin(), ordered.end(),
              [](const PersistentRecord* left, const PersistentRecord* right) {
                  return left->name < right->name;
              });
    std::string out;
    for (const PersistentRecord* record : ordered) {
        std::string payload;
        if (record->has_name) append_string_field(payload, 1, record->name);
        if (record->has_value) append_string_field(payload, 2, record->value);
        append_tag(out, 1, 2);
        append_varint(out, payload.size());
        out.append(payload);
    }
    return out;
}

}  // namespace maplesu::payload::resetprop
