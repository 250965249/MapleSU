// resetprop -- persistent property storage.
//
// Ported from Magisk v30.7 ``native/src/core/resetprop/persist.rs``.  Android
// keeps persistent properties in ``/data/property``; the same directory can be a
// protobuf-encoded record list (current releases) or one file per property
// (older releases).  Both forms are supported, the protobuf form is preferred
// when its marker file exists, and writes go through a temporary file plus
// rename so a crash never leaves a partially written record list.
//
#pragma once

#include <string>
#include <vector>

#include "persist_proto.h"

namespace maplesu::payload::resetprop {

inline constexpr const char* kPersistDir = "/data/property";
inline constexpr const char* kPersistProtoName = "persistent_properties";

// The record schema and its protobuf codec live in persist_proto.h; the store
// below only owns the file layout and atomic publication.

class PersistentStore {
public:
    explicit PersistentStore(std::string base_dir = kPersistDir);

    // Reads one persistent value.  False when the key is not stored.
    bool get(const std::string& key, std::string& value) const;
    // Stores a value (create or replace).
    bool set(const std::string& key, const std::string& value);
    // Removes a value (both representations).
    bool erase(const std::string& key);
    // Enumerates every stored property, sorted by name.
    bool for_each(std::vector<PersistentRecord>& records) const;

    // Last failure reason (errno text or decode diagnostic).
    const std::string& last_error() const { return last_error_; }

private:
    std::string proto_path() const;
    bool proto_present() const;
    bool proto_read(std::vector<PersistentRecord>& records) const;
    bool proto_write(const std::vector<PersistentRecord>& records);
    bool file_get(const std::string& key, std::string& value) const;
    bool file_set(const std::string& key, const std::string& value);
    bool file_erase(const std::string& key);
    bool fail(const std::string& reason) const;

    std::string base_dir_;
    mutable std::string last_error_;
};

}  // namespace maplesu::payload::resetprop
