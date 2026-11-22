// resetprop -- platform boundary for the property commands.
//
// The command logic (mode dispatch, read/write/delete/wait semantics, persistent
// side effects) is written against this interface so the same code runs against
// the Android property area on the device and against a recording fake in the
// host differential tests.  The recording fake is what makes the behaviour
// comparable operation-by-operation with the reference applet semantics.
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "persist_proto.h"
#include "prop_limits.h"

namespace maplesu::payload::resetprop {

// One property record.  Only the serial word is meaningful to the platform; the
// opaque tag lets a host backend identify a record without reading its contents.
struct PropInfo {
    uint32_t serial;
    uint32_t opaque;
};

// Receives every property record of the area.
using PropForeachCallback = void (*)(const PropInfo* info, void* cookie);

class PropertyBackend {
public:
    virtual ~PropertyBackend() = default;

    virtual const PropInfo* find(const char* key) const = 0;
    virtual PropInfo* find_mutable(const char* key) = 0;
    virtual bool read(const PropInfo* info, std::string& key, std::string& value,
                      uint32_t& serial) const = 0;
    virtual bool is_long(const PropInfo* info) const = 0;
    virtual void for_each(PropForeachCallback callback, void* cookie) const = 0;
    virtual bool set(const char* key, const char* value) = 0;
    virtual bool update(PropInfo* info, const char* value, size_t length) = 0;
    virtual bool add(const char* key, const char* value, size_t length) = 0;
    virtual bool remove(const char* key, bool prune) = 0;
    virtual const char* context(const char* key) const = 0;
    virtual uint32_t area_serial() const = 0;
    virtual bool wait_for_change(const PropInfo* info, uint32_t old_serial,
                                 uint32_t& new_serial) const = 0;

    // Persistent property storage (/data/property in both of its layouts).
    virtual bool persist_get(const std::string& key, std::string& value) = 0;
    virtual bool persist_set(const std::string& key, const std::string& value) = 0;
    virtual bool persist_erase(const std::string& key) = 0;
    virtual bool persist_all(std::vector<PersistentRecord>& records) = 0;
};

// The Android implementation (property area + /data/property on this device).
PropertyBackend& android_property_backend();

}  // namespace maplesu::payload::resetprop
