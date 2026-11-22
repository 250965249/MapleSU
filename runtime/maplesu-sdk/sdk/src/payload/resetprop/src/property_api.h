// resetprop -- dynamic Android property API.
//
// Ported from the resetprop C++/Rust boundary of Magisk v30.7
// (``native/src/core/resetprop/sys.cpp`` and ``native/src/core/resetprop/mod.rs``):
// the applet never links against the platform property functions it manipulates.
// It resolves them at run time from the default namespace and keeps a small table,
// so the same binary works whether the platform exposes the classic property API
// or the newer long-property/mutable variants.  Missing entries degrade to the
// classic call or to a documented failure; nothing is assumed present.
//
#pragma once

#include <cstdint>
#include <string>

#include "prop_backend.h"
#include "prop_limits.h"

namespace maplesu::payload::resetprop {

// Receives (key, value, serial) for one property record.
using PropReadCallback = void (*)(void* cookie, const char* key, const char* value,
                                  uint32_t serial);

class PropertyApi {
public:
    static PropertyApi& instance();

    // True when the minimum property surface (find + read) resolved.
    bool available() const {
        return (read_callback_ != nullptr || read_classic_ != nullptr) &&
               find_ != nullptr;
    }

    // Value lookup; false when the property does not exist.
    bool get(const char* key, std::string& value) const;
    // Full record read: key, value and serial in one platform callback.  Used by
    // print-all (which needs the key) and by the wait loops (which need the
    // serial).  False when the platform offers no read primitive.
    bool read_record(const PropInfo* info, std::string& key, std::string& value,
                     uint32_t& serial) const;
    // Value + serial lookup for wait loops; false when the property is gone.
    bool get_with_serial(const PropInfo* info, std::string& value,
                         uint32_t& serial) const;
    // SELinux context of the property name; nullptr when the platform API or the
    // label is unavailable.
    const char* context(const char* key) const;
    // Long-property representation test used before an in-place update.
    bool is_long(const PropInfo* info) const;
    // Mutable lookup used by the bypass path.
    PropInfo* find_mutable(const char* key) const;
    const PropInfo* find(const char* key) const;
    // Enumerates the property area.
    void for_each(PropForeachCallback callback, void* cookie) const;

    // property_service path.
    bool set(const char* key, const char* value) const;
    // Direct (bypass) path.
    bool update(PropInfo* info, const char* value, size_t length) const;
    bool add(const char* key, const char* value, size_t length) const;
    bool remove(const char* key, bool prune) const;

    // Area serial for wait-without-record loops.
    uint32_t area_serial() const;
    // Blocks until the record (or the whole area when info == nullptr) changes.
    bool wait_for_change(const PropInfo* info, uint32_t old_serial,
                         uint32_t& new_serial) const;

private:
    PropertyApi();
    PropertyApi(const PropertyApi&) = delete;
    PropertyApi& operator=(const PropertyApi&) = delete;

    void resolve();

    using FindFn = const PropInfo* (*)(const char*);
    using FindMutableFn = PropInfo* (*)(const char*);
    using ReadCallbackFn = void (*)(const PropInfo*, PropReadCallback, void*);
    using ReadClassicFn = void (*)(const PropInfo*, char*, char*);
    using ForeachFn = int (*)(PropForeachCallback, void*);
    using SetFn = int (*)(const char*, const char*);
    using UpdateFn = int (*)(PropInfo*, const char*, uint32_t);
    using AddFn = int (*)(const char*, uint32_t, const char*, uint32_t);
    using DeleteFn = int (*)(const char*, bool);
    using ContextFn = const char* (*)(const char*);
    using AreaSerialFn = uint32_t (*)();
    using WaitFn = int (*)(const PropInfo*, uint32_t, uint32_t*, const void*);
    using InitFn = int (*)();

    FindFn find_ = nullptr;
    FindMutableFn find_mutable_ = nullptr;
    ReadCallbackFn read_callback_ = nullptr;
    ReadClassicFn read_classic_ = nullptr;
    ForeachFn foreach_ = nullptr;
    SetFn set_ = nullptr;
    UpdateFn update_ = nullptr;
    AddFn add_ = nullptr;
    DeleteFn remove_ = nullptr;
    ContextFn context_ = nullptr;
    AreaSerialFn area_serial_ = nullptr;
    AreaSerialFn area_serial2_ = nullptr;
    WaitFn wait_ = nullptr;
};

}  // namespace maplesu::payload::resetprop
