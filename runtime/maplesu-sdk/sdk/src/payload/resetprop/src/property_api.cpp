// resetprop -- dynamic Android property API implementation.
//
#include "property_api.h"

#include "persist.h"

#include <cstdio>
#include <cstring>

#include <dlfcn.h>

namespace maplesu::payload::resetprop {
namespace {

constexpr const char* kFind = "__system_property_find";
constexpr const char* kFindMutable = "__system_property_find2";
constexpr const char* kReadCallback = "__system_property_read_callback";
constexpr const char* kReadClassic = "__system_property_read";
constexpr const char* kForeach = "__system_property_foreach";
constexpr const char* kSet = "__system_property_set";
constexpr const char* kUpdate = "__system_property_update";
constexpr const char* kUpdateNew = "__system_property_update2";
constexpr const char* kAdd = "__system_property_add";
constexpr const char* kAddNew = "__system_property_add2";
constexpr const char* kDelete = "__system_property_delete";
constexpr const char* kContext = "__system_property_get_context";
constexpr const char* kAreaSerial = "__system_property_area_serial";
constexpr const char* kAreaSerialNew = "__system_property_area_serial2";
constexpr const char* kWait = "__system_property_wait";
constexpr const char* kInit = "__system_properties_init";

template <typename Fn>
Fn resolve_symbol(const char* name) {
    void* symbol = ::dlsym(RTLD_DEFAULT, name);
    return reinterpret_cast<Fn>(symbol);
}

struct ReadCookie {
    std::string* key;
    std::string* value;
    uint32_t* serial;
};

void read_record_callback(void* cookie, const char* key, const char* value,
                          uint32_t serial) {
    auto* state = static_cast<ReadCookie*>(cookie);
    if (state->key != nullptr) state->key->assign((key != nullptr) ? key : "");
    if (state->value != nullptr) state->value->assign((value != nullptr) ? value : "");
    if (state->serial != nullptr) *state->serial = serial;
}

}  // namespace

PropertyApi::PropertyApi() { resolve(); }

PropertyApi& PropertyApi::instance() {
    static PropertyApi api;
    return api;
}

void PropertyApi::resolve() {
    find_ = resolve_symbol<FindFn>(kFind);
    find_mutable_ = resolve_symbol<FindMutableFn>(kFindMutable);
    if (find_mutable_ == nullptr) {
        find_mutable_ = reinterpret_cast<FindMutableFn>(find_);
    }
    read_callback_ = resolve_symbol<ReadCallbackFn>(kReadCallback);
    read_classic_ = resolve_symbol<ReadClassicFn>(kReadClassic);
    foreach_ = resolve_symbol<ForeachFn>(kForeach);
    set_ = resolve_symbol<SetFn>(kSet);
    update_ = resolve_symbol<UpdateFn>(kUpdateNew);
    if (update_ == nullptr) update_ = resolve_symbol<UpdateFn>(kUpdate);
    add_ = resolve_symbol<AddFn>(kAddNew);
    if (add_ == nullptr) add_ = resolve_symbol<AddFn>(kAdd);
    remove_ = resolve_symbol<DeleteFn>(kDelete);
    context_ = resolve_symbol<ContextFn>(kContext);
    area_serial_ = resolve_symbol<AreaSerialFn>(kAreaSerial);
    area_serial2_ = resolve_symbol<AreaSerialFn>(kAreaSerialNew);
    wait_ = resolve_symbol<WaitFn>(kWait);

    if (auto init = resolve_symbol<InitFn>(kInit); init != nullptr) {
        if (init() != 0) {
            // The reference applet reports this on its error stream once the area
            // could not be initialised; later calls then fail per property.
            std::fprintf(stderr, "resetprop: __system_properties_init error\n");
        }
    }
}

bool PropertyApi::read_record(const PropInfo* info, std::string& key,
                             std::string& value, uint32_t& serial) const {
    if (info == nullptr) return false;
    serial = info->serial;
    if (read_callback_ != nullptr) {
        ReadCookie cookie{&key, &value, &serial};
        read_callback_(info, read_record_callback, &cookie);
        return true;
    }
    if (read_classic_ != nullptr) {
        char name[kPropNameMax] = {};
        char buffer[kPropValueMax * 2] = {};
        read_classic_(info, name, buffer);
        key = name;
        value = buffer;
        serial = info->serial;
        return true;
    }
    return false;
}

bool PropertyApi::get_with_serial(const PropInfo* info, std::string& value,
                                  uint32_t& serial) const {
    std::string ignored_key;
    return read_record(info, ignored_key, value, serial);
}

bool PropertyApi::get(const char* key, std::string& value) const {
    if (key == nullptr) return false;
    const PropInfo* info = find(key);
    if (info == nullptr) return false;
    uint32_t serial = 0;
    return get_with_serial(info, value, serial);
}

const char* PropertyApi::context(const char* key) const {
    if (context_ == nullptr || key == nullptr) return nullptr;
    return context_(key);
}

bool PropertyApi::is_long(const PropInfo* info) const {
    if (info == nullptr) return false;
    return (info->serial & kLongPropertyFlag) != 0;
}

PropInfo* PropertyApi::find_mutable(const char* key) const {
    if (find_mutable_ == nullptr || key == nullptr) return nullptr;
    return find_mutable_(key);
}

const PropInfo* PropertyApi::find(const char* key) const {
    if (find_ == nullptr || key == nullptr) return nullptr;
    return find_(key);
}

void PropertyApi::for_each(PropForeachCallback callback, void* cookie) const {
    if (foreach_ == nullptr || callback == nullptr) return;
    foreach_(callback, cookie);
}

bool PropertyApi::set(const char* key, const char* value) const {
    if (set_ == nullptr || key == nullptr || value == nullptr) return false;
    return set_(key, value) == 0;
}

bool PropertyApi::update(PropInfo* info, const char* value, size_t length) const {
    if (update_ == nullptr || info == nullptr || value == nullptr) return false;
    return update_(info, value, static_cast<uint32_t>(length)) == 0;
}

bool PropertyApi::add(const char* key, const char* value, size_t length) const {
    if (add_ == nullptr || key == nullptr || value == nullptr) return false;
    return add_(key, static_cast<uint32_t>(std::strlen(key)), value,
                static_cast<uint32_t>(length)) == 0;
}

bool PropertyApi::remove(const char* key, bool prune) const {
    if (remove_ == nullptr || key == nullptr) return false;
    return remove_(key, prune) == 0;
}

uint32_t PropertyApi::area_serial() const {
    if (area_serial2_ != nullptr) return area_serial2_();
    if (area_serial_ != nullptr) return area_serial_();
    return 0;
}

bool PropertyApi::wait_for_change(const PropInfo* info, uint32_t old_serial,
                                  uint32_t& new_serial) const {
    if (wait_ == nullptr) return false;
    uint32_t observed = old_serial;
    const int result = wait_(info, old_serial, &observed, nullptr);
    new_serial = observed;
    return result == 0;
}

namespace {

// Android implementation of the command-layer boundary: the dynamically resolved
// property area for the live map, and the persistent-property store for storage.
class AndroidPropertyBackend final : public PropertyBackend {
public:
    const PropInfo* find(const char* key) const override {
        return PropertyApi::instance().find(key);
    }
    PropInfo* find_mutable(const char* key) override {
        return PropertyApi::instance().find_mutable(key);
    }
    bool read(const PropInfo* info, std::string& key, std::string& value,
              uint32_t& serial) const override {
        return PropertyApi::instance().read_record(info, key, value, serial);
    }
    bool is_long(const PropInfo* info) const override {
        return PropertyApi::instance().is_long(info);
    }
    void for_each(PropForeachCallback callback, void* cookie) const override {
        PropertyApi::instance().for_each(callback, cookie);
    }
    bool set(const char* key, const char* value) override {
        return PropertyApi::instance().set(key, value);
    }
    bool update(PropInfo* info, const char* value, size_t length) override {
        return PropertyApi::instance().update(info, value, length);
    }
    bool add(const char* key, const char* value, size_t length) override {
        return PropertyApi::instance().add(key, value, length);
    }
    bool remove(const char* key, bool prune) override {
        return PropertyApi::instance().remove(key, prune);
    }
    const char* context(const char* key) const override {
        return PropertyApi::instance().context(key);
    }
    uint32_t area_serial() const override {
        return PropertyApi::instance().area_serial();
    }
    bool wait_for_change(const PropInfo* info, uint32_t old_serial,
                         uint32_t& new_serial) const override {
        return PropertyApi::instance().wait_for_change(info, old_serial, new_serial);
    }
    bool persist_get(const std::string& key, std::string& value) override {
        return store_.get(key, value);
    }
    bool persist_set(const std::string& key, const std::string& value) override {
        return store_.set(key, value);
    }
    bool persist_erase(const std::string& key) override {
        return store_.erase(key);
    }
    bool persist_all(std::vector<PersistentRecord>& records) override {
        return store_.for_each(records);
    }

private:
    PersistentStore store_;
};

}  // namespace

PropertyBackend& android_property_backend() {
    static AndroidPropertyBackend backend;
    return backend;
}

}  // namespace maplesu::payload::resetprop
