#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace maplesu::module_policy {

// One value commits both dependent switches. Bit 1 is never valid on its own.
enum class Mode : unsigned { Block = 0, Load = 1, Hide = 3 };

struct BootState {
    Mode mode;
    unsigned capabilities;
    std::string boot_id;
};

struct State {
    Mode requested = Mode::Block;
    std::optional<BootState> effective;
    bool unverified_hide = false;
    bool can_try_unverified = false;
    bool hide_failed = false;
};

// Owns a validated root-only directory. Reads never create or repair state.
class Store {
public:
    explicit Store(int directory);
    ~Store();
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
    static Store open(bool create);
    State read(const std::string& boot_id) const;
    // Current-boot provenance determines which backend may validate status.
    bool owns_hook(const std::string& boot_id) const;
    // Runtime transactions use the boot-latched state, never the next-boot request.
    // Ultra callers require a proven current-boot backend; legacy callers keep
    // their existing no-backend contract until explicitly migrated.
    bool blocks_transactions(const std::string& boot_id, bool require_ready = false) const;
    void request(Mode mode, const std::string& boot_id, bool allow_unverified = false);
    // The synchronous boot backend calls this only after establishing its hooks.
    // Saving a user preference never publishes effective state.
    void publish(const BootState& state);
    // Serializes pre-module initialization and publishes only a prepared backend.
    // Re-entry in the same boot never reapplies a pending user preference.
    // A durable attempt prevents repeated installation. Ordinary loading is
    // published only after cancellation succeeds; failed recovery stays pending.
    BootState prepare_boot(const std::string& boot_id, unsigned (*prepare)(Mode, bool), bool supports_unverified = false);
    // The caller also holds the policy transaction lock. Without a backend,
    // only the userspace gate is available. A backend publishes Hide only after
    // activation/readback and must resume resident state after interruption.
    BootState prepare_hook(const std::string& boot_id, std::optional<Mode> requested = std::nullopt,
                           unsigned (*prepare)(Mode, bool) = nullptr, bool allow_unverified = false);
    // Best-effort bounded evidence; never changes preparation or query results.
    void record_compatibility(const std::string& report) const noexcept;
    // Boot-bound activation address permits cancellation after a process exit.
    // The synchronous boot owner already holds the preparation lock.
    void remember_activation(const std::string& boot_id, uint64_t address) const;
    std::optional<uint64_t> activation(const std::string& boot_id) const;
private:
    int directory_;
    std::optional<std::string> read_file(const char* name) const;
    void replace(const char* name, const std::string& text) const;
};

bool valid_mode(unsigned mode);
bool valid_boot_id(const std::string& value);
std::string current_boot_id();
std::string json(const State& state);

} // namespace maplesu::module_policy
