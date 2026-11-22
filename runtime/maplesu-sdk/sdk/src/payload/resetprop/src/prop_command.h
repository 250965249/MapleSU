// resetprop -- the property manipulation commands.
//
// Port of the ``ResetProp`` impl block in Magisk v30.7
// ``native/src/core/resetprop/cli.rs``: read / write / delete / wait / file-load
// modes over the dynamically resolved property API, plus the persistent-storage
// side effects.  The mode dispatch and exit-status rules live in ``run()``.
//
#pragma once

#include <string>
#include <vector>

#include "cli_contract.h"
#include "prop_backend.h"
#include "prop_line.h"

namespace maplesu::payload::resetprop {

// Line parsing for -f/--file lives in prop_line.h (host-tested separately).

class ResetProp {
public:
    // `backend` is the platform boundary; the device program uses the Android
    // implementation, the host differential tests pass a recording fake.
    explicit ResetProp(CliOptions options, PropertyBackend* backend = nullptr);

    // Executes the parsed mode.  False means "report exit status 1 and print
    // nothing else" (the reference applet's silent failure contract).
    bool run();

private:
    bool get(const std::string& key, std::string& value) const;
    void print_all() const;
    void set(const std::string& key, const std::string& value) const;
    bool erase(const std::string& key) const;
    void wait() const;
    bool load_file(const std::string& path) const;

    CliOptions options_;
    PropertyBackend* backend_;
};

}  // namespace maplesu::payload::resetprop
