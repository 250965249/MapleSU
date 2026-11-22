// resetprop -- System Property Manipulation Tool (installed payload program).
//
// The SDK publishes this program as ``<root key dir>/resetprop`` and the module
// kit runs it to force property values during environment bring-up, for example
// ``resetprop -n <name> <value>`` from the SELinux module.  The CLI and the
// property semantics are a port of the open-source Magisk resetprop applet
// (v30.7 ``native/src/core/resetprop``); this file only owns the process edge:
// parse, help/usage exit statuses, and the log-level switch.
//
#include <cstdio>
#include <cstring>
#include <string>

#include "cli_contract.h"
#include "payload_support.h"
#include "prop_command.h"

namespace {

using maplesu::payload::resetprop::CliOptions;
using maplesu::payload::resetprop::ParseKind;
using maplesu::payload::resetprop::ParseResult;
using maplesu::payload::resetprop::ResetProp;

void print_usage(const std::string& program) {
    const std::string text = maplesu::payload::resetprop::usage_text(program);
    std::fputs(text.c_str(), stderr);
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::string program = (argc > 0 && argv[0] != nullptr) ? argv[0] : "resetprop";
    const ParseResult parsed = maplesu::payload::resetprop::parse_cli(argc, argv);

    if (parsed.kind == ParseKind::Help) {
        print_usage(program);
        return 0;
    }
    if (parsed.kind == ParseKind::Error) {
        std::fprintf(stderr, "%s\n", parsed.message.c_str());
        print_usage(program);
        return 1;
    }

    CliOptions options = parsed.options;
    maplesu::payload::set_verbose(options.verbose);
    ResetProp command(options);
    return command.run() ? 0 : 1;
}
