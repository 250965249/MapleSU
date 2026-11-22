#include "../../../src/maplesu/compat/module_install_legacy_abi.h"
#include "../../../src/maplesu/module/operations.h"
#include "fixture_config.h"
#include <cstring>
namespace maplesu::module {
KModErr find_module_elf_in_zip(const char*, Descriptor& desc, std::string& name) {
    name = "fixture_mod";
    strcpy(desc.id32, name.c_str());
    desc.min_sdk_ver = {4, 0, 5};
    return KModErr::OK;
}
}
namespace maplesu::sdk {
KModErr unsafe_reset_autorun_bootstrap_safe_flag() { return fixture::reset_result; }
MapleSUSdkVersion get_sdk_version() { return {5, 2, 0}; }
namespace features::callback {
KModErr invoke_module_on_install(const std::string&, std::string&) { return fixture::install_result; }
KModErr invoke_module_on_uninstall(const std::string&) { return KModErr::OK; }
}
}
