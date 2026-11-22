#pragma once

#include "types.h"
#include <string>
#include <vector>
#include "module_err_def.h"

namespace maplesu::module {
__attribute__((visibility("hidden")))
KModErr parse_metadata(const std::vector<uint8_t>& elf_bytes, Descriptor& out_desc);
__attribute__((visibility("hidden")))
KModErr find_module_elf_in_zip(const char* archive, Descriptor& out_desc, std::string& out_elf_name);
__attribute__((visibility("hidden")))
KModErr safe_parse_module_desc_from_zip_file(const char* archive, Descriptor& out_desc);
__attribute__((visibility("hidden")))
KModErr unsafe_get_all_modules(std::vector<Record>& out_list);
// Boot recovery excludes only IDs whose installation could not be restored.
__attribute__((visibility("hidden")))
KModErr unsafe_get_boot_modules(std::vector<Record>& out_list,
                                const std::vector<std::string>& excluded);
__attribute__((visibility("hidden")))
KModErr safe_get_all_modules(std::vector<Record>& out_list);
}  // namespace maplesu::module

namespace maplesu::module_install {
struct InstallCompletion;

__attribute__((visibility("hidden")))
KModErr unsafe_uninstall_module(const char* id, bool callback);
// The caller already owns this ID's ModuleMutation; no callback is invoked.
__attribute__((visibility("hidden")))
KModErr cleanup_pending_module(const char* id);
__attribute__((visibility("hidden")))
KModErr safe_uninstall_module(const char* id);
__attribute__((visibility("hidden")))
KModErr safe_install_module(const char* archive, bool run_once, std::string& reason);
__attribute__((visibility("hidden")))
KModErr safe_install_module(const char* archive, bool run_once, std::string& reason,
                           InstallCompletion& completion);
// Recovery is called with this ID's existing ModuleMutation held.
__attribute__((visibility("hidden")))
KModErr recover_installation(const char* id, bool& found);
__attribute__((visibility("hidden")))
KModErr pending_installations(std::vector<std::string>& ids);
__attribute__((visibility("hidden")))
KModErr installation_list_paths(const char* id, std::string& image, std::string& state,
                               std::string& description, bool& hidden);
}  // namespace maplesu::module_install
