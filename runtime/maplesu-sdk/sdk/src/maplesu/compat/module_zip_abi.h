#pragma once
// Frozen module ABI and existing process boundaries used by archive parsing.
#include "module_metadata_abi.h"
#include "fork_legacy_abi.h"
#include "../../maplesu_core/fixed_transfer_io.h"
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <vector>

namespace default_modules::module_root {
KModErr set_current_root(bool enabled);
}

namespace maplesu::sdk {
KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>&, module_desc&);
std::vector<uint8_t> serialize_module_descs(const std::vector<module_desc>&);
std::vector<module_desc> deserialize_module_descs(const std::vector<uint8_t>&);

__attribute__((visibility("hidden")))
KModErr find_module_elf_in_zip(const char*, module_desc&, std::string&);
__attribute__((visibility("hidden")))
KModErr safe_parse_module_desc_from_zip_file(const char*, module_desc&);
}

namespace maplesu::compat {
using default_modules::module_root::set_current_root;
using maplesu::sdk::FixedTransferRead;
using maplesu::sdk::FixedTransferStatus;
using maplesu::sdk::fork_pipe_info;
using maplesu::sdk::fork_pipe_child_process;
using maplesu::sdk::parse_module_meta_from_elf_bytes;
using maplesu::sdk::read_errcode_from_child;
using maplesu::sdk::read_fixed_transfer_data_from_child;
using maplesu::sdk::serialize_module_descs;
using maplesu::sdk::write_errcode_from_child;
using maplesu::sdk::write_transfer_data_from_child;
}
