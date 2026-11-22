#include "kernel_module_kit_umbrella.h"
#include "fixture_config.h"
#include "../../../src/maplesu/compat/module_list_legacy_abi.h"
#include "../../../src/maplesu/compat/module_carrier_conversion.h"
#include "../../../src/maplesu/module/operations.h"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
namespace kernel_module { void set_current_module_description_with_str(const char*); }
extern "C" const char* __get_current_module_id32_1b0494ae8a788541db46b82cc1f0577c() {
    return "fixture_mod";
}
namespace maplesu::sdk {
KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>& bytes, module_desc& desc) {
    if (std::string(bytes.begin(), bytes.end()) != "fixture:fixture_mod")
        return KModErr::ERR_MODULE_PARSE_ID32;
    strcpy(desc.name, "NAME_GUARD");
    strcpy(desc.version, "VERSION_GUARD");
    strcpy(desc.desc, "original description");
    strcpy(desc.author, "AUTHOR_GUARD");
    strcpy(desc.id32, "fixture_mod");
    strcpy(desc.update_json, "UPDATE_GUARD");
    desc.web_ui = true;
    desc.min_sdk_ver = {11, 22, 33};
    return KModErr::OK;
}
}
namespace maplesu::module {
KModErr parse_metadata(const std::vector<uint8_t>& bytes, Descriptor& desc) {
    maplesu::sdk::module_desc parsed;
    const KModErr error = maplesu::sdk::parse_module_meta_from_elf_bytes(bytes, parsed);
    if (is_ok(error)) maplesu::compat::copy_module_descriptor(desc, parsed);
    return error;
}
}
static void put(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out.write(text.data(), text.size());
    out.close();
    if (!out.good()) std::exit(2);
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const std::string mode = argv[1];
    const size_t length = std::stoull(argv[2]);
    std::string text(length, 'D');
    const std::string head = fixture::key.substr(0, 16);
    const fs::path root = "/data/" + head + head[0];
    fs::remove_all(root);
    fs::create_directories(root / "modules_new_desc");
    put(root / "modules/fixture_mod/fixture_mod", "fixture:fixture_mod");
    const fs::path path = root / "modules_new_desc/fixture_mod";
    kernel_module::set_current_module_description_with_str(mode == "null" ? nullptr : text.c_str());
    if (mode == "nul-file") {
        text.at(31) = '\0';
        put(path, text); // The reader accepts persisted files, including embedded NUL bytes.
    } else if (mode == "null") {
        text.clear();
    }
    std::ifstream saved(path, std::ios::binary);
    const std::string persisted((std::istreambuf_iterator<char>(saved)), {});
    const bool writer = persisted == text && fixture::label_calls == 1 && fixture::label_contract_ok;
    std::cout << "{\"phase\":\"writer\",\"mode\":\"" << mode << "\",\"inputBytes\":" << length
              << ",\"fileBytes\":" << persisted.size() << ",\"unchanged\":" << (writer ? "true" : "false")
              << "}" << std::endl;
    std::vector<maplesu::sdk::module_record> records;
    const auto error = maplesu::sdk::unsafe_get_all_modules(records);
    if (error != KModErr::OK || records.size() != 1) return 3;
    const auto& value = records[0];
    maplesu::sdk::module_desc metadata{};
    const std::string elf = "fixture:fixture_mod";
    maplesu::sdk::parse_module_meta_from_elf_bytes({elf.begin(), elf.end()}, metadata);
    constexpr size_t capacity = sizeof(value.desc.desc);
    const size_t nul = text.find('\0');
    const size_t expected_length = text.empty() ? strlen(metadata.desc)
        : std::min(capacity - 1, nul == std::string::npos ? text.size() : nul);
    const char* expected = text.empty() ? metadata.desc : text.data();
    const auto* end = static_cast<const char*>(memchr(value.desc.desc, 0, capacity));
    const bool description = end && static_cast<size_t>(end - value.desc.desc) == expected_length
        && !memcmp(value.desc.desc, expected, expected_length)
        && std::all_of(value.desc.desc + expected_length, value.desc.desc + capacity,
                       [](char c) { return c == 0; });
    constexpr size_t start = offsetof(maplesu::sdk::module_desc, desc);
    constexpr size_t after = start + capacity;
    const bool guards = !memcmp(&value.desc, &metadata, start)
        && !memcmp(reinterpret_cast<const char*>(&value.desc) + after,
                   reinterpret_cast<const char*>(&metadata) + after, sizeof(metadata) - after);
    const bool state = value.state == maplesu::sdk::ModuleRunState::NotRunning;
    std::cout << "{\"phase\":\"reader\",\"mode\":\"" << mode << "\",\"inputBytes\":" << length
              << ",\"descCapacity\":" << capacity << ",\"expectedLength\":" << expected_length
              << ",\"nulWithinCapacity\":" << (end ? "true" : "false")
              << ",\"descriptionCorrect\":" << (description ? "true" : "false")
              << ",\"metadataGuardsIntact\":" << (guards ? "true" : "false")
              << ",\"stateIntact\":" << (state ? "true" : "false") << "}" << std::endl;
    return writer && description && guards && state ? 0 : 10;
}
