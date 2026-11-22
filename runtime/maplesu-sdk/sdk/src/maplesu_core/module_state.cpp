#include "module_state_private.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>
#include <sys/stat.h>
#include <sys/xattr.h>

extern "C" const char*
__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

namespace maplesu::module_state {

std::string path(List state) {
    static constexpr const char* names[] = {
        "running_mods.3cee2062f9eab0e034c55c298c7571b4",
        "abnormal_mods.3cee2062f9eab0e034c55c298c7571b4",
        "removed_pending_reboot_mods.3cee2062f9eab0e034c55c298c7571b4",
        "pending_developer_run_once_mods.3cee2062f9eab0e034c55c298c7571b4",
        "finished_developer_run_once_mods.3cee2062f9eab0e034c55c298c7571b4",
    };
    const auto index = static_cast<uint8_t>(state);
    if (index >= sizeof(names) / sizeof(names[0])) return {};
    const std::string key = __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();
    return (std::filesystem::path("/data/" + key.substr(0, 16) + "/") / names[index]).string();
}

KModErr read(List state, std::vector<std::string>& out) {
    out.clear();
    const std::string file_path = path(state);
    if (file_path.empty()) return KModErr::ERR_MODULE_PARAM;
    std::string text;
    std::error_code error;
    if (std::filesystem::exists(file_path, error)) {
        std::ifstream input(file_path, std::ios::binary);
        if (!input) return KModErr::ERR_MODULE_READ_FILE;
        input.seekg(0, std::ios::end);
        const std::streamoff size = input.tellg();
        if (size < 0) return KModErr::ERR_MODULE_READ_FILE;
        input.seekg(0, std::ios::beg);
        text.resize(static_cast<size_t>(size));
        if (!input.read(text.data(), size)) return KModErr::ERR_MODULE_READ_FILE;
    }
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return KModErr::OK;
}

KModErr save(List state, const std::vector<std::string>& ids) {
    const std::string file_path = path(state);
    if (file_path.empty()) return KModErr::ERR_MODULE_PARAM;
    std::ostringstream text;
    for (const auto& id : ids) if (!id.empty()) text << id << '\n';
    const std::string contents = text.str();
    std::ofstream output(file_path, std::ios::out | std::ios::trunc);
    if (!output.is_open()) return KModErr::ERR_MODULE_WRITE_FILE;
    output << std::string_view(contents.c_str());
    output.close();
    if (!output.good()) return KModErr::ERR_MODULE_WRITE_FILE;
    if (chmod(file_path.c_str(), 0777) != 0) return KModErr::ERR_SET_FILE_SELINUX;
    static constexpr char context[] = "u:object_r:kernel:s0";
    if (setxattr(file_path.c_str(), "security.selinux", context, sizeof(context), 0) != 0)
        return KModErr::ERR_SET_FILE_SELINUX;
    return KModErr::OK;
}

KModErr add(List state, const std::string& id) {
    if (id.empty()) return KModErr::ERR_MODULE_PARAM;
    std::vector<std::string> ids;
    RETURN_IF_ERROR(read(state, ids));
    if (std::find(ids.begin(), ids.end(), id) == ids.end()) ids.push_back(id);
    return save(state, ids);
}

KModErr remove(List state, const std::string& id) {
    if (id.empty()) return KModErr::ERR_MODULE_PARAM;
    std::vector<std::string> ids;
    RETURN_IF_ERROR(read(state, ids));
    const size_t before = ids.size();
    ids.erase(std::remove(ids.begin(), ids.end(), id), ids.end());
    return ids.size() == before ? KModErr::OK : save(state, ids);
}

}  // namespace maplesu::module_state
