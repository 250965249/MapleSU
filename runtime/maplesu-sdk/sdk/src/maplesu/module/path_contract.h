#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace maplesu::module_paths {

static inline bool valid_id(std::string_view id) {
    return !id.empty() && id != "." && id != ".." &&
        id.find('/') == std::string_view::npos &&
        id.find('\0') == std::string_view::npos;
}

static inline bool valid_id(const char* id) {
    return id && valid_id(std::string_view(id));
}

static inline bool relative_components(std::string_view name,
                                      std::vector<std::string>* components = nullptr) {
    if (components) components->clear();
    if (name.empty() || name.front() == '/' ||
        name.find('\0') != std::string_view::npos) return false;
    bool has_component = false;
    for (std::size_t begin = 0; begin < name.size();) {
        const std::size_t slash = name.find('/', begin);
        const std::size_t end = slash == std::string_view::npos ? name.size() : slash;
        const std::string_view component = name.substr(begin, end - begin);
        if (component == "..") return false;
        if (!component.empty() && component != ".") {
            has_component = true;
            if (components) components->emplace_back(component);
        }
        if (slash == std::string_view::npos) break;
        begin = slash + 1;
    }
    return has_component || (!components && name.back() == '/');
}

}  // namespace maplesu::module_paths
