#include "../../../src/maplesu/module/operations.h"
#include <cstring>
namespace maplesu::module {
KModErr parse_metadata(const std::vector<uint8_t>& bytes, Descriptor& desc) {
    const std::string marker(bytes.begin(), bytes.end());
    if (!marker.starts_with("fixture:")) return KModErr::ERR_MODULE_PARSE_ID32;
    const std::string id = marker.substr(8);
    if (id.size() >= sizeof(desc.id32)) return KModErr::ERR_MODULE_PARSE_ID32;
    strcpy(desc.id32, id.c_str());
    strcpy(desc.desc, "original description");
    return KModErr::OK;
}
}
