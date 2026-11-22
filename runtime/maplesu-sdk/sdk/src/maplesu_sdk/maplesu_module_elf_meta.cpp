// MapleSU module elf meta implementation.
//
#define module_desc public_packed_module_desc
#define module_record public_packed_module_record
#include "kernel_module_kit_umbrella.h"
#undef module_desc
#undef module_record
#include <cstddef>
namespace maplesu::sdk {
struct module_desc {
    char name[1024] = {}, version[1024] = {}, desc[4096] = {}, author[1024] = {};
    char id32[1024] = {}, update_json[1024] = {};
    bool web_ui = false;
    MapleSUSdkVersion min_sdk_ver = {};
};
struct module_record { module_desc desc; ModuleRunState state = ModuleRunState::NotRunning; };
static_assert(sizeof(module_desc) == 9232 && alignof(module_desc) == 4);
static_assert(offsetof(module_desc, min_sdk_ver) == 9220 && sizeof(module_record) == 9236);
}

#include <cstdio>
#include <filesystem>
extern "C" const char* __get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW();

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace maplesu::sdk {
namespace {

// 名字保持原符号名：它们是 internal constant（nm 类型 r），不参与 T 集比较，
constexpr std::array<char, 65> ___MOD_NAME_TAG_BEGIN_REVERSED{
    "e3bd8f89934f810e3030f470b11ef13300ffeadc12a1de9c7d297eacb366f1ed"};
constexpr std::array<char, 65> ___MOD_NAME_TAG_END_REVERSED{
    "71bf67a805a3a670cee5a2f5b77719ec13657b44d5a7ca7ecc4e2717f3c92440"};
constexpr std::array<char, 65> ___MOD_ID32_TAG_BEGIN_REVERSED{
    "c111289bbfc43216a19bac64abde2f51f679ba6ce9e0e8a970d70c88dddcd33b"};
constexpr std::array<char, 65> ___MOD_ID32_TAG_END_REVERSED{
    "4c2c6ebca96a5acd12d6b754ac0c0f12175e7d27a92dd9462e03a70c6a9d0203"};
constexpr std::array<char, 65> ___MOD_VERSION_TAG_BEGIN_REVERSED{
    "b8134d6ab9c9227c71fa50f6c143e865df483d28a6c54f0dc2f50868b2a47cd7"};
constexpr std::array<char, 65> ___MOD_VERSION_TAG_END_REVERSED{
    "2cfece323efb1314dc05062653f97807d53550faef9bd3a4d8ef15e6a910cbd8"};
constexpr std::array<char, 65> ___MOD_DESC_TAG_BEGIN_REVERSED{
    "668d60ff73fe091531de7699b6c7f823837645df79d49c277e118c644dc26c50"};
constexpr std::array<char, 65> ___MOD_DESC_TAG_END_REVERSED{
    "3a1e34f632f8dee872240ab493b1592b29369f4554f2f6d00166c190e59c20de"};
constexpr std::array<char, 65> ___MOD_AUTHOR_TAG_BEGIN_REVERSED{
    "154496867398db4cff2ba8fe435ac338faf0d971f59cef4e6bf2a192022b93f1"};
constexpr std::array<char, 65> ___MOD_AUTHOR_TAG_END_REVERSED{
    "c1f36ec3017cffe391c45140e3642e09dcce91df621b1c496ddec6df688c904d"};
constexpr std::array<char, 65> ___MOD_UPDATE_JSON_TAG_BEGIN_REVERSED{
    "145da9a64df4a7d07486b99691f9ad62615afb9f121cdabac39d93f8636a3634"};
constexpr std::array<char, 65> ___MOD_UPDATE_JSON_TAG_END_REVERSED{
    "cbe0d8d0611f822b7a0a33726998eb065f57958dce1c4ce436331e7b4cdfe2f9"};
constexpr std::array<char, 33> ___MOD_WEB_UI_FLAG_BEGIN_REVERSED{
    "62ed142d7f934306db7cfa3e64257fa8"};
constexpr std::array<char, 33> ___MOD_WEB_UI_FLAG_END_REVERSED{
    "cb61bdb0ec6299dabbbd82edf7c56d8f"};
constexpr std::array<char, 65> ____MAPLESU_MODULE_MIN_SUPPORT_SDK_VERSION_TAG_BEGIN_REVERSED{
    "c625dddd86e78539e8222b88bcc5dd85ff1f6742db1e1e89f39a9bafcc8e0b2d"};
constexpr std::array<char, 65> ____MAPLESU_MODULE_MIN_SUPPORT_SDK_VERSION_TAG_END_REVERSED{
    "b4f508ed2f683ef8e079b8006b561704659649d2db7d78005671b1d06614c261"};
constexpr std::array<char, 33> ___MOD_ON_INSTALL_FLAG_BEGIN_REVERSED{
    "ddvq0azt6cox7dljnd1mjr0r5pnrh5az"};
constexpr std::array<char, 33> ___MOD_ON_INSTALL_FLAG_END_REVERSED{
    "pe7vr3l42atuefi5ry7ceqplp5wltl2v"};
constexpr std::array<char, 33> ___MOD_ON_UNINSTALL_FLAG_BEGIN_REVERSED{
    "dccpa03vrd5jyknav3ffofqcdnrl0tfh"};
constexpr std::array<char, 33> ___MOD_ON_UNINSTALL_FLAG_END_REVERSED{
    "khqyu0lf6ca2pzt38lr0a5gonir4vt6p"};

}  // namespace

template <std::size_t N>
static std::string runtime_reverse_to_string(const std::array<char, N>& tag) {
    std::string out(tag.data());  // 到 NUL 为止：数组尾部是 '\0'，反转即还原原 tag
    std::reverse(out.begin(), out.end());
    return out;
}

static std::optional<std::string> find_tagged_value(const std::vector<uint8_t>& bytes,
                                                    std::string_view begin_tag,
                                                    std::string_view end_tag,
                                                    std::size_t max_len) {
    (void)max_len;
    if (bytes.empty() || begin_tag.empty() || end_tag.empty()) {
        return std::nullopt;
    }
    auto begin = std::search(bytes.begin(), bytes.end(), begin_tag.begin(), begin_tag.end());
    if (begin == bytes.end()) {
        return std::nullopt;
    }
    const auto value_begin = begin + begin_tag.size();
    auto end = std::search(value_begin, bytes.end(), end_tag.begin(), end_tag.end());
    if (end == bytes.end()) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(&*value_begin),
                       static_cast<std::size_t>(end - value_begin));
}

template <std::size_t N, std::size_t M>
static std::optional<std::string> find_tagged_value_reversed_tag(
    const std::vector<uint8_t>& bytes, const std::array<char, N>& begin_tag,
    const std::array<char, M>& end_tag, std::size_t max_len = 1024) {
    const std::string begin = runtime_reverse_to_string(begin_tag);
    const std::string end = runtime_reverse_to_string(end_tag);
    return find_tagged_value(bytes, begin, end, max_len);
}

// 把描述符数组按 module_desc 的原始字节整块序列化。
std::vector<uint8_t> serialize_module_descs(const std::vector<module_desc>& descs) {
    std::vector<uint8_t> out(descs.size() * sizeof(module_desc));
    if (!descs.empty()) {
        std::memcpy(out.data(), descs.data(), out.size());
    }
    return out;
}

std::vector<module_desc> deserialize_module_descs(const std::vector<uint8_t>& bytes) {
    if (bytes.size() % sizeof(module_desc) != 0) {
        return {};
    }
    const std::size_t count = bytes.size() / sizeof(module_desc);
    std::vector<module_desc> descs(count);
    if (bytes.size() >= sizeof(module_desc)) {
        std::memcpy(descs.data(), bytes.data(), count * sizeof(module_desc));
    }
    return descs;
}

// existing destination bytes when their tag is absent; required fields are then
KModErr parse_module_meta_from_elf_bytes(const std::vector<uint8_t>& elf_bytes,
                                       module_desc& out_desc) {
    if (auto v = find_tagged_value_reversed_tag(elf_bytes, ___MOD_NAME_TAG_BEGIN_REVERSED,
                                               ___MOD_NAME_TAG_END_REVERSED))
        strncpy(out_desc.name, v->c_str(), sizeof(out_desc.name) - 1);
    if (strlen(out_desc.name) == 0) return KModErr::ERR_MODULE_PARSE_NAME;
    if (auto v = find_tagged_value_reversed_tag(elf_bytes, ___MOD_ID32_TAG_BEGIN_REVERSED,
                                               ___MOD_ID32_TAG_END_REVERSED))
        strncpy(out_desc.id32, v->c_str(), sizeof(out_desc.id32) - 1);
    if (strlen(out_desc.id32) == 0) return KModErr::ERR_MODULE_PARSE_ID32;
    if (auto v = find_tagged_value_reversed_tag(elf_bytes, ___MOD_VERSION_TAG_BEGIN_REVERSED,
                                               ___MOD_VERSION_TAG_END_REVERSED))
        strncpy(out_desc.version, v->c_str(), sizeof(out_desc.version) - 1);
    if (strlen(out_desc.version) == 0) return KModErr::ERR_MODULE_PARSE_VERSION;
    if (auto v = find_tagged_value_reversed_tag(elf_bytes, ___MOD_DESC_TAG_BEGIN_REVERSED,
                                               ___MOD_DESC_TAG_END_REVERSED))
        strncpy(out_desc.desc, v->c_str(), sizeof(out_desc.desc) - 1);
    if (auto v = find_tagged_value_reversed_tag(elf_bytes, ___MOD_AUTHOR_TAG_BEGIN_REVERSED,
                                               ___MOD_AUTHOR_TAG_END_REVERSED))
        strncpy(out_desc.author, v->c_str(), sizeof(out_desc.author) - 1);
    if (auto v = find_tagged_value_reversed_tag(elf_bytes, ___MOD_UPDATE_JSON_TAG_BEGIN_REVERSED,
                                               ___MOD_UPDATE_JSON_TAG_END_REVERSED))
        strncpy(out_desc.update_json, v->c_str(), sizeof(out_desc.update_json) - 1);
    out_desc.web_ui = find_tagged_value_reversed_tag(elf_bytes, ___MOD_WEB_UI_FLAG_BEGIN_REVERSED,
                                                    ___MOD_WEB_UI_FLAG_END_REVERSED).has_value();
    if (!out_desc.web_ui) {
        std::string webroot;
        if (strlen(out_desc.id32) != 0) {
            std::string head = std::string(__get_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW()).substr(0, 16);
            std::string dirname = head + head[0];
            char path[1024] = {};
            snprintf(path, sizeof(path), "/data/%s/", dirname.c_str());
            std::string modules = (std::filesystem::path(std::string(path)) / "modules" / "").string();
            std::string private_dir = (std::filesystem::path(modules) / out_desc.id32 / "").string();
            webroot = (std::filesystem::path(private_dir) / "webroot").string();
        }
        std::error_code ec;
        out_desc.web_ui = std::filesystem::exists(std::filesystem::path(webroot), ec);
    }
    char min_sdk[128] = {};
    if (auto v = find_tagged_value_reversed_tag(elf_bytes,
            ____MAPLESU_MODULE_MIN_SUPPORT_SDK_VERSION_TAG_BEGIN_REVERSED,
            ____MAPLESU_MODULE_MIN_SUPPORT_SDK_VERSION_TAG_END_REVERSED))
        strncpy(min_sdk, v->c_str(), sizeof(min_sdk) - 1);
    if (strlen(min_sdk) == 0) return KModErr::ERR_MODULE_PARSE_MIN_SDK;
    sscanf(min_sdk, "%u.%u.%u", &out_desc.min_sdk_ver.major,
           &out_desc.min_sdk_ver.minor, &out_desc.min_sdk_ver.patch);
    return KModErr::OK;
}

bool module_has_install_callback(const std::vector<uint8_t>& elf_bytes) {
    return find_tagged_value_reversed_tag(elf_bytes, ___MOD_ON_INSTALL_FLAG_BEGIN_REVERSED,
                                          ___MOD_ON_INSTALL_FLAG_END_REVERSED)
        .has_value();
}

bool module_has_uninstall_callback(const std::vector<uint8_t>& elf_bytes) {
    return find_tagged_value_reversed_tag(elf_bytes, ___MOD_ON_UNINSTALL_FLAG_BEGIN_REVERSED,
                                          ___MOD_ON_UNINSTALL_FLAG_END_REVERSED)
        .has_value();
}

}  // namespace maplesu::sdk
