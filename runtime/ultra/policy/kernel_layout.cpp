#include "kernel_layout.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <unordered_map>

namespace maplesu::module_policy {
namespace {
[[noreturn]] void fail(const std::string& reason) {
    throw std::runtime_error("MODULE_POLICY_LAYOUT_" + reason);
}
class Btf {
    struct Type { uint32_t name, kind, count, value; bool bits; size_t extra; };
    const std::vector<uint8_t>& bytes_;
    size_t strings_, string_size_;
    std::vector<Type> types_{{}};
    std::unordered_map<std::string, std::vector<uint32_t>> structs_;
    std::unordered_map<std::string, std::vector<uint32_t>> functions_;
    uint32_t u32(size_t offset) const {
        if (offset > bytes_.size() || bytes_.size() - offset < 4) fail("TRUNCATED");
        return uint32_t(bytes_[offset]) | uint32_t(bytes_[offset+1]) << 8 |
               uint32_t(bytes_[offset+2]) << 16 | uint32_t(bytes_[offset+3]) << 24;
    }
    std::string name(uint32_t offset) const {
        if (offset >= string_size_) fail("STRING");
        const char* first = reinterpret_cast<const char*>(bytes_.data() + strings_ + offset);
        auto end = static_cast<const char*>(memchr(first, 0, string_size_ - offset));
        if (!end) fail("STRING");
        return std::string(first, end);
    }
    const Type& type(uint32_t id) const {
        if (!id || id >= types_.size()) fail("TYPE_ID");
        return types_[id];
    }
    uint32_t resolved(uint32_t id) const {
        for (unsigned i = 0; i < 64; ++i) {
            if (!id) return 0;
            const auto& t = type(id);
            if (t.kind != 8 && t.kind != 9 && t.kind != 10 && t.kind != 11 && t.kind != 18)
                return id;
            id = t.value;
        }
        fail("TYPE_CYCLE");
    }
    std::string signature(uint32_t id, unsigned depth = 0, bool pointer = false) const {
        if (!id) return "v";
        if (depth >= 32) fail("ABI_CYCLE");
        id = resolved(id);
        if (!id) return "v";
        const auto& t = type(id);
        auto nested = [&](uint32_t next, bool indirect = false) {
            return signature(next, depth + 1, indirect);
        };
        switch (t.kind) {
            case 1: return "i" + std::to_string(t.value) + ":" + std::to_string(u32(t.extra));
            case 2: return "*" + nested(t.value, true);
            case 3: return "a" + std::to_string(u32(t.extra + 8)) + ":" + nested(u32(t.extra));
            case 4: case 5: {
                auto result = std::string(t.kind == 4 ? "s" : "u") + name(t.name);
                if (pointer && t.name) return result;
                result += ":" + std::to_string(t.value) + "{";
                for (uint32_t i = 0; i < t.count; ++i) {
                    auto at = t.extra + size_t(i) * 12;
                    result += std::to_string(u32(at + 8)) + "=" + nested(u32(at + 4)) + ";";
                    if (result.size() > 65536) fail("ABI_SIZE");
                }
                return result + "}";
            }
            case 6: case 19: {
                auto result = "e" + std::to_string(t.value) + (t.bits ? "s{" : "u{");
                for (uint32_t i = 0; i < t.count; ++i) {
                    auto at = t.extra + size_t(i) * (t.kind == 6 ? 8 : 12);
                    uint64_t value = u32(at + 4);
                    if (t.kind == 19) value |= uint64_t(u32(at + 8)) << 32;
                    result += name(u32(at)) + "=" + std::to_string(value) + ";";
                    if (result.size() > 65536) fail("ABI_SIZE");
                }
                return result + "}";
            }
            case 7: return std::string(t.bits ? "u" : "s") + name(t.name);
            case 12: return nested(t.value);
            case 13: {
                auto result = "f" + nested(t.value) + "(";
                for (uint32_t i = 0; i < t.count; ++i) {
                    result += nested(u32(t.extra + size_t(i) * 8 + 4)) + ";";
                    if (result.size() > 65536) fail("ABI_SIZE");
                }
                return result + ")";
            }
            default: fail("ABI_TYPE");
        }
    }
    uint32_t size(uint32_t id, unsigned depth = 0) const {
        if (depth >= 32) fail("TYPE_CYCLE");
        const auto& t = type(resolved(id));
        if (t.kind == 2) return 8;
        if (t.kind == 1 || t.kind == 4 || t.kind == 5 || t.kind == 6 || t.kind == 16 || t.kind == 19)
            return t.value;
        if (t.kind == 3) {
            auto element = size(u32(t.extra), depth + 1);
            auto count = u32(t.extra + 8);
            if (count && element > std::numeric_limits<uint32_t>::max() / count) fail("ARRAY_SIZE");
            return element * count;
        }
        fail("FIELD_TYPE");
    }
    bool field(uint32_t id, const std::string& wanted, uint32_t prefix,
               LayoutField& result, unsigned depth = 0, std::string* abi = nullptr,
               uint32_t* member_id = nullptr) const {
        if (depth >= 16) fail("MEMBER_CYCLE");
        const auto dot = wanted.find('.');
        if (dot != std::string::npos) {
            if (!dot || dot + 1 == wanted.size()) fail("MEMBER_PATH");
            LayoutField parent;
            uint32_t parent_id = 0;
            if (!field(id, wanted.substr(0, dot), prefix, parent, depth, nullptr, &parent_id)) return false;
            if ((parent.bit_offset & 7) || parent.bit_size != uint64_t(size(parent_id)) * 8)
                fail("MEMBER_TYPE");
            if (!field(parent_id, wanted.substr(dot + 1), parent.bit_offset, result, depth + 1, abi, member_id))
                return false;
            result.name = wanted;
            return true;
        }
        const auto& t = type(resolved(id));
        if (t.kind != 4 && t.kind != 5) fail("MEMBER_TYPE");
        bool found = false;
        auto select = [&](LayoutField value, uint32_t type_id, const std::string& signature) {
            if (found) fail("MEMBER_AMBIGUOUS:" + wanted);
            found = true;
            result = std::move(value);
            if (member_id) *member_id = type_id;
            if (abi) *abi = signature;
        };
        for (uint32_t i = 0; i < t.count; ++i) {
            auto at = t.extra + size_t(i) * 12;
            auto member_name = name(u32(at));
            auto member_type = u32(at + 4);
            auto offset = u32(at + 8);
            auto width = t.bits ? offset >> 24 : 0;
            offset = t.bits ? offset & 0xffffff : offset;
            if (offset > std::numeric_limits<uint32_t>::max() - prefix) fail("MEMBER_OFFSET");
            if (member_name.empty()) {
                auto kind = type(resolved(member_type)).kind;
                LayoutField nested;
                std::string nested_abi;
                uint32_t nested_id = 0;
                if ((kind == 4 || kind == 5) && field(member_type, wanted, prefix + offset,
                    nested, depth + 1, abi ? &nested_abi : nullptr, &nested_id)) {
                    if (uint64_t(offset) + uint64_t(size(member_type)) * 8 > uint64_t(t.value) * 8)
                        fail("MEMBER_BOUNDS");
                    select(std::move(nested), nested_id, nested_abi);
                }
            } else if (member_name == wanted) {
                auto member_size = size(member_type);
                if (member_size > std::numeric_limits<uint32_t>::max() / 8) fail("MEMBER_SIZE");
                auto member_bits = width ? width : member_size * 8;
                const auto& value_type = type(resolved(member_type));
                if (value_type.kind == 1) {
                    const auto encoding = u32(value_type.extra);
                    const auto int_bits = encoding & 0xff, int_offset = (encoding >> 16) & 0xff;
                    if (!int_bits || int_bits + int_offset > 128 ||
                        int_bits + int_offset > member_size * 8) fail("MEMBER_INT");
                    if (t.bits) {
                        if (int_offset || int_bits < 8 || (int_bits & (int_bits - 1))) fail("MEMBER_INT");
                        if (width > int_bits) fail("MEMBER_BITS");
                        member_bits = width ? width : int_bits;
                    } else {
                        if (int_offset > std::numeric_limits<uint32_t>::max() - prefix - offset)
                            fail("MEMBER_OFFSET");
                        offset += int_offset;
                        member_bits = int_bits;
                    }
                } else if (width && ((value_type.kind != 6 && value_type.kind != 19) || width > member_size * 8))
                    fail("MEMBER_BITS");
                if (uint64_t(offset) + member_bits > uint64_t(t.value) * 8) fail("MEMBER_BOUNDS");
                select({wanted, prefix + offset, member_bits}, member_type,
                       abi ? signature(member_type) : std::string{});
            }
        }
        return found;
    }
    LayoutType describe_type(uint32_t id, const std::string& name,
                             const std::vector<std::string>& fields,
                             std::vector<KernelFunctionAbi>* field_abis = nullptr) const {
        LayoutType actual{name, size(id), {}};
        if (!actual.size) fail("EMPTY_TYPE:" + name);
        for (const auto& member : fields) {
            LayoutField value;
            std::string abi;
            if (!field(id, member, 0, value, 0, field_abis ? &abi : nullptr)) fail("MEMBER:" + name + "." + member);
            if (uint64_t(value.bit_offset) + value.bit_size > uint64_t(actual.size) * 8)
                fail("MEMBER_BOUNDS:" + name + "." + member);
            actual.fields.push_back(std::move(value));
            if (field_abis) field_abis->push_back({name + "." + member, std::move(abi)});
        }
        return actual;
    }
    void merge_description(LayoutType& selected, LayoutType actual) const {
        if (!selected.size) { selected = std::move(actual); return; }
        if (selected.size != actual.size) fail("AMBIGUOUS:" + actual.name);
        for (size_t i = 0; i < actual.fields.size(); ++i)
            if (selected.fields[i].bit_offset != actual.fields[i].bit_offset ||
                selected.fields[i].bit_size != actual.fields[i].bit_size)
                fail("AMBIGUOUS:" + actual.name + "." + actual.fields[i].name);
    }
public:
    explicit Btf(const std::vector<uint8_t>& bytes) : bytes_(bytes) {
        if (bytes.size() < 24 || bytes.size() > 64 * 1024 * 1024 ||
            bytes[0] != 0x9f || bytes[1] != 0xeb || bytes[2] != 1 || bytes[3]) fail("HEADER");
        auto header = u32(4), type_offset = u32(8), type_size = u32(12);
        auto string_offset = u32(16), string_size = u32(20);
        if (header < 24 || header > bytes.size() || type_offset > bytes.size() - header ||
            type_size > bytes.size() - header - type_offset || string_offset > bytes.size() - header ||
            string_size > bytes.size() - header - string_offset || !string_size) fail("BOUNDS");
        size_t at = size_t(header) + type_offset, end = at + type_size;
        strings_ = size_t(header) + string_offset;
        string_size_ = string_size;
        if (!(end <= strings_ || strings_ + string_size_ <= at) || bytes_[strings_]) fail("SECTIONS");
        while (at < end) {
            if (end - at < 12) fail("TYPE_RECORD");
            auto info = u32(at + 4);
            Type t{u32(at), (info >> 24) & 0x1f, info & 0xffff, u32(at + 8), bool(info >> 31), at + 12};
            size_t extra;
            switch (t.kind) {
                case 1: case 14: case 17: extra = 4; break;
                case 3: extra = 12; break;
                case 4: case 5: case 15: case 19: extra = size_t(t.count) * 12; break;
                case 6: case 13: extra = size_t(t.count) * 8; break;
                case 2: case 7: case 8: case 9: case 10: case 11: case 12: case 16: case 18:
                    extra = 0; break;
                default: fail("KIND");
            }
            if (extra > end - t.extra) fail("TYPE_RECORD");
            auto type_name = name(t.name);
            if (t.kind == 4 && !type_name.empty()) {
                structs_[type_name].push_back(static_cast<uint32_t>(types_.size()));
            }
            if (t.kind == 12 && !type_name.empty())
                functions_[type_name].push_back(static_cast<uint32_t>(types_.size()));
            types_.push_back(t);
            at = t.extra + extra;
        }
    }
    KernelLayoutDescription describe(const std::vector<LayoutTypeRequest>& required,
                                     const std::vector<std::string>& functions) const {
        if (required.empty() && functions.empty()) fail("EMPTY_CONTRACT");
        KernelLayoutDescription result;
        for (const auto& item : required) {
            auto found = structs_.find(item.name);
            if (found == structs_.end()) fail("MISSING:" + item.name);
            LayoutType selected{item.name, 0, {}};
            for (auto type_id : found->second)
                merge_description(selected, describe_type(type_id, item.name, item.fields));
            result.types.push_back(std::move(selected));
        }
        for (const auto& function : functions) {
            auto found = functions_.find(function);
            if (found == functions_.end()) fail("ABI_MISSING:" + function);
            std::string selected;
            for (auto id : found->second) {
                auto actual = signature(id);
                if (!selected.empty() && selected != actual) fail("ABI_AMBIGUOUS:" + function);
                selected = std::move(actual);
            }
            result.functions.push_back({function, std::move(selected)});
        }
        return result;
    }
    KernelLayoutDescription task_credentials(const std::vector<std::string>& task_fields,
                                             const std::vector<std::string>& credential_fields,
                                             std::vector<KernelFunctionAbi>* field_abis = nullptr) const {
        const auto found = structs_.find("task_struct");
        if (found == structs_.end()) fail("MISSING:task_struct");
        LayoutType task{"task_struct", 0, {}}, cred{"cred", 0, {}};
        std::vector<KernelFunctionAbi> selected_abis;
        for (auto id : found->second) {
            if (!type(id).value || !type(id).count) continue;
            LayoutField pointer;
            uint32_t pointer_id = 0;
            if (!field(id, "cred", 0, pointer, 0, nullptr, &pointer_id)) fail("MEMBER:task_struct.cred");
            const auto& indirect = type(resolved(pointer_id));
            if (pointer.bit_size != 64 || pointer.bit_offset % 64 || indirect.kind != 2 || !indirect.value)
                fail("CRED_POINTER");
            const auto cred_id = resolved(indirect.value);
            const auto& pointee = type(cred_id);
            if (pointee.kind != 4 || name(pointee.name) != "cred" || !pointee.value)
                fail("CRED_POINTER");
            std::vector<KernelFunctionAbi> actual_abis;
            auto* abis = field_abis ? &actual_abis : nullptr;
            merge_description(task, describe_type(id, "task_struct", task_fields, abis));
            merge_description(cred, describe_type(cred_id, "cred", credential_fields, abis));
            if (field_abis) {
                if (selected_abis.empty()) selected_abis = std::move(actual_abis);
                else for (size_t i = 0; i < actual_abis.size(); ++i)
                    if (selected_abis[i].signature != actual_abis[i].signature)
                        fail("ABI_AMBIGUOUS:" + actual_abis[i].name);
            }
        }
        if (!task.size) fail("EMPTY_TYPE:task_struct");
        if (field_abis) *field_abis = std::move(selected_abis);
        return {{std::move(task), std::move(cred)}, {}};
    }
    std::vector<KernelFunctionAbi> fields(const std::vector<LayoutTypeRequest>& required) const {
        std::vector<KernelFunctionAbi> result;
        for (const auto& owner : required) {
            auto found = structs_.find(owner.name);
            if (found == structs_.end()) fail("MISSING:" + owner.name);
            for (const auto& member : owner.fields) {
                std::string selected;
                for (auto id : found->second) {
                    LayoutField value;
                    std::string actual;
                    if (!field(id, member, 0, value, 0, &actual)) fail("MEMBER:" + owner.name + "." + member);
                    if (!selected.empty() && selected != actual) fail("ABI_AMBIGUOUS:" + owner.name + "." + member);
                    selected = std::move(actual);
                }
                result.push_back({owner.name + "." + member, std::move(selected)});
            }
        }
        return result;
    }
    std::vector<LayoutType> resolve(const std::vector<LayoutType>& required,
        const std::vector<KernelFieldRelocation>& relocations,
        const std::vector<std::string>& resized, const std::vector<KernelFunctionAbi>& functions) const {
        if (required.empty()) fail("EMPTY_CONTRACT");
        for (const auto& name : resized)
            if (std::none_of(required.begin(), required.end(), [&](const auto& t) { return t.name == name && t.size; }))
                fail("RESIZE_CONTRACT:" + name);
        for (const auto& field : relocations) {
            auto owner = std::find_if(required.begin(), required.end(), [&](const auto& t) { return t.name == field.type; });
            if (owner == required.end() || std::none_of(owner->fields.begin(), owner->fields.end(),
                [&](const auto& f) { return f.name == field.member; })) fail("RELOCATION_CONTRACT:" + field.type + "." + field.member);
        }
        std::vector<LayoutType> result;
        for (const auto& item : required) {
            auto found = structs_.find(item.name);
            if (found == structs_.end()) fail("MISSING:" + item.name);
            const bool resize = std::find(resized.begin(), resized.end(), item.name) != resized.end();
            LayoutType selected{item.name, 0, {}};
            for (auto type_id : found->second) {
                const auto actual_size = size(type_id);
                if (item.size && !resize && actual_size != item.size) fail("SIZE:" + item.name);
                if (!actual_size || actual_size > 16 * 1024 * 1024) fail("OBJECT_SIZE:" + item.name);
                if (item.fields.empty() && !item.size) fail("EMPTY_TYPE:" + item.name);
                if (selected.size && selected.size != actual_size) fail("AMBIGUOUS:" + item.name);
                std::vector<LayoutField> fields;
                for (const auto& member : item.fields) {
                    LayoutField actual;
                    if (!field(type_id, member.name, 0, actual)) fail("MEMBER:" + item.name + "." + member.name);
                    const auto end = uint64_t(actual.bit_offset) + actual.bit_size;
                    if (end > uint64_t(actual_size) * 8) fail("MEMBER_BOUNDS:" + item.name + "." + member.name);
                    auto relocated = std::find_if(relocations.begin(), relocations.end(), [&](const auto& f) {
                        return f.type == item.name && f.member == member.name;
                    });
                    if (relocated == relocations.end()) {
                        if (actual.bit_offset != member.bit_offset || actual.bit_size != member.bit_size)
                            fail("OFFSET:" + item.name + "." + member.name);
                    } else if (relocated->bitfield) {
                        if (!actual.bit_size || actual.bit_size > 32) fail("RELOCATION_BIT_WIDTH:" + item.name + "." + member.name);
                    } else {
                        if ((actual.bit_offset & 7) || !actual.bit_size || (actual.bit_size & 7))
                            fail("RELOCATION_BITFIELD:" + item.name + "." + member.name);
                        if (!relocated->embedded && actual.bit_size != member.bit_size)
                            fail("RELOCATION_WIDTH:" + item.name + "." + member.name);
                        const auto alignment = relocated->alignment_bits ? relocated->alignment_bits :
                            (relocated->embedded ? 8U : std::min(64U, member.bit_size));
                        if (alignment && actual.bit_offset % alignment)
                            fail("RELOCATION_ALIGNMENT:" + item.name + "." + member.name);
                    }
                    if (selected.size) {
                        const auto& previous = selected.fields[fields.size()];
                        if (previous.bit_offset != actual.bit_offset || previous.bit_size != actual.bit_size)
                            fail("AMBIGUOUS:" + item.name + "." + member.name);
                    }
                    fields.push_back(actual);
                }
                selected.size = actual_size;
                selected.fields = std::move(fields);
            }
            result.push_back(std::move(selected));
        }
        for (const auto& function : functions) {
            auto found = functions_.find(function.name);
            if (function.signature.empty() || found == functions_.end()) fail("ABI_MISSING:" + function.name);
            for (auto id : found->second)
                if (signature(id) != function.signature) fail("ABI_MISMATCH:" + function.name);
        }
        return result;
    }
};
}
KernelLayoutDescription describe_kernel_layout(const std::vector<uint8_t>& btf,
    const std::vector<LayoutTypeRequest>& required, const std::vector<std::string>& functions) {
    return Btf(btf).describe(required, functions);
}
KernelLayoutDescription describe_task_credential_layout(const std::vector<uint8_t>& btf,
    const std::vector<std::string>& task_fields, const std::vector<std::string>& credential_fields) {
    return Btf(btf).task_credentials(task_fields, credential_fields);
}
KernelLayoutDescription describe_task_credential_layout(const std::vector<uint8_t>& btf,
    const std::vector<std::string>& task_fields, const std::vector<std::string>& credential_fields,
    std::vector<KernelFunctionAbi>& field_abis) {
    return Btf(btf).task_credentials(task_fields, credential_fields, &field_abis);
}
std::vector<KernelFunctionAbi> describe_kernel_fields(const std::vector<uint8_t>& btf,
    const std::vector<LayoutTypeRequest>& required) {
    return Btf(btf).fields(required);
}
void verify_kernel_layout(const std::vector<uint8_t>& btf, const std::vector<LayoutType>& required,
                          const std::vector<KernelFunctionAbi>& functions) {
    Btf(btf).resolve(required, {}, {}, functions);
}
std::vector<LayoutType> resolve_kernel_layout(const std::vector<uint8_t>& btf,
    const std::vector<LayoutType>& required, const std::vector<KernelFieldRelocation>& relocated_fields,
    const std::vector<std::string>& resized_types, const std::vector<KernelFunctionAbi>& functions) {
    return Btf(btf).resolve(required, relocated_fields, resized_types, functions);
}

}
