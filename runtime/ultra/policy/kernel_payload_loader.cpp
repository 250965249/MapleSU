#include "kernel_payload_loader.h"
#include "policy_layout_slots.h"
#include <algorithm>
#include <cstring>
#include <elf.h>
#include <stdexcept>

namespace maplesu::module_policy {
namespace {
[[noreturn]] void fail(const char* reason) {
    throw std::runtime_error(std::string("MODULE_POLICY_LOADER_") + reason);
}
constexpr const char* hooks[] = {"sel_write_context", "sel_write_access",
    "selinux_setprocattr", "sel_open_handle_status", "sel_read_handle_status",
    "sel_mmap_handle_status", "sk_filter_trim_cap", "commit_creds", "__skb_try_recv_datagram"};
constexpr const char* handlers[] = {"maplesu_policy_view_context", "maplesu_policy_view_access",
    "maplesu_policy_view_setprocattr", "maplesu_policy_view_status_open",
    "maplesu_policy_view_status_read", "maplesu_policy_view_status_mmap",
    "maplesu_policy_view_filter", "maplesu_policy_view_creds_changed", "maplesu_policy_view_receive"};
uint32_t instruction(const std::array<uint8_t, 16>& code, unsigned at) {
    uint32_t word = 0;
    for (unsigned i = 0; i < 4; ++i) word |= uint32_t(code[at + i]) << (8 * i);
    return word;
}
std::string hex_code(const std::array<uint8_t, 16>& code) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (auto byte : code) { out += digits[byte >> 4]; out += digits[byte & 15]; }
    return out;
}
bool compatible_hook_entry(const std::array<uint8_t, 16>& code, const std::array<uint8_t, 16>& expected,
                           bool dynamic_scs) {
    if (code == expected) return true;
    auto normalized = code;
    if (dynamic_scs) for (unsigned at = 0; at < code.size(); at += 4) {
        // Native dynamic SCS rewrites PACIASP to STR X30,[X18],#8.
        if (instruction(code, at) == 0xf800865e && instruction(expected, at) == 0xd503233f)
            std::copy_n(expected.begin() + at, 4, normalized.begin() + at);
    }
    if (normalized == expected) return true;
    // The SDK trampoline relocates the first live instruction, not the
    // reference image's complete prologue. Later returns/branches and OEM
    // register/frame choices therefore do not imply an entry conflict.
    const auto first = instruction(code, 0);
    if (first == 0xd503233f || first == 0xd503237f || first == 0xd503245f ||
        first == 0xd503201f || first == 0xf800865e) return true;
    // Ordinary integer arithmetic and load/store instructions are independent
    // of the original PC. ADR/ADRP and literal loads need relocation support;
    // direct/register branch entries may already be a detour.
    const auto group = (first >> 25) & 15;
    return ((group == 8 || group == 9) && (first & 0x1f000000U) != 0x10000000U) ||
           ((group & 5) == 4 && (first & 0x3b000000U) != 0x18000000U) ||
           group == 5 || group == 13;
}
bool matches_config(const KernelPolicyCompatibility& contract, std::string_view text, std::string* mismatch = nullptr,
                    bool bound_layout = false) {
    if (text.empty() || text.size() > 4 << 20 || contract.config.empty()) fail("CONFIG_UNVERIFIED");
    std::map<std::string, std::string> values;
    while (!text.empty()) {
        auto end = text.find('\n');
        auto line = text.substr(0, end);
        text = end == text.npos ? std::string_view{} : text.substr(end + 1);
        if (!line.starts_with("CONFIG_")) continue;
        auto equals = line.find('=');
        if (equals == line.npos || equals == 7) fail("CONFIG_RECORD");
        auto key = std::string(line.substr(0, equals));
        auto raw = line.substr(equals + 1);
        std::string value;
        if (raw.starts_with('"')) {
            if (raw.size() < 2 || !raw.ends_with('"')) fail("CONFIG_RECORD");
            raw = raw.substr(1, raw.size() - 2);
            for (size_t i = 0; i < raw.size(); ++i) {
                if (raw[i] == '\\') {
                    if (++i == raw.size() || (raw[i] != '\\' && raw[i] != '"')) fail("CONFIG_RECORD");
                }
                value.push_back(raw[i]);
            }
        } else value = raw;
        if (!values.emplace(key, value).second) fail("CONFIG_DUPLICATE");
    }
    size_t best_count = SIZE_MAX;
    auto matches = [&](const auto& overrides) {
        size_t count = 0;
        std::string fields;
        for (const auto& [key, expected] : contract.config) {
            auto override = std::find_if(overrides.begin(), overrides.end(),
                [&](const auto& pair) { return pair.first == key; });
            auto found = values.find(key);
            auto actual = found == values.end() ? "n" : found->second;
            if (bound_layout && std::find(contract.declaration_configs.begin(), contract.declaration_configs.end(), key)
                    != contract.declaration_configs.end() && !actual.empty() && actual.size() <= 9 && actual[0] != '0' &&
                actual.find_first_not_of("0123456789") == actual.npos) continue;
            if (actual != (override == overrides.end() ? expected : override->second)) {
                if (++count <= 8) fields += (fields.empty() ? "" : ",") + key;
            }
        }
        if (mismatch && count < best_count) {
            *mismatch = fields + (count > 8 ? ",..." : "");
            best_count = count;
        }
        return count == 0;
    };
    const std::vector<std::pair<std::string, std::string>> none;
    if (matches(none)) return true;
    for (const auto& profile : contract.equivalent_configs)
        if (!profile.empty() && matches(profile)) return true;
    return false;
}
}
bool bind_policy_payload_layout(PolicyPayload& payload, const std::vector<LayoutType>& reference,
                                const std::vector<uint8_t>& btf, const std::vector<KernelFunctionAbi>& functions) {
    const auto symbol = payload.exports.find("maplesu_policy_layout");
    if (symbol == payload.exports.end()) return false;
    using Table = maplesu_policy_layout_table;
    static_assert(sizeof(unsigned int) == 4 && sizeof(Table) == 24 + 4 * (2 * unsigned(MP_FIELD_COUNT) + unsigned(MP_TYPE_COUNT) + 2 * unsigned(MP_BIT_COUNT)));
    const auto at = symbol->second;
    if ((at & 3) || at > payload.image.size() || sizeof(Table) > payload.image.size() - at ||
        std::none_of(payload.segments.begin(), payload.segments.end(), [&](const auto& seg) {
            return (seg.flags & PF_W) && at >= seg.offset && at - seg.offset <= seg.size &&
                   sizeof(Table) <= seg.size - (at - seg.offset);
        })) fail("DYNAMIC_TABLE_RANGE");
    for (const auto& relocation : payload.relocations)
        if (uint64_t(relocation.offset) < uint64_t(at) + sizeof(Table) && uint64_t(relocation.offset) + 8 > at)
            fail("DYNAMIC_TABLE_RELOCATION");
    Table table;
    memcpy(&table, payload.image.data() + at, sizeof(table));
    if (table.magic != MAPLESU_POLICY_LAYOUT_MAGIC || table.version != MAPLESU_POLICY_LAYOUT_VERSION ||
        table.bytes != sizeof(table) || table.fields != MP_FIELD_COUNT || table.types != MP_TYPE_COUNT || table.ready)
        fail("DYNAMIC_TABLE_HEADER");
    struct Field { const char *type, *member; bool embedded; };
    const Field fields[] = {
#define MP_FIELD(type, member, embedded) {#type, #member, bool(embedded)},
        MAPLESU_POLICY_LAYOUT_FIELDS(MP_FIELD)
    MAPLESU_POLICY_OPTIONAL_LAYOUT_FIELDS(MP_FIELD)
#undef MP_FIELD
    };
    const Field bits[] = {
#define MP_BIT(type, member) {#type, #member, true},
        MAPLESU_POLICY_LAYOUT_BITS(MP_BIT)
#undef MP_BIT
    };
    const char* types[] = {
#define MP_TYPE(type) #type,
        MAPLESU_POLICY_LAYOUT_TYPES(MP_TYPE)
#undef MP_TYPE
    };
    auto type_name = [&](const char* type) -> std::string {
        if (std::string_view(type) != "maplesu_cred_security") return type;
        for (const auto& t : reference)
            if (t.name == "task_security_struct" || t.name == "cred_security_struct") return t.name;
        fail("DYNAMIC_CREDENTIAL_CONTRACT");
    };
    auto find_type = [&](const auto& layout, const std::string& name) -> const LayoutType& {
        auto t = std::find_if(layout.begin(), layout.end(), [&](const auto& item) { return item.name == name; });
        if (t == layout.end()) throw std::runtime_error("MODULE_POLICY_LOADER_DYNAMIC_CONTRACT:" + name);
        return *t;
    };
    auto find_field = [&](const auto& layout, const std::string& name, const std::string& member) -> const LayoutField& {
        const auto& t = find_type(layout, name);
        auto f = std::find_if(t.fields.begin(), t.fields.end(), [&](const auto& item) { return item.name == member; });
        if (f == t.fields.end()) throw std::runtime_error("MODULE_POLICY_LOADER_DYNAMIC_CONTRACT:" + name + "." + member);
        return *f;
    };
    std::vector<KernelFieldRelocation> relocations;
    std::vector<std::string> resized;
    // A new payload always has a complete compiler contract. Partial metadata
    // is not interpreted as permission to run unbound field accesses.
    for (unsigned i = 0; i < MP_FIELD_COUNT; ++i) {
        if (!table.alignments[i] && i == MP_FIELD_mm_struct_mm_lock_seq) continue;
        const auto name = type_name(fields[i].type);
        const auto& compiled = find_field(reference, name, fields[i].member);
        if ((compiled.bit_offset & 7) || (compiled.bit_size & 7) || !compiled.bit_size ||
            table.offsets[i] != compiled.bit_offset / 8) fail("DYNAMIC_COMPILED_OFFSET");
        const auto align = table.alignments[i];
        if (!align || align > 4096 || (align & (align - 1)) || table.offsets[i] % align)
            fail("DYNAMIC_COMPILED_ALIGNMENT");
        relocations.push_back({name, fields[i].member, fields[i].embedded, false, align * 8});
    }
    for (unsigned i = 0; i < MP_TYPE_COUNT; ++i) {
        const auto& compiled = find_type(reference, types[i]);
        if (!compiled.size || table.sizes[i] != compiled.size) fail("DYNAMIC_COMPILED_SIZE");
        resized.emplace_back(types[i]);
    }
    for (unsigned i = 0; i < MP_BIT_COUNT; ++i) {
        if (table.bit_offsets[i] || table.bit_widths[i] > 1) fail("DYNAMIC_COMPILED_BITS");
        if (!table.bit_widths[i]) continue;
        const auto& compiled = find_field(reference, bits[i].type, bits[i].member);
        if (!compiled.bit_size || compiled.bit_size > 32) fail("DYNAMIC_COMPILED_BIT_WIDTH");
        table.bit_offsets[i] = compiled.bit_offset;
        table.bit_widths[i] = compiled.bit_size;
        relocations.push_back({bits[i].type, bits[i].member, true, true});
    }
    // The caller permits reference offsets only for the exact kernel image.
    // Every cross-image installation requires the running kernel's BTF.
    if (!btf.empty()) {
        const auto actual = resolve_kernel_layout(btf, reference, relocations, resized, functions);
        if (find_field(actual, "selinux_policy", "policydb").bit_size !=
            uint64_t(find_type(actual, "policydb").size) * 8) fail("DYNAMIC_EMBEDDED_SIZE");
        for (unsigned i = 0; i < MP_FIELD_COUNT; ++i) {
            if (!table.alignments[i]) continue;
            if (!fields[i].embedded) continue;
            const auto name = type_name(fields[i].type);
            if (name == "selinux_policy" && std::string_view(fields[i].member) == "policydb") continue;
            uint64_t minimum = find_field(reference, name, fields[i].member).bit_size;
            const char* child = nullptr;
            if (name == "sock" && std::string_view(fields[i].member) == "__sk_common") child = "sock_common";
            if (name == "sk_buff" && std::string_view(fields[i].member) == "cb") child = "netlink_skb_parms";
            if (child) {
                minimum = 0;
                for (const auto& field : find_type(actual, child).fields)
                    minimum = std::max(minimum, uint64_t(field.bit_offset) + field.bit_size);
            }
            if (find_field(actual, name, fields[i].member).bit_size < minimum)
                throw std::runtime_error("MODULE_POLICY_LOADER_DYNAMIC_EMBEDDED_BOUNDS:" + name + "." + fields[i].member);
        }
        for (unsigned i = 0; i < MP_FIELD_COUNT; ++i) if (table.alignments[i])
            table.offsets[i] = find_field(actual, type_name(fields[i].type), fields[i].member).bit_offset / 8;
        for (unsigned i = 0; i < MP_TYPE_COUNT; ++i) table.sizes[i] = find_type(actual, types[i]).size;
        for (unsigned i = 0; i < MP_BIT_COUNT; ++i) if (table.bit_widths[i]) {
            const auto& field = find_field(actual, bits[i].type, bits[i].member);
            table.bit_offsets[i] = field.bit_offset;
            table.bit_widths[i] = field.bit_size;
        }
    }
    table.ready = 1;
    memcpy(payload.image.data() + at, &table, sizeof(table));
    return true;
}
static unsigned load_policy_view(const KernelPolicyBundle& bundle, std::string_view build_id,
                                uint32_t page_size, const std::vector<uint8_t>& btf, PolicyKernelIo& io,
                                bool preflight_only, std::string_view release, std::string_view config, bool allow_unverified) {
    io.select_bundle(bundle);
    // Consent records the user's request; it cannot establish a kernel ABI.
    (void)allow_unverified;
    if (page_size != bundle.page_size)
        fail("IMAGE_UNVERIFIED");
    const bool cross_image = build_id.empty() || build_id != bundle.build_id;
    if (cross_image) {
        auto contract = bundle.compatibility;
        auto series = bundle.kernel_series.empty() && contract ? std::string_view(contract->kernel_series) : bundle.kernel_series;
        if (series.empty() || !release.starts_with(std::string(series) + ".")) fail("IMAGE_UNVERIFIED");
        if (!contract || contract->functions.empty() || btf.empty()) fail("IMAGE_UNVERIFIED");
        if (!bundle.layout) fail("LAYOUT_MISSING");
    }
    auto payload = parse_policy_payload(bundle.image, page_size);
    if (cross_image) {
        std::string mismatch;
        // Declaration-only values never relax static payloads. The complete
        // live BTF/function contract is still bound below, before allocation.
        if (!matches_config(*bundle.compatibility, config, &mismatch,
                            payload.exports.contains("maplesu_policy_layout")))
            throw std::runtime_error("MODULE_POLICY_LOADER_CONFIG_MISMATCH:" + mismatch);
    }
    const auto functions = cross_image && bundle.compatibility ? bundle.compatibility->functions :
        std::vector<KernelFunctionAbi>{};
    if (payload.exports.contains("maplesu_policy_layout")) {
        if (!bundle.layout) fail("LAYOUT_MISSING");
        bind_policy_payload_layout(payload, bundle.layout(), btf, functions);
        io.progress(btf.empty() ? "dynamic-layout-reference-attempt:btf-missing" : "dynamic-layout-bound:btf");
    } else if (!btf.empty()) {
        if (!bundle.layout) fail("LAYOUT_MISSING");
        verify_kernel_layout(btf, bundle.layout(), functions);
    }
    const auto scs_sites = bundle.dynamic_scs ? policy_scs_patch_sites(payload) : std::vector<uint32_t>{};
    std::map<std::string, uint64_t> resolved;
    auto lookup = [&](const char* n) {
        auto it = resolved.find(n);
        if (it != resolved.end()) return it->second;
        auto address = io.lookup(n);
        if (address < 0xffff000000000000ULL) fail("SYMBOL_ADDRESS");
        resolved.emplace(n, address);
        return address;
    };
    if (cross_image && bundle.compatibility) for (const auto& [name, expected] : bundle.compatibility->native_code) {
        std::array<uint8_t, 16> actual{};
        io.read(lookup(name.c_str()), actual);
        if (std::find(expected.begin(), expected.end(), actual) == expected.end()) {
            const auto reason = "MODULE_POLICY_LOADER_NATIVE_ABI_CODE:" + name + ":" + hex_code(actual);
            throw std::runtime_error(reason);
        }
    }
    for (const auto& r : payload.relocations)
        if (!r.symbol.empty()) lookup(r.symbol.c_str());
    const char* protection[] = {"set_memory_nx", "set_memory_rw", "set_memory_ro", "set_memory_x"};
    for (const auto* n : protection) lookup(n);
    if (!bundle.cache_function || (std::string_view(bundle.cache_function) != "caches_clean_inval_pou" &&
                                  std::string_view(bundle.cache_function) != "__flush_icache_range"))
        fail("CACHE_FUNCTION");
    lookup(bundle.cache_function);
    if (payload.alternative_bytes) lookup("apply_alternatives_module");
    bool patch_scs = false;
    if (bundle.dynamic_scs) {
        if (bundle.scs_arguments != 2 && bundle.scs_arguments != 3) fail("SCS_ARGUMENTS");
        if (!bundle.scs_function || (std::string_view(bundle.scs_function) != "__pi_scs_patch" &&
                                    std::string_view(bundle.scs_function) != "scs_patch")) fail("SCS_FUNCTION");
        lookup(bundle.scs_function);
        lookup("static_key_count");
        lookup("dynamic_scs_enabled");
    }
    std::array<uint64_t, std::size(hooks)> targets{};
    std::array<std::array<uint8_t, 16>, std::size(hooks)> entries{};
    for (unsigned i = 0; i < targets.size(); ++i) {
        targets[i] = lookup(hooks[i]);
        if ((targets[i] & 3) || std::find(targets.begin(), targets.begin() + i, targets[i]) != targets.begin() + i)
            fail("HOOK_ALIAS");
        io.read(targets[i], entries[i]);
        if (!compatible_hook_entry(entries[i], bundle.hook_code[i], bundle.dynamic_scs))
            throw std::runtime_error(std::string("MODULE_POLICY_LOADER_HOOK_CONFLICT:") + hooks[i] +
                ":expected=" + hex_code(bundle.hook_code[i]) + ":observed=" + hex_code(entries[i]));
    }
    if (preflight_only) return 0;
    // Capability reporting with hiding disabled must not allocate executable
    // SDK requests or run kernel code. Read live execution state only when the
    // requested Hide installation is actually being prepared.
    if (bundle.dynamic_scs) {
        const std::array<uint64_t, 1> key_arg{resolved.at("dynamic_scs_enabled")};
        io.progress("static_key_count");
        auto count = static_cast<int32_t>(io.call(resolved.at("static_key_count"), key_arg));
        if (count < 0) fail("SCS_KEY");
        patch_scs = count > 0;
    }
    // All layout, image, imports and target-byte checks precede allocation.
    uint64_t allocation = 0;
    bool owned = false;
    bool retained = false;
    uint64_t activation = 0;
    bool activation_attempted = false;
    try {
        const auto total = uint32_t(payload.image.size() + 65536);
        io.progress("allocate-payload");
        allocation = io.allocate(total);
        if (allocation < 0xffff000000000000ULL || (allocation & (page_size - 1)) ||
            allocation > UINT64_MAX - total) fail("ALLOCATION");
        owned = true;
        const auto base = (allocation + 65535) & ~uint64_t(65535);
        activation = base + payload.image.size();
        if (activation + page_size > allocation + total) fail("ACTIVATION_ALLOCATION");
        relocate_policy_payload(payload, base, resolved);
        std::array<std::vector<uint8_t>, std::size(hooks)> dispatches;
        for (unsigned i = 0; i < dispatches.size(); ++i) {
            dispatches[i] = io.dispatch(i, base + payload.exports.at("maplesu_policy_view_handles"),
                                       base + payload.exports.at(handlers[i]), activation);
            if (dispatches[i].empty() || (dispatches[i].size() & 3)) fail("DISPATCH");
        }
        // Once a protection call is attempted, its execution/cleanup may have
        // succeeded despite a transport error. Retain the image for this boot.
        // Store's persisted attempt prevents a second allocation/install.
        retained = true;
        auto call = [&](const char* n, uint64_t a, uint64_t b, bool check) {
            const std::array<uint64_t, 2> args{a, b};
            io.progress(n);
            auto value = io.call(resolved.at(n), args);
            if (check && static_cast<int32_t>(value)) fail("KERNEL_CALL");
        };
        call("set_memory_nx", base, payload.image.size() / page_size + 1, true);
        call("set_memory_rw", base, payload.image.size() / page_size + 1, true);
        // The separate RW/NX gate is zero before the first hook is exposed.
        // A partial installation remains an ordinary pass-through for this boot.
        const std::array<uint8_t, 4> disabled{};
        io.write(activation, disabled);
        std::array<uint8_t, 4> gate{};
        io.read(activation, gate);
        if (gate != disabled) fail("ACTIVATION_READBACK");
        io.progress("write-payload");
        io.write(base, payload.image);
        std::vector<uint8_t> observed(payload.image.size());
        io.read(base, observed);
        if (observed != payload.image) fail("READBACK");
        if (payload.alternative_bytes)
            call("apply_alternatives_module", base + payload.alternatives, payload.alternative_bytes,
                 bundle.alternatives_returns_status);
        if (patch_scs) {
            // Follow native module_finalize: alternatives, dynamic SCS, cache
            // publication, then executable permissions. No callback runs yet.
            if (payload.alternative_bytes) io.read(base, observed);
            auto expected = observed;
            for (auto site : scs_sites) {
                const auto before = uint32_t(expected[site]) | uint32_t(expected[site + 1]) << 8 |
                    uint32_t(expected[site + 2]) << 16 | uint32_t(expected[site + 3]) << 24;
                if (before != 0xd503233f && before != 0xd50323bf) fail("SCS_ALTERNATIVE_CONFLICT");
                const auto after = before == 0xd503233f ? 0xf800865eU : 0xf85f8e5eU;
                for (unsigned i = 0; i < 4; ++i)
                    expected[site + i] = (after >> (i * 8)) & 255;
            }
            const std::array<uint64_t, 3> args{base + payload.scs_frames, payload.scs_frame_bytes, 1};
            io.progress(bundle.scs_function);
            if (static_cast<int32_t>(io.call(resolved.at(bundle.scs_function),
                    std::span(args).first(bundle.scs_arguments)))) fail("KERNEL_CALL");
            // One readback for the image, not one SDK round-trip per site.
            io.read(base, observed);
            if (observed != expected) fail("SCS_READBACK");
        }
        // Native cache maintenance uses the running CPU feature selection.
        // Never execute this image while its bytes or page permissions change.
        call(bundle.cache_function, base, base + payload.image.size(), false);
        for (const auto& seg : payload.segments) {
            if (seg.flags & PF_W) continue;
            auto first = seg.offset & ~(uint64_t(page_size) - 1);
            auto pages = ((seg.offset + seg.size + page_size - 1) / page_size) - first / page_size;
            call("set_memory_ro", base + first, pages, true);
            if (seg.flags & PF_X) call("set_memory_x", base + first, pages, true);
        }
        // The prepared policy, independent SID table and status page must exist
        // before any application can reach a dispatcher.
        io.progress("prepare-snapshot");
        if (static_cast<int32_t>(io.call(base + payload.exports.at("maplesu_policy_view_prepare"), {})))
            fail("PREPARE");
        for (unsigned i = 0; i < targets.size(); ++i) {
            io.progress(hooks[i]);
            std::array<uint8_t, 16> current{};
            io.read(targets[i], current);
            if (current != entries[i])
                throw std::runtime_error(std::string("MODULE_POLICY_LOADER_HOOK_CHANGED:") + hooks[i] +
                    ":observed=" + hex_code(current));
            io.hook(targets[i], dispatches[i]);
        }
        io.progress("activate-hidden-view");
        activation_attempted = true;
        io.activate(activation, true);
        return 3;
    } catch (...) {
        try { io.abort(); }
        catch (...) { io.progress("transport-abort-failed"); }
        if (activation_attempted) {
            try { io.activate(activation, false); }
            catch (...) { io.progress("activation-cancel-failed"); }
        }
        // Only an unpublished allocation with no attempted kernel call can be
        // released here. No hot-unload of executable code or policy objects.
        if (owned && !retained) {
            try { io.release(allocation); } catch (...) {}
        }
        throw;
    }
}
unsigned install_policy_view(const KernelPolicyBundle& bundle, std::string_view build_id,
                             uint32_t page_size, const std::vector<uint8_t>& btf, PolicyKernelIo& io,
                             std::string_view release, std::string_view config, bool allow_unverified) {
    return load_policy_view(bundle, build_id, page_size, btf, io, false, release, config, allow_unverified);
}
void preflight_policy_view(const KernelPolicyBundle& bundle, std::string_view build_id,
                           uint32_t page_size, const std::vector<uint8_t>& btf, PolicyKernelIo& io,
                           std::string_view release, std::string_view config, bool allow_unverified) {
    (void)load_policy_view(bundle, build_id, page_size, btf, io, true, release, config, allow_unverified);
}
}
