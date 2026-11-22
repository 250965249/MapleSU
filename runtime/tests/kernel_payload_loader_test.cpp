#include "kernel_payload_loader.h"
#include "kernel_payload_io_fixture.h"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <stdexcept>

using namespace maplesu::module_policy;
namespace {
unsigned tests = 0;

template<class F> void rejects(F fn, Io& io, unsigned allocations, unsigned releases) {
    bool failed = false;
    try { fn(); } catch (const std::runtime_error&) { failed = true; }
    if (!failed || io.allocations != allocations || io.releases != releases)
        fprintf(stderr, "Case %u: failed=%d allocations=%u/%u releases=%u/%u missing=%s address=%llx\n",
            tests + 1, failed, io.allocations, allocations, io.releases, releases, io.missing.c_str(),
            static_cast<unsigned long long>(io.allocation));
    assert(failed && io.allocations == allocations && io.releases == releases); ++tests;
}
}
int main(int argc, char** argv) {
    assert(argc >= 2 && argc <= 4);
    bool dynamic_scs = false;
    uint32_t page_size = 4096;
    for (int i = 2; i < argc; ++i) {
        const std::string_view option(argv[i]);
        if (option == "dynamic-scs") dynamic_scs = true;
        else if (option == "4096") page_size = 4096;
        else if (option == "16384") page_size = 16384;
        else if (option == "65536") page_size = 65536;
        else { fprintf(stderr, "Unknown loader test option: %s\n", argv[i]); return 2; }
    }
    std::ifstream input(argv[1], std::ios::binary); assert(input);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    KernelPolicyBundle bundle{bytes, "fixture-build", page_size, false, "caches_clean_inval_pou", {}, nullptr};
    auto install = [&](Io& io) { return install_policy_view(bundle, "fixture-build", page_size, {}, io); };
    {
        Io io;
        preflight_policy_view(bundle, "fixture-build", page_size, {}, io);
        assert(io.allocations == 0 && io.hooks == 0 && io.memory.empty());
        assert(std::find(io.events.begin(), io.events.end(), "write") == io.events.end()); ++tests;
    }
    {
        Io io; io.conflict = true;
        rejects([&] { preflight_policy_view(bundle, "fixture-build", page_size, {}, io); }, io, 0, 0);
    }
    {
        Io io; assert(install(io) == 3 && io.hooks == std::size(hook_names) && !io.releases); ++tests;
        assert(io.last_phase == "activate-hidden-view" && io.activation_enabled); ++tests;
        auto where = [&](const char* name) { return std::find(io.events.begin(), io.events.end(), name); };
        assert(where("allocate") < where("write") && where("write") < where("readback") &&
            where("readback") < where("prepare") && where("prepare") < where("hook") &&
            where("hook") < where("activate")); ++tests;
    }
    {
        Io io; rejects([&] { install_policy_view(bundle, "other-build", page_size, {}, io); }, io, 0, 0);
    }
    {
        Io io; io.bad_hook = 3;
        rejects([&] { install(io); }, io, 1, 0);
        assert(io.last_phase == "sel_open_handle_status"); ++tests;
    }
    {
        // A second image is qualified by its contract, never by replacing the
        // reference bundle's build ID. Keep all kernel operations read-only.
        std::vector<uint8_t> btf;
        auto word = [&](uint32_t v) { for (unsigned i = 0; i < 4; ++i) btf.push_back(v >> (i * 8)); };
        for (auto v : {0x0001eb9fU,24U,0U,52U,52U,18U,1U,1U<<24,4U,32U,5U,4U<<24,8U,
                       0U,13U<<24,1U,12U,12U<<24,3U}) word(v);
        const uint8_t strings[] = {0,'u','3','2',0,'p','o','l','i','c','y',0,'e','n','t','r','y',0};
        btf.insert(btf.end(), std::begin(strings), std::end(strings));
        KernelPolicyCompatibility compatibility{"6.6", {{"CONFIG_TEST", "y"}}, {}, {{"entry", "fi4:32()"}}, {}};
        bundle.layout = +[] { return std::vector<LayoutType>{{"policy",8,{}}}; };
        bundle.compatibility = &compatibility;
        // Missing notes must use full cross-image qualification. Consent
        // never substitutes for BTF, configuration or native helper checks.
        {
            for (bool has_btf : {false, true}) for (auto config : {"", "CONFIG_TEST=y\nCONFIG_TEST=n\n",
                    "CONFIG_TEST=\"unterminated\n"}) {
                Io confirmed;
                const auto metadata = has_btf ? btf : std::vector<uint8_t>{};
                rejects([&] { install_policy_view(bundle, "", page_size, metadata, confirmed,
                    "6.6.89", config, true); }, confirmed, 0, 0);
                assert(!confirmed.hooks && !confirmed.activation_enabled);
            }
            for (const bool consent : {false, true}) {
                Io qualified;
                assert(install_policy_view(bundle, "", page_size, btf, qualified,
                    "6.6.89", "CONFIG_TEST=y\n", consent) == 3);
                assert(qualified.hooks == std::size(hook_names) && qualified.activation_enabled); ++tests;
                Io missing_btf;
                rejects([&] { install_policy_view(bundle, "", page_size, {}, missing_btf,
                    "6.6.89", "CONFIG_TEST=y\n", consent); }, missing_btf, 0, 0);
            }
            Io wrong_series;
            rejects([&] { install_policy_view(bundle, "", page_size, {}, wrong_series,
                "6.1.89", "", true); }, wrong_series, 0, 0);
        }
        Io io;
        try { preflight_policy_view(bundle, "other-build", page_size, btf, io, "6.6.89-oem", "CONFIG_TEST=y\n"); }
        catch (const std::runtime_error& error) {
            fprintf(stderr, "FAIL compatible second image: %s\n", error.what());
            return 1;
        }
        assert(!io.allocations && !io.hooks && io.memory.empty()); ++tests;
        {
            Io bad;
            bool explained = false;
            try { preflight_policy_view(bundle, "other-build", page_size, btf, bad, "6.6.89", "CONFIG_TEST=n\n"); }
            catch (const std::runtime_error& error) {
                explained = std::string_view(error.what()) == "MODULE_POLICY_LOADER_CONFIG_MISMATCH:CONFIG_TEST";
            }
            assert(explained && bad.events.empty() && !bad.allocations && !bad.hooks); ++tests;
        }
        for (auto [release, config] : {std::pair{"6.6.89-oem", ""}, {"6.60.1", "CONFIG_TEST=y\n"},
                {"6.6.89", "CONFIG_TEST=n\n"}, {"6.6.89", "CONFIG_TEST=y\nCONFIG_TEST=n\n"},
                {"6.6.89", "CONFIG_TEST=\"unterminated\n"}}) {
            Io bad;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, btf, bad, release, config); }, bad, 0, 0);
            assert(bad.events.empty());
        }
        {
            Io bad;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, {}, bad, "6.6.89", "CONFIG_TEST=y\n"); }, bad, 0, 0);
        }
        compatibility.equivalent_configs = {{{"CONFIG_TEST", "n"}}};
        {
            Io other;
            preflight_policy_view(bundle, "other-build", page_size, btf, other, "6.6.89", "# CONFIG_TEST is not set\n");
            assert(!other.allocations && !other.hooks); ++tests;
        }
        {
            // An accepted neutral variant must still reject other config
            // differences and identify the closest profile's actual blocker.
            compatibility.config.emplace_back("CONFIG_REQUIRED", "y");
            Io bad;
            bool explained = false;
            try { preflight_policy_view(bundle, "other-build", page_size, btf, bad, "6.6.89", "CONFIG_TEST=n\n"); }
            catch (const std::runtime_error& error) {
                explained = std::string_view(error.what()) == "MODULE_POLICY_LOADER_CONFIG_MISMATCH:CONFIG_REQUIRED";
            }
            assert(explained && bad.events.empty() && !bad.allocations && !bad.hooks); ++tests;
            compatibility.config.pop_back();
        }
        std::array<uint8_t, 16> original{}, alternative{};
        alternative[0] = 1;
        compatibility.native_code = {{"native", {original, alternative}}};
        for (auto code : {original, alternative}) {
            Io other; other.native_bytes[other.lookup("native")] = code;
            preflight_policy_view(bundle, "other-build", page_size, btf, other, "6.6.89", "CONFIG_TEST=y\n");
            assert(!other.allocations && !other.hooks); ++tests;
        }
        {
            Io bad; alternative[1] = 2; bad.native_bytes[bad.lookup("native")] = alternative;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, btf, bad, "6.6.89", "CONFIG_TEST=y\n"); }, bad, 0, 0);
            assert(!bad.hooks);
            Io confirmed; confirmed.native_bytes[confirmed.lookup("native")] = alternative;
            rejects([&] { install_policy_view(bundle, "other-build", page_size, btf, confirmed,
                "6.6.89", "CONFIG_TEST=y\n", true); }, confirmed, 0, 0);
            assert(!confirmed.hooks);
        }
        compatibility.native_code.clear();
        {
            // A compatible OEM build may use a different stack frame/register
            // allocation. Reference-image text is not a cross-image ABI.
            auto code = [](std::initializer_list<uint32_t> words) {
                std::array<uint8_t, 16> bytes{};
                unsigned at = 0;
                for (auto word : words) for (unsigned i = 0; i < 4; ++i) bytes.at(at++) = word >> (i * 8);
                return bytes;
            };
            const auto reference = code({0xd503233f, 0xd10103ff, 0xa9027bfd, 0xa9034ff4});
            const auto saved = bundle.hook_code[0];
            bundle.hook_code[0] = reference;
            for (const auto& entry : {
                    code({0xd503233f, 0xd10143ff, 0xa9027bfd, 0xa9034ff4}),
                    code({0xd503245f, 0xd10143ff, 0xa9027bfd, 0xa9034ff4}),
                    code({0xf800865e, 0xd10143ff, 0xa9027bfd, 0xa9034ff4}),
                    code({0xa9be7bfd, 0x910003fd, 0xa9014ff4, 0xd503201f}),
                    code({0xd10143ff, 0xa9027bfd, 0xa9034ff4, 0x910083fd}),
                    code({0xd503245f, 0xd65f03c0, 0xd503201f, 0xd503201f}),
                    code({0xd503245f, 0x14000040, 0xa9027bfd, 0xa9034ff4}),
                    code({0x52800000, 0xd65f03c0, 0xd503201f, 0xd503201f})}) {
                Io other; other.native_bytes[other.lookup(hook_names[0])] = entry;
                try { preflight_policy_view(bundle, "other-build", page_size, btf, other, "6.6.89", "CONFIG_TEST=y\n"); }
                catch (const std::runtime_error& error) {
                    fprintf(stderr, "FAIL normal cross-image entry: %s\n", error.what());
                    return 1;
                }
                assert(!other.allocations && !other.hooks); ++tests;
                assert(install_policy_view(bundle, "other-build", page_size, btf, other, "6.6.89", "CONFIG_TEST=y\n") == 3);
                assert(other.hooks == std::size(hook_names)); ++tests;
                Io exact; exact.native_bytes[exact.lookup(hook_names[0])] = entry;
                assert(install(exact) == 3 && exact.hooks == std::size(hook_names)); ++tests;
            }
            // Existing detours and invalid instructions still fail before any
            // allocation, even when the user confirmed an unverified build.
            for (const auto& entry : {
                    code({0x14000040, 0xd10103ff, 0xa9027bfd, 0xa9034ff4}),
                    code({0xd61f0200, 0xd10103ff, 0xa9027bfd, 0xa9034ff4}),
                    code({0x58000050, 0xd61f0200, 0xd503201f, 0xd503201f}),
                    code({0x10000000, 0xd65f03c0, 0xd503201f, 0xd503201f}),
                    code({0x00000000, 0xd10103ff, 0xa9027bfd, 0xa9034ff4})}) {
                for (bool consent : {false, true}) {
                    Io bad; bad.native_bytes[bad.lookup(hook_names[0])] = entry;
                    bool explained = false;
                    try { install_policy_view(bundle, "other-build", page_size, btf, bad, "6.6.89", "CONFIG_TEST=y\n", consent); }
                    catch (const std::runtime_error& error) {
                        explained = std::string_view(error.what()).find(hook_names[0]) != std::string_view::npos;
                    }
                    assert(explained && !bad.allocations && !bad.hooks); ++tests;
                }
            }
            bundle.hook_code[0] = saved;
            const auto saved_leaf = bundle.hook_code[4];
            bundle.hook_code[4] = code({0xf940100a, 0xb40002ca, 0xaa0303e8, 0xaa0103e0});
            Io leaf;
            leaf.native_bytes[leaf.lookup(hook_names[4])] = code({0xf9400c09, 0xb4000309, 0xaa0303e8, 0xaa0103e0});
            assert(install_policy_view(bundle, "other-build", page_size, btf, leaf, "6.6.89", "CONFIG_TEST=y\n") == 3);
            assert(leaf.hooks == std::size(hook_names)); ++tests;
            bundle.hook_code[4] = saved_leaf;
            bundle.hook_code[0] = reference;
            if (dynamic_scs) {
            bundle.dynamic_scs = true;
            bundle.scs_function = "__pi_scs_patch";
            Io scs;
            scs.native_bytes[scs.lookup(hook_names[0])] = code({0xf800865e, 0xd10103ff, 0xa9027bfd, 0xa9034ff4});
            assert(install(scs) == 3 && scs.hooks == std::size(hook_names)); ++tests;
            bundle.dynamic_scs = false;
            }
            bundle.hook_code[0] = saved;
        }
        compatibility.functions[0].signature = "fv()";
        {
            Io bad;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, btf, bad, "6.6.89", "CONFIG_TEST=y\n"); }, bad, 0, 0);
            assert(bad.events.empty());
        }
        bundle.layout = nullptr;
        bundle.compatibility = nullptr;
    }
    {
        // Consent alone never qualifies an image without a measured ABI.
        KernelPolicyCompatibility compatibility{"6.6", {{"CONFIG_TEST", "y"}}, {}, {}, {}};
        bundle.compatibility = &compatibility;
        bundle.kernel_series = "6.6";
        bundle.layout = +[] { return std::vector<LayoutType>{{"policy",8,{}}}; };
        {
            Io io;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, {}, io,
                "6.6.89", "CONFIG_TEST=n\n", true); }, io, 0, 0);
            rejects([&] { install_policy_view(bundle, "other-build", page_size, {}, io,
                "6.6.89", "CONFIG_TEST=n\n", true); }, io, 0, 0);
            assert(!io.hooks);
        }
        {
            Io io;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, {}, io,
                "6.6.89", {}, true); }, io, 0, 0);
        }
        for (const auto* release : {"5.10.1", "6.60.1", "6.18.1", ""}) {
            Io io;
            rejects([&] { install_policy_view(bundle, "other-build", page_size, {}, io, release, {}, true); }, io, 0, 0);
            assert(io.events.empty());
        }
        {
            Io io; io.conflict = true;
            rejects([&] { install_policy_view(bundle, "other-build", page_size, {}, io, "6.6.89", {}, true); }, io, 0, 0);
        }
        {
            Io io; io.missing = "policydb_read";
            rejects([&] { install_policy_view(bundle, "other-build", page_size, {}, io, "6.6.89", {}, true); }, io, 0, 0);
        }
        {
            Io io;
            rejects([&] { install_policy_view(bundle, "other-build", page_size, {1}, io, "6.6.89", {}, true); }, io, 0, 0);
        }
        bundle.compatibility = nullptr;
        for (const auto* series : {"5.10", "5.15", "6.1", "6.6", "6.12", "6.18"}) {
            bundle.kernel_series = series;
            Io io;
            rejects([&] { preflight_policy_view(bundle, "other-build", page_size, {}, io,
                std::string(series) + ".99-oem", {}, true); }, io, 0, 0);
        }
        bundle.kernel_series = {};
        bundle.layout = nullptr;
    }
    for (uint32_t other_page : {4096, 16384, 65536}) if (other_page != page_size) {
        Io io;
        rejects([&] { install_policy_view(bundle, "fixture-build", other_page, {}, io); }, io, 0, 0);
        assert(io.events.empty());
    }
    {
        Io io; rejects([&] { install_policy_view(bundle, "fixture-build", page_size, {1}, io); }, io, 0, 0);
    }
    const auto payload = parse_policy_payload(bytes, page_size);
    for (const auto* name : {"policydb_read", "set_memory_nx", "set_memory_rw", "set_memory_ro",
            "set_memory_x", "caches_clean_inval_pou",
            "sel_write_context", "sel_write_access", "selinux_setprocattr", "sel_open_handle_status",
            "sel_read_handle_status", "sel_mmap_handle_status", "sk_filter_trim_cap"}) {
        Io io; io.missing = name; rejects([&] { install(io); }, io, 0, 0);
    }
    for (bool alias : {false, true}) {
        Io io; io.alias = alias; io.conflict = !alias; rejects([&] { install(io); }, io, 0, 0);
    }
    for (unsigned i = 0; i < std::size(hook_names); ++i) {
        Io io; io.bad_dispatch = i; rejects([&] { install(io); }, io, 1, 1);
    }
    {
        Io io; io.bad_readback = true; rejects([&] { install(io); }, io, 1, 0); assert(!io.hooks);
    }
    {
        Io io; io.prepare_error = true; rejects([&] { install(io); }, io, 1, 0); assert(!io.hooks);
    }
    {
        Io io; io.change_entry_after_prepare = true;
        rejects([&] { install(io); }, io, 1, 0);
        assert(!io.hooks && io.last_phase == hook_names[0]); ++tests;
    }
    for (const auto* name : {"set_memory_nx", "set_memory_rw", "set_memory_ro", "set_memory_x",
            "caches_clean_inval_pou"}) {
        Io io; io.failed_call = name; rejects([&] { install(io); }, io, 1, 0); assert(!io.hooks);
    }
    for (unsigned i = 0; i < std::size(hook_names); ++i) {
        Io io; io.bad_hook = i; rejects([&] { install(io); }, io, 1, 0);
        assert(io.hooks == unsigned(i + 1) && !io.activation_enabled);
        assert(std::find(io.events.begin(), io.events.end(), "activate") == io.events.end());
    }
    {
        Io io; io.activation_error = true;
        rejects([&] { install(io); }, io, 1, 0);
        assert(io.hooks == std::size(hook_names) && !io.activation_enabled);
        assert(io.events.back() == "deactivate"); ++tests;
    }
    // An invalid SDK allocation return value is not ownership of an allocation.
    // In particular, never send a NULL/error/user/unaligned address to free().
    for (uint64_t address : {uint64_t(0), uint64_t(4096), kernel_base + 1, uint64_t(-12)}) {
        Io io; io.allocation = address; rejects([&] { install(io); }, io, 1, 0);
    }
    if (payload.alternative_bytes) {
        Io io; io.missing = "apply_alternatives_module"; rejects([&] { install(io); }, io, 0, 0);
        Io other; other.failed_call = "apply_alternatives_module"; rejects([&] { install(other); }, other, 1, 0);
        bundle.alternatives_returns_status = true;
        Io returned_error; returned_error.alternatives_error = true;
        rejects([&] { install(returned_error); }, returned_error, 1, 0); assert(!returned_error.hooks);
    }
    bundle.dynamic_scs = true;
    bundle.scs_function = "__pi_scs_patch";
    if (dynamic_scs) {
        const auto sites = policy_scs_patch_sites(payload);
        for (int enabled : {0, 1, -1}) {
            Io io; io.dynamic_enabled = enabled;
            preflight_policy_view(bundle, "fixture-build", page_size, {}, io);
            if (std::any_of(io.events.begin(), io.events.end(), [](const auto& event) {
                    return event.starts_with("call:") || event == "prepare";
                })) {
                fprintf(stderr, "FAIL hiding-disabled capability probe executed kernel code\n");
                return 1;
            }
            assert(!io.allocations && !io.hooks && !io.releases && io.memory.empty()); ++tests;
        }
        for (int enabled : {0, 1}) {
            Io io; io.dynamic_enabled = enabled; io.scs_sites = sites;
            assert(install(io) == 3 && io.hooks == std::size(hook_names)); ++tests;
            const auto patch = std::find(io.events.begin(), io.events.end(), "call:__pi_scs_patch");
            const auto cache = std::find(io.events.begin(), io.events.end(), "call:caches_clean_inval_pou");
            assert(enabled ? patch < cache : patch == io.events.end()); ++tests;
        }
        for (const auto* name : {"__pi_scs_patch", "static_key_count", "dynamic_scs_enabled"}) {
            Io io; io.missing = name; rejects([&] { install(io); }, io, 0, 0);
        }
        {
            Io io; io.dynamic_enabled = -1; rejects([&] { install(io); }, io, 0, 0);
        }
        for (bool missing : {false, true}) {
            Io io; io.dynamic_enabled = 1; io.scs_sites = sites;
            io.scs_patch_error = !missing; io.scs_patch_missing = missing;
            rejects([&] { install(io); }, io, 1, 0); assert(!io.hooks);
        }
        {
            Io io; io.dynamic_enabled = 1; io.scs_sites = sites; io.scs_patch_extra_write = true;
            rejects([&] { install(io); }, io, 1, 0); assert(!io.hooks);
        }
        bundle.scs_arguments = 3;
        {
            Io io; io.dynamic_enabled = 1; io.scs_sites = sites; io.expected_scs_arguments = 3;
            assert(install(io) == 3 && io.hooks == std::size(hook_names)); ++tests;
        }
        for (uint8_t count : {1, 4}) {
            bundle.scs_arguments = count;
            Io io; rejects([&] { install(io); }, io, 0, 0);
        }
    }
    printf("PASS: %u kernel payload loader cases (page size %u; kernel I/O fixture)\n", tests, page_size);
}
