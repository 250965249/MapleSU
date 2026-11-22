// SPDX-License-Identifier: GPL-3.0-only
#include "../ultra/policy/kernel_payload_loader.cpp"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iterator>
int main(int argc, char** argv) {
    using namespace maplesu::module_policy;
    assert(argc == 2);
    std::ifstream input(argv[1]);
    const std::string config((std::istreambuf_iterator<char>(input)), {});
    unsigned tests = 0;
    for (const auto& bundle : kernel_policy_bundles()) if (bundle.kernel_series == "6.12") {
        const auto& contract = *bundle.compatibility;
        std::string mismatch;
        assert(!matches_config(contract, config, &mismatch)); ++tests;
        assert(matches_config(contract, config, &mismatch, true)); ++tests;
        const auto key = contract.declaration_configs.at(0);
        auto replace = [&](std::string value) {
            auto at = config.find(key + "="); assert(at != config.npos);
            auto end = config.find('\n', at);
            return config.substr(0, at) + key + "=" + value + config.substr(end);
        };
        for (const auto value : {"512", "1536", "2048", "8192", "999999999"}) {
            assert(matches_config(contract, replace(value), &mismatch, true)); ++tests;
        }
        for (const auto value : {"0", "-1", "01", "y", "n", "0x1000", "9999999999"}) {
            assert(!matches_config(contract, replace(value), &mismatch, true)); ++tests;
        }
        // Semantic configuration differences retain their strict rejection.
        auto changed = config + "\nCONFIG_PER_VMA_LOCK=n\n";
        bool rejected = false;
        try { (void)matches_config(contract, changed, &mismatch, true); }
        catch (const std::runtime_error&) { rejected = true; }
        assert(rejected); ++tests;
    }
    assert(tests == 15);
    printf("PASS %u dynamic configuration cases; static payload and invalid values rejected\n", tests);
}
