#include "analyze/kernel_version_parser.h"
#include "analyze/symbol_analyze.h"
#include "patch_plan.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

// Read-only bring-up entry point. No patch writer or credential generation is called.
int main(int argc, char** argv) {
    const bool plan_requested = argc == 3 && std::string(argv[1]) == "--plan";
    const bool symbols_requested = argc == 3 && std::string(argv[1]) == "--symbols";
    if (argc != 2 && !plan_requested && !symbols_requested) {
        std::cerr << "Usage: maplesu-kernel-analyze [--symbols|--plan] <raw-arm64-kernel>\n";
        return 2;
    }
    try {
        std::ifstream input(argv[argc - 1], std::ios::binary | std::ios::ate);
        if (!input) throw std::runtime_error("INPUT_OPEN_FAILED");
        const auto size = input.tellg();
        if (size < 64 || size > 512LL * 1024 * 1024) throw std::runtime_error("INPUT_SIZE_INVALID");
        std::vector<char> bytes(static_cast<size_t>(size));
        input.seekg(0);
        if (!input.read(bytes.data(), size)) throw std::runtime_error("INPUT_READ_FAILED");
        if (std::string(bytes.data() + 56, 4) != std::string("ARM\x64", 4))
            throw std::runtime_error("RAW_ARM64_REQUIRED");
        KernelVersionParser version(bytes);
        if (version.get_kernel_version().empty()) throw std::runtime_error("KERNEL_VERSION_INVALID");
        if (symbols_requested) {
            KernelSymbolFinder finder(bytes);
            if (!finder.init()) throw std::runtime_error("SYMBOL_TABLE_ANALYSIS_FAILED");
            const auto symbols = finder.get_all_symbols();
            if (symbols.empty()) throw std::runtime_error("SYMBOL_TABLE_EMPTY");
            std::cout << std::dec << "SYMBOL_TABLE_OK count=" << symbols.size() << '\n';
            return 0;
        }
        SymbolAnalyze symbols(bytes);
        if (!symbols.analyze_kernel_symbol()) throw std::runtime_error("SYMBOL_ANALYSIS_FAILED");
        std::cout << std::dec << "SYMBOL_ANALYSIS_OK count=" << symbols.get_all_symbols().size() << '\n';
        if (plan_requested) {
            const auto plan = maplesu::make_patch_plan(bytes, symbols.get_symbol_offset());
            const auto replay = maplesu::apply_plan_for_validation(bytes, plan);
            size_t changed = 0;
            for (size_t i = 0; i < bytes.size(); ++i) changed += bytes[i] != replay[i];
            for (const auto& edit : plan.edits) {
                std::cout << std::dec << "PLAN_EDIT offset=" << edit.offset
                          << " expected=" << bytes2hex(edit.expected.data(), edit.expected.size())
                          << " replacement=" << bytes2hex(edit.replacement.data(), edit.replacement.size()) << '\n';
            }
            std::cout << std::dec << "PLAN_SLOT offset=" << plan.credential_slot << " length=" << ROOT_KEY_LEN << '\n';
            std::cout << std::dec << "PATCH_PLAN_OK edits=" << plan.edits.size()
                      << " credentialInitialized=false flashableCandidate=false\n";
            std::cout << "PLAN_REPLAY_OK changedBytes=" << changed << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
