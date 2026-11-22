#include "analyze/kernel_version_parser.h"
#include "analyze/symbol_analyze.h"
#include "patch_plan.h"
#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {
constexpr size_t max_kernel = 128 * 1024 * 1024;
std::vector<char> read_kernel(const char* path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("PATCH_INPUT_OPEN_FAILED");
    const auto size = input.tellg();
    if (size < 64 || size > max_kernel) throw std::runtime_error("PATCH_INPUT_SIZE_INVALID");
    std::vector<char> bytes(static_cast<size_t>(size));
    input.seekg(0);
    if (!input.read(bytes.data(), size)) throw std::runtime_error("PATCH_INPUT_READ_FAILED");
    if (std::string(bytes.data() + 56, 4) != std::string("ARM\x64", 4))
        throw std::runtime_error("RAW_ARM64_REQUIRED");
    return bytes;
}
}

// The caller owns an app-private directory. No device or privileged I/O is used.
int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: maplesu-kernel-patch <raw-kernel> <new-output>\n";
        return 2;
    }
    std::vector<uint8_t> credential(48);
    bool output_created = false;
    try {
#ifdef _WIN32
        _setmode(_fileno(stdin), _O_BINARY);
#endif
        std::array<char, 4> length{};
        if (!std::cin.read(length.data(), length.size()) || length != std::array<char, 4>{0, 0, 0, 48} ||
            !std::cin.read(reinterpret_cast<char*>(credential.data()), credential.size()) ||
            std::cin.peek() != std::char_traits<char>::eof())
            throw std::runtime_error("PATCH_CREDENTIAL_PROTOCOL_INVALID");
        if (std::filesystem::exists(argv[2])) throw std::runtime_error("PATCH_OUTPUT_EXISTS");
        const auto bytes = read_kernel(argv[1]);
        KernelVersionParser version(bytes);
        if (version.get_kernel_version().empty()) throw std::runtime_error("KERNEL_VERSION_INVALID");
        SymbolAnalyze symbols(bytes);
        if (!symbols.analyze_kernel_symbol()) throw std::runtime_error("SYMBOL_ANALYSIS_FAILED");
        const auto plan = maplesu::make_patch_plan(bytes, symbols.get_symbol_offset());
        const auto patched = maplesu::apply_plan_with_credential(bytes, plan, credential);
        std::fill(credential.begin(), credential.end(), 0);
        {
            std::ofstream output(argv[2], std::ios::binary | std::ios::trunc);
            if (!output) throw std::runtime_error("PATCH_OUTPUT_OPEN_FAILED");
            output_created = true;
            if (!output.write(patched.data(), patched.size()) || !output.flush())
                throw std::runtime_error("PATCH_OUTPUT_WRITE_FAILED");
        }
        if (read_kernel(argv[2]) != patched || read_kernel(argv[1]) != bytes)
            throw std::runtime_error("PATCH_READBACK_MISMATCH");
        std::cout << std::dec << "MAPLESU_PATCH_OK edits=" << plan.edits.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::fill(credential.begin(), credential.end(), 0);
        if (output_created) {
            std::error_code ignored;
            std::filesystem::remove(argv[2], ignored);
        }
        std::cerr << error.what() << '\n';
        return 1;
    }
}
