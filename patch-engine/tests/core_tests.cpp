#include <algorithm>
#include "analyze/kernel_version_parser.h"
#include "analyze/kernel_symbol_finder.h"
#include "3rdparty/aarch64_asm_helper.h"
#include "patch_safety.h"
#include "patch_plan.h"
#include "3rdparty/find_end_func_offset.h"
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

static int checks = 0;
static void require(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
static std::vector<char> buffer(const std::string& text) { return {text.begin(), text.end()}; }
static std::vector<char> instructions(std::initializer_list<uint32_t> words) {
    std::vector<char> bytes(words.size() * 4);
    size_t offset = 0;
    for (const auto word : words) {
        for (unsigned shift = 0; shift < 32; shift += 8) bytes[offset++] = char(word >> shift);
    }
    return bytes;
}
class FixtureLookup final : public IKallsymsLookup {
public:
    bool init() override { return true; }
    bool is_inited() const override { return true; }
    uint64_t get_kallsyms_relative_base() override { return 0; }
    std::unordered_map<std::string, uint64_t> kallsyms_on_each_symbol() override { return cache; }
    uint64_t kallsyms_lookup_name(const char* name) override {
        require_unique_symbol(name);
        const auto it = cache.find(name);
        return it == cache.end() ? 0 : it->second;
    }
    uint64_t kallsyms_symbol_size(uint64_t offset) override { return symbol_span(offset); }
    void add(const char* name, uint64_t offset) { record_symbol(cache, name, offset); }
    void reset() { cache.clear(); clear_symbol_records(); }
private:
    std::unordered_map<std::string, uint64_t> cache;
};
int main() {
    try {
        auto tail = buffer("Linux version 6.6.66-device\0");
        KernelVersionParser parser(tail);
        require(parser.get_kernel_version() == "6.6.66", "banner near EOF ignored");
        require(parser.is_kernel_version_less("6.12.0"), "numeric version comparison");
        require(!parser.is_kernel_version_less("6.6.66"), "equal version comparison");
        auto empty = buffer("");
        require(KernelVersionParser(empty).get_kernel_version().empty(), "empty input");
        for (size_t i = 0; i <= 14; ++i) {
            auto truncated = buffer(std::string("Linux version ").substr(0, i));
            require(KernelVersionParser(truncated).get_kernel_version().empty(), "truncated banner");
        }
        for (const auto& text : {"Linux version 6..6", "Linux version 6.6.",
                "Linux version 99999999999999999999.6.1", "Linux version 6.6.1.2"}) {
            auto invalid = buffer(text);
            require(KernelVersionParser(invalid).get_kernel_version().empty(), "malformed version accepted");
        }
        auto multiple = buffer("Linux version 5.4.0-a\nLinux version 6.6.0-b");
        require(KernelVersionParser(multiple).get_kernel_version().empty(), "conflicting versions accepted");
        SymbolRegion region{64, 8};
        region.consume(4);
        require(region.offset == 68 && region.size == 4, "region consume");
        try { region.consume(8); throw std::logic_error("region overflow accepted"); }
        catch (const std::out_of_range&) { ++checks; }
        require(region.offset == 68 && region.size == 4, "failed consume mutated region");
        FixtureLookup duplicate_symbols;
        duplicate_symbols.add("start", 16);
        duplicate_symbols.add("duplicate", 32);
        duplicate_symbols.add("duplicate", 64);
        duplicate_symbols.add("alias", 64);
        duplicate_symbols.add("alias", 64);
        require(duplicate_symbols.get_symbol_records().size() == 5, "symbol records collapsed by name");
        require(duplicate_symbols.kallsyms_symbol_size(16) == 16, "duplicate name erased next symbol boundary");
        require(duplicate_symbols.kallsyms_symbol_size(32) == 32, "duplicate address boundary missing");
        require(duplicate_symbols.kallsyms_symbol_size(64) == 0, "last symbol has invented boundary");
        require(duplicate_symbols.kallsyms_lookup_name("alias") == 64, "same-address alias marked ambiguous");
        bool ambiguous = false;
        try { duplicate_symbols.kallsyms_lookup_name("duplicate"); }
        catch (const std::runtime_error& error) { ambiguous = std::string(error.what()) == "SYMBOL_MATCH_AMBIGUOUS"; }
        require(ambiguous, "ambiguous exact symbol accepted");
        duplicate_symbols.reset();
        duplicate_symbols.add("duplicate", 100);
        duplicate_symbols.add("end", 112);
        require(duplicate_symbols.get_symbol_records().size() == 2, "unmapped records survived cache reset");
        require(duplicate_symbols.kallsyms_lookup_name("duplicate") == 100, "ambiguity survived cache reset");
        require(duplicate_symbols.kallsyms_symbol_size(100) == 12, "old address survived cache reset");
        for (int64_t distance : {-(1LL << 27), 0LL, (1LL << 27) - 4}) {
            auto assembly = init_aarch64_asm();
            require(aarch64_asm_b(assembly.assembler(), distance), "valid B rejected");
            require(aarch64_asm_bl_raw(assembly.assembler(), distance), "valid BL rejected");
            require(aarch64_asm_to_bytes(assembly.assembler()).size() == 8, "branch omitted");
        }
        for (int64_t distance : {-(1LL << 27) - 4, 2LL, (1LL << 27), (1LL << 32)}) {
            auto assembly = init_aarch64_asm();
            try { aarch64_asm_b(assembly.assembler(), distance); throw std::logic_error("invalid B accepted"); }
            catch (const std::out_of_range&) { ++checks; }
            try { aarch64_asm_bl_raw(assembly.assembler(), distance); throw std::logic_error("invalid BL accepted"); }
            catch (const std::out_of_range&) { ++checks; }
            require(aarch64_asm_to_bytes(assembly.assembler()).empty(), "invalid branch emitted bytes");
        }
        for (uint32_t instruction : {0x90000000U, 0x14000000U, 0x58000000U, 0xd65f03c0U, 0xd503233fU, 0xffffffffU}) {
            std::vector<char> source(4);
            std::memcpy(source.data(), &instruction, 4);
            std::vector<uint8_t> dest(4, 0x42);
            bool rejected = false;
            try { maplesu::restore_instruction(source, 0, dest, 0); }
            catch (const std::runtime_error&) { rejected = true; }
            require(rejected, "unsupported relocation accepted");
            require(dest == std::vector<uint8_t>(4, 0x42), "rejected relocation mutated output");
        }
        std::vector<char> source{char(0xfd), char(0x7b), char(0xbf), char(0xa9)}; // stp x29,x30,[sp,#-16]!
        std::vector<uint8_t> dest(4);
        maplesu::restore_instruction(source, 0, dest, 0);
        require(std::memcmp(source.data(), dest.data(), 4) == 0, "ordinary prologue relocation changed");
        size_t end = 0;
        require(!a64_find_end_func_offset::find_end_func_offset(source, source.size(), end), "EOF function accepted");
        std::vector<char> undecodable(8, char(0xff));
        require(!a64_find_end_func_offset::find_end_func_offset(undecodable, 0, end), "skipdata interpreted as instructions");
        // Early RET with a forward block that returns through a backward branch.
        const auto split_return = instructions({0xb4000040, 0xd65f03c0, 0xd503201f, 0x17fffffe});
        require(a64_find_end_func_offset::find_end_func_offset(split_return, 0, end), "split return block not resolved");
        require(end == 12, "split return block truncated");
        const auto panic_path = instructions({0xb4000040, 0xd65f03c0, 0x94000002, 0xffffffff, 0xd4200000});
        end = 0xface;
        require(!a64_find_end_func_offset::find_end_func_offset(panic_path, 0, end, 16),
                "ordinary call treated as noreturn");
        require(end == 0xface, "failed function scan changed output");
        require(a64_find_end_func_offset::find_end_func_offset(panic_path, 0, end, 16, {16}),
                "verified noreturn path not resolved");
        require(end == 8, "noreturn path included trailing data");
        struct FunctionCase {
            const char* name;
            std::vector<char> code;
            size_t bound;
            bool found;
            size_t last;
        };
        const std::vector<FunctionCase> function_cases{
            {"single return", instructions({0xd65f03c0}), 4, true, 0},
            {"PAC return", instructions({0xd65f0bff}), 4, true, 0},
            {"PAC B-key return", instructions({0xd65f0fff}), 4, true, 0},
            {"forward branch", instructions({0x14000002, 0xd503201f, 0xd65f03c0}), 12, true, 8},
            {"conditional zero target", instructions({0xb4000000, 0xd65f03c0}), 8, true, 4},
            {"backward zero target", instructions({0xb4000040, 0xd65f03c0, 0x17fffffe}), 12, true, 8},
            {"merged return paths", instructions({0xb4000060, 0xb5000041, 0xd65f03c0, 0x17ffffff}), 16, true, 12},
            {"call returns", instructions({0x94000002, 0xd65f03c0, 0xd4200000}), 8, true, 4},
            {"unreachable different return", instructions({0xd65f03c0, 0xd65f0bff}), 8, true, 0},
            {"unreachable undecodable tail", instructions({0xd65f03c0, 0xffffffff}), 8, true, 0},
            {"undecodable entry", instructions({0xffffffff, 0xd65f03c0}), 8, false, 0},
            {"reachable undecodable block", instructions({0xb4000040, 0xd65f03c0, 0xffffffff}), 12, false, 0},
            {"reachable fallthrough", instructions({0xb4000040, 0xd65f03c0, 0xd503201f}), 12, false, 0},
            {"next symbol return", instructions({0xd503201f, 0xd503201f, 0xd65f03c0}), 8, false, 0},
            {"branch into next symbol", instructions({0x14000002, 0xd503201f, 0xd65f03c0}), 8, false, 0},
            {"external conditional branch", instructions({0xb4ffffe0, 0xd65f03c0}), 8, false, 0},
            {"external backward tail", instructions({0xb4000040, 0xd65f03c0, 0x17fffffd}), 12, false, 0},
            {"external forward tail", instructions({0xb4000040, 0xd65f03c0, 0x14000002, 0xd65f03c0}), 12, false, 0},
            {"indirect branch", instructions({0xb4000040, 0xd65f03c0, 0xd61f0000}), 12, false, 0},
            {"exception return", instructions({0xd69f03e0, 0xd65f03c0}), 8, false, 0},
            {"authenticated exception return", instructions({0xd69f0bff, 0xd65f03c0}), 8, false, 0},
            {"B-key exception return", instructions({0xd69f0fff, 0xd65f03c0}), 8, false, 0},
            {"debug state return", instructions({0xd6bf03e0, 0xd65f03c0}), 8, false, 0},
            {"breakpoint trap", instructions({0xd4200000, 0xd65f03c0}), 8, false, 0},
            {"halt trap", instructions({0xd4400000, 0xd65f03c0}), 8, false, 0},
            {"supervisor exception", instructions({0xd4000001, 0xd65f03c0}), 8, false, 0},
            {"no return in closed cycle", instructions({0x14000000, 0xd65f03c0}), 8, false, 0},
            {"different reachable returns", instructions({0xb4000040, 0xd65f03c0, 0xd65f0bff}), 12, false, 0},
            {"unaligned bound", instructions({0xd65f03c0, 0xd503201f}), 6, false, 0},
            {"bound past EOF", instructions({0xd65f03c0}), 8, false, 0},
        };
        for (const auto& test : function_cases) {
            end = 0xface;
            require(a64_find_end_func_offset::find_end_func_offset(test.code, 0, end, test.bound) == test.found, test.name);
            require(end == (test.found ? test.last : 0xface), test.name);
        }
        // Capstone targets are relative to the scanned start; noreturn evidence uses file offsets.
        auto shifted_panic = panic_path;
        shifted_panic.insert(shifted_panic.begin(), 16, char(0xff));
        require(a64_find_end_func_offset::find_end_func_offset(shifted_panic, 16, end, 16, {32}) && end == 8,
                "noreturn absolute target conversion");
        end = 0xface;
        require(!a64_find_end_func_offset::find_end_func_offset(shifted_panic, 16, end, 16, {16}),
                "relative target mistaken for file offset");
        require(end == 0xface, "rejected noreturn scan changed output");
        std::vector<char> long_chain;
        for (size_t i = 0; i < 4096; ++i) {
            const auto branch = instructions({0x14000001});
            long_chain.insert(long_chain.end(), branch.begin(), branch.end());
        }
        const auto return_bytes = instructions({0xd65f03c0});
        long_chain.insert(long_chain.end(), return_bytes.begin(), return_bytes.end());
        require(a64_find_end_func_offset::find_end_func_offset(long_chain, 0, end, long_chain.size()) && end == 4096 * 4,
                "long forward branch chain");
        long_chain.resize(0x10000 * 4 + 4, 0);
        require(!a64_find_end_func_offset::find_end_func_offset(long_chain, 0, end, long_chain.size()),
                "oversized function accepted");
        std::vector<char> original(128, char(0xff));
        maplesu::PatchPlan plan{{{64, {0xff, 0xff}, {1, 2}}, {100, {0xff}, {3}}}, 0};
        const auto applied = maplesu::apply_plan_for_validation(original, plan);
        require(original == std::vector<char>(128, char(0xff)), "plan mutated source");
        require(applied[64] == 1 && applied[65] == 2 && applied[100] == 3, "plan bytes not applied");
        for (size_t i = 0; i < original.size(); ++i)
            if (i != 64 && i != 65 && i != 100) require(applied[i] == original[i], "unplanned modification");
        auto changed = original;
        changed[64] = 0;
        bool rejected = false;
        try { maplesu::apply_plan_for_validation(changed, plan); }
        catch (const std::runtime_error&) { rejected = true; }
        require(rejected, "stale plan accepted");
        plan.edits[1].offset = 65;
        rejected = false;
        try { maplesu::apply_plan_for_validation(original, plan); }
        catch (const std::runtime_error&) { rejected = true; }
        require(rejected, "overlapping writes accepted");
        maplesu::PatchPlan credential_plan{{{64, std::vector<uint8_t>(48, 0xff),
            std::vector<uint8_t>(48, 0)}}, 64};
        std::vector<uint8_t> credential(48, 'A');
        credential.back() = 'Z';
        const auto initialized = maplesu::apply_plan_with_credential(original, credential_plan, credential);
        require(std::all_of(initialized.begin() + 64, initialized.begin() + 111,
                [](char c) { return c == 'A'; }) && initialized[111] == 0,
                "credential does not match runtime truncation contract");
        require(original == std::vector<char>(128, char(0xff)), "credential initialization mutated source");
        for (size_t i = 0; i < original.size(); ++i)
            if (i < 64 || i >= 112) require(initialized[i] == original[i], "credential changed outside plan");
        for (const auto& invalid : {std::vector<uint8_t>(47, 'A'), std::vector<uint8_t>(48, '!')}) {
            rejected = false;
            try { maplesu::apply_plan_with_credential(original, credential_plan, invalid); }
            catch (const std::runtime_error&) { rejected = true; }
            require(rejected, "invalid runtime credential accepted");
        }
        credential_plan.edits[0].replacement[0] = 1;
        rejected = false;
        try { maplesu::apply_plan_with_credential(original, credential_plan, credential); }
        catch (const std::runtime_error&) { rejected = true; }
        require(rejected, "nonzero credential slot accepted");
        std::cout << "PASS " << checks << " native core checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
