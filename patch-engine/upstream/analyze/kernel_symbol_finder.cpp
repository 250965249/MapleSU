#include "kernel_symbol_finder.h"

#include "3rdparty/find_end_func_offset.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

KernelSymbolFinder::KernelSymbolFinder(const std::vector<char>& file_buf)
	: m_file_buf(file_buf), m_symbol_proxy(file_buf) {
}

bool KernelSymbolFinder::init() {
	m_noreturn_calls.clear();
	if (!m_symbol_proxy.init()) return false;
	const auto symbols = m_symbol_proxy.get_all_symbols();
	// Linux call contracts, not inferred from a missing RET or from function size.
	for (const char* name : {"panic", "make_task_dead", "__stack_chk_fail"}) {
		const auto entry = symbols.find(name);
		if (entry == symbols.end()) continue;
		for (const auto target : {entry->second, m_symbol_proxy.kallsyms_lookup_name(name)}) {
			if (target && target % 4 == 0 && target < m_file_buf.size()) m_noreturn_calls.insert(target);
		}
	}
	return true;
}

std::unordered_map<std::string, uint64_t> KernelSymbolFinder::get_all_symbols() {
	return m_symbol_proxy.get_all_symbols();
}

namespace {
// A kallsyms name may point anywhere. Only a 4-byte aligned offset inside the
// image can be an instruction entry: unaligned "symbols" are data (`__kstrtab_*`,
// static-key descriptors such as `do_execveat_common.__print_once`), and an
// out-of-image offset is a parsing artifact. Validating the candidate is what
// makes a candidate *set* safe to resolve from.
bool plausible_entry(uint64_t offset, size_t image_size) {
	return offset && offset % 4 == 0 && image_size >= sizeof(uint32_t) &&
	       offset <= image_size - sizeof(uint32_t);
}

// Local clones the compiler emits next to the function they were cloned from.
// They are never the entry point a rule asks for, and they usually sit in a
// different section (note `.__print_once` at an odd address in 5.10).
bool compiler_clone(const std::string& name) {
	static const char* const suffixes[] = {
		".__print_once", ".isra.", ".constprop.", ".part.", ".cold", ".llvm.", ".cfi_jt",
	};
	for (const char* suffix : suffixes) {
		const std::string text(suffix);
		if (name.size() >= text.size() &&
		    name.compare(name.size() - text.size(), text.size(), text) == 0)
			return true;
	}
	return false;
}
} // namespace

uint64_t KernelSymbolFinder::find_one(const char* name, bool fuzzy) {
	if (!fuzzy) return m_symbol_proxy.kallsyms_lookup_name(name);

	const std::string query(name);
	const auto symbols = find_all(name);
	if (symbols.empty()) return 0;

	// 1) The named symbol beats anything that merely contains the query as a
	//    substring: `do_execveat_common` vs `do_execveat_common.__print_once`,
	//    `__cfi_check` vs `__cfi_check_fail`. This is the pre-6.1 single-name
	//    fallback: a substring match must never outrank the exact name.
	const auto exact = symbols.find(query);
	if (exact != symbols.end() && plausible_entry(exact->second, m_file_buf.size()))
		return exact->second;

	// 2) Otherwise pick from the candidate set, but only candidates that can be a
	//    function entry and are not compiler clones of one.
	std::vector<std::pair<uint64_t, std::string>> kept;
	kept.reserve(symbols.size());
	for (const auto& [symbol_name, address] : symbols) {
		if (!plausible_entry(address, m_file_buf.size())) continue;
		if (compiler_clone(symbol_name)) continue;
		kept.emplace_back(address, symbol_name);
	}
	if (kept.empty()) return 0;   // nothing addressable: same answer as "absent"

	const uint64_t first = kept.front().first;
	const bool one_address = std::all_of(kept.begin(), kept.end(),
		[first](const auto& item) { return item.first == first; });
	if (one_address) return first;

	// 3) Several distinct functions really do match. Fail closed, but name them:
	//    the stable marker stays first for the CLI contract.
	std::cerr << "SYMBOL_MATCH_AMBIGUOUS name=" << query << " candidates=";
	for (const auto& [address, symbol_name] : kept)
		std::cerr << symbol_name << "@0x" << std::hex << address << std::dec << ' ';
	std::cerr << '\n';
	throw std::runtime_error("SYMBOL_MATCH_AMBIGUOUS");
}

std::unordered_map<std::string, uint64_t> KernelSymbolFinder::find_all(const char* name) {
	return m_symbol_proxy.kallsyms_lookup_names_like(name);
}

uint64_t KernelSymbolFinder::find_addr(SymbolCandidates names) {
	for (const auto& [name, fuzzy] : names) {
		uint64_t addr = find_one(name, fuzzy);
		if (addr) return addr;
	}
	return 0;
}

SymbolRegion KernelSymbolFinder::find_region(SymbolCandidates names) {
	for (const auto& [name, fuzzy] : names) {
		uint64_t addr = find_one(name, fuzzy);
		if (!addr) continue;

		auto region = parse_region(addr);
		if (region.valid()) return region;
	}
	return {};
}

SymbolRegion KernelSymbolFinder::parse_region(uint64_t offset) {
	using namespace a64_find_end_func_offset;

	SymbolRegion result;
	if (!offset || offset % 4 != 0 || offset >= m_file_buf.size()) return result;
	result.offset = offset;

	const uint64_t kallsyms_size = m_symbol_proxy.kallsyms_symbol_size(offset);
	if (!kallsyms_size) return result;
	size_t candidate_offset = 0;
	if (find_end_func_offset(m_file_buf, offset, candidate_offset, kallsyms_size, m_noreturn_calls)) {
		result.size = candidate_offset + 4;
		if (result.size > m_file_buf.size() - offset) return {};
		return result;
	}

	/*
	 * The end scan fails on functions that have no single reachable return: an
	 * inline BUG() (`brk`, 5.10 do_execveat_common), a jump-table dispatcher
	 * (`br`, 5.10 __cfi_check), or a tail call out of the symbol. kallsyms already
	 * bounds such a symbol by the next symbol in the image, so hand that span back
	 * instead of reporting "no region at all".
	 *
	 * The span is a *superset* of the function: it may include alignment padding or
	 * a neighbouring local label, so it is only safe for entry-relative work
	 * (patching the first instruction, using the head as stub space). Callers that
	 * need the exact epilogue keep using the scan, which still runs first.
	 */
	result.size = kallsyms_size;
	if (result.size > m_file_buf.size() - offset) return {};
	std::cerr << "note: region span-bounded offset=0x" << std::hex << offset
	          << " size=0x" << result.size << std::dec << '\n';
	return result;
}

std::unordered_map<std::string, SymbolRegion> KernelSymbolFinder::parse_regions(
	const std::unordered_map<std::string, uint64_t>& symbols) {
	std::unordered_map<std::string, SymbolRegion> results;
	for (const auto& [func_name, offset] : symbols) {
		if (func_name.find(".cfi_jt") != std::string::npos) continue;
		results.emplace(func_name, parse_region(offset));
	}
	return results;
}

uint64_t KernelSymbolFinder::get_kallsyms_relative_base() {
	return m_symbol_proxy.get_kallsyms_relative_base();
}
