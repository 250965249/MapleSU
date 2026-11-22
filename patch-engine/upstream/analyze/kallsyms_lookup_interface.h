#pragma once
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <stdexcept>
#include <vector>
#include <utility>

class IKallsymsLookup {
public:
    virtual ~IKallsymsLookup() = default;

    virtual bool init() = 0;
    virtual bool is_inited() const = 0;
    virtual uint64_t kallsyms_lookup_name(const char* name) = 0;
    virtual uint64_t kallsyms_symbol_size(uint64_t cur_addr) = 0;
    virtual std::unordered_map<std::string, uint64_t> kallsyms_on_each_symbol() = 0;
    virtual uint64_t get_kallsyms_relative_base() = 0;

    const std::vector<std::pair<std::string, uint64_t>>& get_symbol_records() {
        if (m_symbol_records.empty()) (void)kallsyms_on_each_symbol();
        return m_symbol_records;
    }

    void require_unique_symbol(const std::string& name) const {
        if (!m_ambiguous_names.count(name)) return;
        // Keep the stable marker first (the CLI contract and the native tests match
        // it exactly) and name the offending symbol after it: a bare marker made
        // the 5.10 abort impossible to attribute without a debugger.
        std::cerr << "SYMBOL_MATCH_AMBIGUOUS name=" << name << '\n';
        throw std::runtime_error("SYMBOL_MATCH_AMBIGUOUS");
    }

    // A duplicate kallsyms name is information, not an error: enumeration callers
    // may list it, and only an actual single-name resolution has to decide what to
    // do about it. See KallsymsLookupName_4_6_0::kallsyms_lookup_name.
    bool is_symbol_ambiguous(const std::string& name) const {
        return m_ambiguous_names.count(name) != 0;
    }

protected:
    void record_symbol(std::unordered_map<std::string, uint64_t>& cache, const char* name, uint64_t offset) {
        const auto previous = cache.find(name);
        if (previous != cache.end() && previous->second != offset) m_ambiguous_names.insert(name);
        cache[name] = offset; // Retain the upstream name view for enumeration only.
        m_symbol_records.emplace_back(name, offset);
        m_symbol_addresses.insert(offset);
    }

    void clear_symbol_records() {
        m_symbol_records.clear();
        m_symbol_addresses.clear();
        m_ambiguous_names.clear();
    }

    uint64_t symbol_span(uint64_t offset) const {
        if (!offset) return 0;
        const auto next = m_symbol_addresses.upper_bound(offset);
        return next == m_symbol_addresses.end() ? 0 : *next - offset;
    }

private:
    std::vector<std::pair<std::string, uint64_t>> m_symbol_records;
    std::set<uint64_t> m_symbol_addresses;
    std::unordered_set<std::string> m_ambiguous_names;
};
