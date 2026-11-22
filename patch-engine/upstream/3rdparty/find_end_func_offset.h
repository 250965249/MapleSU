#pragma once
#include <iostream>
#include <map>
#include <vector>
#include <set>
#include <sstream>
#include <regex>
#include <string>
#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <capstone/capstone.h>

namespace a64_find_end_func_offset {
	constexpr size_t k_npos = static_cast<size_t>(-1);

	enum class ret_mode : uint8_t {
		none = 0,
		ret,
		retaa,
		retab
	};

	struct code_line {
		uint64_t addr = 0;
		arm64_insn cmd_id = ARM64_INS_INVALID;
		arm64_cc cc_id = ARM64_CC_INVALID;
		int64_t final_imm = 0;
		bool has_imm = false;
		bool unsupported_jump = false;
		bool noreturn_call = false;
	};

	static inline ret_mode get_ret_mode(arm64_insn id) {
		switch (id) {
		case ARM64_INS_RET:   return ret_mode::ret;
		case ARM64_INS_RETAA: return ret_mode::retaa;
		case ARM64_INS_RETAB: return ret_mode::retab;
		default: return ret_mode::none;
		}
	}

	static inline const char* get_ret_mode_name(ret_mode mode) {
		switch (mode) {
		case ret_mode::ret: return "RET";
		case ret_mode::retaa: return "RETAA";
		case ret_mode::retab: return "RETAB";
		default: return "";
		}
	}

	static inline bool is_ret_insn(arm64_insn id) {
		return get_ret_mode(id) != ret_mode::none;
	}

	static inline bool is_offset_jump_asm(const code_line& line) {
		switch (line.cmd_id) {
		case ARM64_INS_B:
		case ARM64_INS_CBZ:
		case ARM64_INS_CBNZ:
		case ARM64_INS_TBZ:
		case ARM64_INS_TBNZ:
			return true;
		default:
			return false;
		}
	}

	static inline bool is_force_jump_asm(const code_line& line) {
		if (line.cmd_id == ARM64_INS_BR) return true;
		return line.cmd_id == ARM64_INS_B &&
			(line.cc_id == ARM64_CC_INVALID || line.cc_id == ARM64_CC_AL || line.cc_id == ARM64_CC_NV);
	}

	static size_t index_by_addr(const std::vector<code_line>& v, uint64_t addr) {
		auto it = std::lower_bound(v.begin(), v.end(), addr, [](const code_line& L, uint64_t a) { return L.addr < a; });
		if (it != v.end() && it->addr == addr) return static_cast<size_t>(it - v.begin());
		return k_npos;
	}

	static bool scan_from_index(const std::vector<code_line>& v_code_line, size_t start_idx,
		std::set<uint64_t>& visited, std::vector<uint64_t>& out_terminal_addrs,
		std::vector<uint64_t>& out_branch_anchors, size_t limit, ret_mode& found_ret_mode) {
		
		for (size_t x = start_idx; x < v_code_line.size(); ++x) {
			const auto& line = v_code_line[x];
			if (!visited.insert(line.addr).second) return true;
			if (line.unsupported_jump) return false;
			if (line.noreturn_call) {
				out_terminal_addrs.push_back(line.addr);
				return true;
			}
			if (is_offset_jump_asm(line)) {
				const int64_t addr = line.final_imm;
				// External branches need separate tail-call evidence; never follow them into another symbol.
				if (!line.has_imm || addr < 0 || static_cast<uint64_t>(addr) >= limit || addr % 4) return false;
				const uint64_t fork = static_cast<uint64_t>(addr);
				if (!visited.count(fork)) out_branch_anchors.push_back(fork);

				if (is_force_jump_asm(line)) {
					return true;
				}
				continue;
			}

			if (is_ret_insn(line.cmd_id)) {
				const auto mode = get_ret_mode(line.cmd_id);
				if (found_ret_mode != ret_mode::none && found_ret_mode != mode) {
					printf("Error: mixed reachable return instructions %s and %s at address 0x%llx.\n",
						get_ret_mode_name(found_ret_mode), get_ret_mode_name(mode),
						static_cast<unsigned long long>(line.addr));
					return false;
				}
				found_ret_mode = mode;
				out_terminal_addrs.push_back(line.addr);
				return true;
			}
		}
		return false; // A reachable fallthrough still needs another decoded instruction.
	}

	static bool handle_candidate_offsets(const std::vector<code_line>& v_code_line, size_t& candidate_offsets, size_t limit) {
		std::vector<uint64_t> terminal_addrs;
		std::vector<uint64_t> branch_anchors;
		std::set<uint64_t> visited;
		ret_mode found_ret_mode = ret_mode::none;

		// scan main line
		if (!scan_from_index(v_code_line, 0, visited, terminal_addrs, branch_anchors, limit, found_ret_mode)) return false;

		// scan branch lines
		while (!branch_anchors.empty()) {
			const uint64_t fork_addr = branch_anchors.back();
			branch_anchors.pop_back();

			const size_t idx = index_by_addr(v_code_line, fork_addr);
			if (idx == k_npos) {
				return false; // need more code line
			}
			if (!scan_from_index(v_code_line, idx, visited, terminal_addrs, branch_anchors, limit, found_ret_mode)) return false;
		}

		if (!terminal_addrs.empty()) {
			candidate_offsets = static_cast<size_t>(*visited.rbegin());
			return true;
		}

		return false;
	}

	static bool find_end_func_offset(const std::vector<char>& file_buf, size_t start, size_t& candidate_offsets,
		size_t symbol_size = 0, const std::set<uint64_t>& noreturn_targets = {}) {
		if (start % 4 || start >= file_buf.size() || file_buf.size() - start < 4) return false;
		if (symbol_size && (symbol_size % 4 || symbol_size > file_buf.size() - start)) return false;
		const size_t limit = symbol_size ? symbol_size : file_buf.size() - start;
		if (limit > 0x10000 * 4) return false;

		csh handle;
		cs_err err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			return false;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

		cs_insn* insn = cs_malloc(handle);
		if (!insn) {
			printf("Failed to allocate Capstone instruction object.\n");
			cs_close(&handle);
			return false;
		}

		uint64_t address = 0;
		const uint8_t* code = reinterpret_cast<const uint8_t*>(file_buf.data()) + start;
		size_t file_size = limit;

		std::vector<code_line> v_code_line;
		v_code_line.reserve(100);

		while (cs_disasm_iter(handle, &code, &file_size, &address, insn)) {
			if (!insn->id || !insn->detail || insn->size != 4) break;
			code_line line;
			line.addr = insn->address;
			line.cmd_id = static_cast<arm64_insn>(insn->id);
			line.cc_id = insn->detail->arm64.cc;

			for (int y = 0; y < insn->detail->arm64.op_count; ++y) {
				if (insn->detail->arm64.operands[y].type == ARM64_OP_IMM) {
					line.final_imm = insn->detail->arm64.operands[y].imm;
					line.has_imm = true;
				}
			}
			line.unsupported_jump = (cs_insn_group(handle, insn, CS_GRP_JUMP) &&
				!cs_insn_group(handle, insn, CS_GRP_CALL) && !is_offset_jump_asm(line)) ||
				cs_insn_group(handle, insn, CS_GRP_IRET) || cs_insn_group(handle, insn, CS_GRP_INT) ||
				line.cmd_id == ARM64_INS_ERET || line.cmd_id == ARM64_INS_ERETAA ||
				line.cmd_id == ARM64_INS_ERETAB || line.cmd_id == ARM64_INS_DRPS ||
				line.cmd_id == ARM64_INS_BRK || line.cmd_id == ARM64_INS_HLT;
			if (line.cmd_id == ARM64_INS_BL && line.has_imm) {
				const int64_t target = static_cast<int64_t>(start) + line.final_imm;
				line.noreturn_call = target >= 0 && noreturn_targets.count(static_cast<uint64_t>(target));
			}

			v_code_line.push_back(line);
		}

		const bool res = handle_candidate_offsets(v_code_line, candidate_offsets, limit);
		cs_free(insn, 1);
		cs_close(&handle);
		return res;
	}

} // namespace a64_find_end_func_offset
