// Frozen fork/pipe entry names; every body forwards to the MapleSU transport.
#pragma once

#include "fork_legacy_abi.h"

namespace maplesu::compat::fork_legacy {
using maplesu::sdk::fork_pipe_info;

// The frozen ABI passes the same 24-byte descriptor by reference. Explicit
// labels retain its old namespace spelling without duplicating its type/state.
bool fork_pipe_child_process(fork_pipe_info& pipe)
    asm("_ZN10skroot_env23fork_pipe_child_processERNS_14fork_pipe_infoE");

bool write_bool_from_child(const fork_pipe_info& pipe, bool value)
    asm("_ZN10skroot_env21write_bool_from_childERKNS_14fork_pipe_infoEb");

bool read_bool_from_child(const fork_pipe_info& pipe, bool& out_value)
    asm("_ZN10skroot_env20read_bool_from_childERKNS_14fork_pipe_infoERb");

bool write_int_from_child(const fork_pipe_info& pipe, int value)
    asm("_ZN10skroot_env20write_int_from_childERKNS_14fork_pipe_infoEi");

bool read_int_from_child(const fork_pipe_info& pipe, int& out_value)
    asm("_ZN10skroot_env19read_int_from_childERKNS_14fork_pipe_infoERi");

bool write_uint64_from_child(const fork_pipe_info& pipe, uint64_t value)
    asm("_ZN10skroot_env23write_uint64_from_childERKNS_14fork_pipe_infoEm");

bool read_uint64_from_child(const fork_pipe_info& pipe, uint64_t& out_value)
    asm("_ZN10skroot_env22read_uint64_from_childERKNS_14fork_pipe_infoERm");

bool write_errcode_from_child(const fork_pipe_info& pipe, KModErr err)
    asm("_ZN10skroot_env24write_errcode_from_childERKNS_14fork_pipe_infoE7KModErr");

bool read_errcode_from_child(const fork_pipe_info& pipe, KModErr& out_err)
    asm("_ZN10skroot_env23read_errcode_from_childERKNS_14fork_pipe_infoER7KModErr");

bool write_transfer_data_from_child(const fork_pipe_info& pipe, const std::vector<uint8_t>& data)
    asm("_ZN10skroot_env30write_transfer_data_from_childERKNS_14fork_pipe_infoERKNSt6__ndk16vectorIhNS3_9allocatorIhEEEE");

bool read_transfer_data_from_child(fork_pipe_info& pipe, std::vector<uint8_t>& out_data)
    asm("_ZN10skroot_env29read_transfer_data_from_childERNS_14fork_pipe_infoERNSt6__ndk16vectorIhNS2_9allocatorIhEEEE");

bool write_string_from_child(const fork_pipe_info& pipe, const std::string& text)
    asm("_ZN10skroot_env23write_string_from_childERKNS_14fork_pipe_infoERKNSt6__ndk112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE");

bool read_string_from_child(fork_pipe_info& pipe, std::string& out_text)
    asm("_ZN10skroot_env22read_string_from_childERNS_14fork_pipe_infoERNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE");

bool write_set_int_from_child(const fork_pipe_info& pipe, const std::set<int>& values)
    asm("_ZN10skroot_env24write_set_int_from_childERKNS_14fork_pipe_infoERKNSt6__ndk13setIiNS3_4lessIiEENS3_9allocatorIiEEEE");

bool read_set_int_from_child(fork_pipe_info& pipe, std::set<int>& out_values)
    asm("_ZN10skroot_env23read_set_int_from_childERNS_14fork_pipe_infoERNSt6__ndk13setIiNS2_4lessIiEENS2_9allocatorIiEEEE");

bool write_set_string_from_child(const fork_pipe_info& pipe, const std::set<std::string>& values)
    asm("_ZN10skroot_env27write_set_string_from_childERKNS_14fork_pipe_infoERKNSt6__ndk13setINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS3_4lessISA_EENS8_ISA_EEEE");

bool read_set_string_from_child(fork_pipe_info& pipe, std::set<std::string>& out_values)
    asm("_ZN10skroot_env26read_set_string_from_childERNS_14fork_pipe_infoERNSt6__ndk13setINS2_12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEENS2_4lessIS9_EENS7_IS9_EEEE");

bool write_map_i_s_from_child(const fork_pipe_info& pipe,
                              const std::map<int, std::string>& values)
    asm("_ZN10skroot_env24write_map_i_s_from_childERKNS_14fork_pipe_infoERKNSt6__ndk13mapIiNS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS3_4lessIiEENS8_INS3_4pairIKiSA_EEEEEE");

bool read_map_i_s_from_child(fork_pipe_info& pipe, std::map<int, std::string>& out_values)
    asm("_ZN10skroot_env23read_map_i_s_from_childERNS_14fork_pipe_infoERNSt6__ndk13mapIiNS2_12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEENS2_4lessIiEENS7_INS2_4pairIKiS9_EEEEEE");

bool write_map_s_i_from_child(const fork_pipe_info& pipe,
                              const std::map<std::string, int>& values)
    asm("_ZN10skroot_env24write_map_s_i_from_childERKNS_14fork_pipe_infoERKNSt6__ndk13mapINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEiNS3_4lessISA_EENS8_INS3_4pairIKSA_iEEEEEE");

bool read_map_s_i_from_child(fork_pipe_info& pipe, std::map<std::string, int>& out_values)
    asm("_ZN10skroot_env23read_map_s_i_from_childERNS_14fork_pipe_infoERNSt6__ndk13mapINS2_12basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEEiNS2_4lessIS9_EENS7_INS2_4pairIKS9_iEEEEEE");

} // namespace maplesu::compat::fork_legacy
