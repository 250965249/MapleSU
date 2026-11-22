// private module base kernel func executor implementation.
//
#pragma once

#include <stdint.h>
#include <algorithm>

#include "module_err_def.h"
#include "aarch64_asm_helper.h"
#include "../../../ultra/authorization/execution_frame.h"

namespace kernel_module {

namespace maplesu_frame {
inline constexpr uint32_t magic = MAPLESU_FRAME_MAGIC;
inline constexpr uint16_t version = MAPLESU_FRAME_VERSION;
enum class Kind : uint32_t { Begin = 1, Void = 2, U64 = 3 };
struct Marker {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
    Kind kind;
    uint32_t reserved;
};
static_assert(sizeof(Marker) == 16, "frame marker ABI");
inline constexpr Marker marker(Kind kind) {
    return {magic, version, sizeof(Marker), kind, 0};
}
}

// Only the legacy LR locators and the single outer adapter use this ABI.
void maplesu_legacy_asm_func_start(asmjit::a64::Assembler* a);
void maplesu_legacy_asm_func_end(asmjit::a64::Assembler* a);
void maplesu_legacy_asm_func_end(asmjit::a64::Assembler* a, asmjit::a64::GpX result);

// 在内核态执行一段"带本模块帧标记"的 AArch64 机器码。
// 与公开的 execute_kernel_asm_func(vector) 的差别：这里直接吃裸缓冲区。
KModErr execute_kernel_asm_func_with_buf(const uint8_t* func_bytes,
                                         uint32_t size,
                                         uint64_t& output_result);

}  // namespace kernel_module

extern "C" {

// 不安装 SuidSgidGuard、不还原 securebits 的裸执行入口（调用者自理 cred）。
KModErr maplesu_raw_execute(const uint8_t* func_bytes, uint32_t size,
                            uint64_t& output_result);

// 把 securebits 通过内核执行通道写回（part2 = executor_restore.cpp）。
KModErr maplesu_restore_securebits(uint32_t securebits);

}  // extern "C"

// 实参是 request_kernel_alloc_mem 返回的内核地址，返回值为通道错误码。
extern "C" int64_t maplesu_release_staging(uint64_t address);
