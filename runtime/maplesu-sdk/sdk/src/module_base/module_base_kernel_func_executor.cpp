// module base kernel func executor implementation.
//
#include "kernel_module_kit_umbrella.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

#include <sys/prctl.h>

#include "module_base_kernel_func_executor.h"
#include "module_base_kernel_request.h"
#include "maplesu_request_private.h"
#include "private_module_base_kernel_func_executor.h"

// 三个 64 字节帧标记。
//     也让 with_buf 里 std::search 的迭代器类型退化为 `char*`（见下）。
// 安装 hook 后，执行器靠它们在目标机器码里定位"本模块生成的帧"。
static char aarch64_my_frame_begin_flag[64] =
    "05YWtaGvdCvO80RRK5wuYlPiP5khll8YcJ4P2zGL53FIK9VG3EJGBY20vkCz1kO";
static char aarch64_my_frame_end_no_ret_flag[64] =
    "CtAjGglsdr80qLTmGyaXMBMorEA9tc2Mll62TwcifS6CujoERzZJVwtQtl3X20C";
static char aarch64_my_frame_end_ret_flag[64] =
    "7Cj4G79IYh5P9GpIBTMeLZsN1YBaylVD77IsAPgfnEhuWn8MGqEd8eBpEcmDoo5";

// is_my_kernel_frame_func —— 判断一段机器码是不是"本模块生成的函数"。
//
//     含 begin 标记                       （否则 false）
//  且 含 end_no_ret 标记 或 end_ret 标记   （否则 false）
//
//   _ZL23is_my_kernel_frame_funcPKvj
//   _ZZL23is_my_kernel_frame_funcPKvjENK3$_0clEPKcm
// 所以它必须是"全局命名空间里的 static 函数"，不能放进 namespace kernel_module，
// 也不能放进匿名命名空间（否则 mangling 会带 _ZN13kernel_module12_GLOBAL__N_1）。
static bool is_my_kernel_frame_func(const void* void_buf, uint32_t size) {
    const char* begin = static_cast<const char*>(void_buf);
    const char* end = begin + size;

    // 在 [begin, end) 里找长度为 flag_len 的标记；找不到时 std::search 返回 end。
    auto contains = [&](const char* flag, size_t flag_len) -> bool {
        return std::search(begin, end, flag, flag + flag_len) != end;
    };

    if (!contains(aarch64_my_frame_begin_flag, sizeof(aarch64_my_frame_begin_flag))) {
        return false;
    }
    if (contains(aarch64_my_frame_end_no_ret_flag,
                 sizeof(aarch64_my_frame_end_no_ret_flag))) {
        return true;
    }
    return contains(aarch64_my_frame_end_ret_flag,
                    sizeof(aarch64_my_frame_end_ret_flag));
}

namespace kernel_module {

namespace {
constexpr uint32_t standard_prefix[] = {
    0xd503245f, 0xa9bf53f3, 0xa9bf5bf5, 0xa9bf63f7,
    0xa9bf6bf9, 0xa9bf73fb, 0xa9bf7bfd, 0x14000005,
};
bool standard_frame(const uint8_t* bytes, uint32_t size) {
    return maplesu_standard_frame_valid(bytes, size) != 0;
}

bool standard_candidate(const uint8_t* bytes, uint32_t size) {
    if (size < 36) return false;
    uint32_t magic = 0;
    std::memcpy(&magic, bytes + 32, sizeof(magic));
    return magic == maplesu_frame::magic ||
        !std::memcmp(bytes, standard_prefix, sizeof(standard_prefix) - 4);
}
}

// __exec_kernel_asm_func —— 真正把机器码送进内核执行的私有实现。
//
// 旧回执控制流：
//   1) request_kernel_alloc_mem(size)                    失败 -> 直接返回
//   2) unsafe_request_kernel_write_mem(kaddr, buf, size) 失败 -> maplesu_release_staging(kaddr) 后返回
//   3) unsafe_request_kernel_exec_mem(kaddr, size, reply) 失败 -> 直接返回（staging 交由内核侧回收）
//   4) prctl(PR_GET_SECUREBITS) 失败 -> CRED_DANGER，不发布输出或重放
//   5) 回填 output_result = { reply[1..6], securebits[0..1] }（字节布局见下）
//
//   ldur  w8, [sp, #0x9]   ; reply 字节 1..4
//   strh  w0, [x19, #0x6]  ; securebits 低 16 位 -> out[6..7]
//   ldurh w9, [sp, #0xd]   ; reply 字节 5..6
//   str   w8, [x19]        ; out[0..3]
//   strh  w9, [x19, #0x4]  ; out[4..5]
// 即输出 8 字节 = reply[1..6]（6 字节返回值） + securebits 低 16 位。
static KModErr __exec_kernel_asm_func(const uint8_t* func_bytes, uint32_t size,
                                      uint64_t& output_result, bool* execution_attempted = nullptr) {
    if (execution_attempted) *execution_attempted = false;
    uint64_t kaddr = 0;
    KModErr err = request_kernel_alloc_mem(size, kaddr);
    if (err != KModErr::OK) {
        return err;
    }

    err = unsafe_request_kernel_write_mem(kaddr, func_bytes, size);
    if (err != KModErr::OK) {
        // 写入失败：staging 页由调用方释放，避免泄漏（[A] +0x66c bl maplesu_release_staging）。
        CleanupReceiptScope preserve_failure;
        maplesu_release_staging(kaddr);
        return err;
    }

    uint64_t reply = 0;
    if (execution_attempted) *execution_attempted = true;
    err = unsafe_request_kernel_exec_mem(kaddr, size, reply);
    if (err != KModErr::OK) {
        return err;
    }

    // 执行成功后内核把返回值放在 reply 的字节 1..6；securebits 由本进程补在末尾。
    const int securebits = prctl(PR_GET_SECUREBITS);
    if (securebits < 0) return KModErr::ERR_MODULE_CRED_DANGER;

#pragma pack(push, 1)
    struct ExecResult {
        uint32_t value_lo;   // reply 字节 1..4
        uint16_t value_hi;   // reply 字节 5..6
        uint16_t securebits; // securebits 低 16 位
    };
#pragma pack(pop)
    static_assert(sizeof(ExecResult) == 8, "ExecResult 必须是 8 字节（回填 ABI）");

    ExecResult result;
    __builtin_memcpy(&result.value_lo,
                     reinterpret_cast<const uint8_t*>(&reply) + 1,
                     sizeof(result.value_lo) + sizeof(result.value_hi));
    result.securebits = static_cast<uint16_t>(securebits);
    output_result = 0;
    __builtin_memcpy(&output_result, &result, sizeof(result));
    return KModErr::OK;
}

// execute_kernel_asm_func_with_buf —— 公开入口（被 m024/m029 等成员以 U 引用）。
//
//
//
// 失败码实测（枚举值见 include/module_err_def.h）：
//   size==0 或 size%4!=0                -> ERR_MODULE_ASM            (-19990)
//   buf==nullptr / size<64 / 帧不合法   -> ERR_MODULE_FUNC_NOT_STANDARD (-19989)
static KModErr execute_legacy_frame(const uint8_t* func_bytes, uint32_t size,
                                    uint64_t& output_result) {
    const char* begin = reinterpret_cast<const char*>(func_bytes);
    const char* end = begin + size;

    // 命中 end_ret 说明该函数会回写返回值 -> 必须先把 securebits 换回来。
    if (std::search(begin, end, aarch64_my_frame_end_ret_flag,
                    aarch64_my_frame_end_ret_flag +
                        sizeof(aarch64_my_frame_end_ret_flag)) == end) {
        return __exec_kernel_asm_func(func_bytes, size, output_result);
    }

    // 走"带返回值"的帧：执行期间内核会改掉 suid/sgid/securebits。
    // 快照失败时不创建会在析构中发送恢复请求的旧回执守卫。
    const int securebits = prctl(PR_GET_SECUREBITS);
    if (securebits < 0) return KModErr::ERR_MODULE_CRED_DANGER;
    SuidSgidGuard guard;
    if (guard.status() != KModErr::OK) return guard.status();
    uint64_t candidate_result = 0;
    bool execution_attempted = false;
    KModErr err = __exec_kernel_asm_func(func_bytes, size, candidate_result, &execution_attempted);
    int first_errno = errno;
    // A failed receipt or post-execution PR_GET_SECUREBITS does not prove that
    // the old binary's result frame left securebits unchanged. Restore only
    // this saved field, never replay the requested function.
    if (execution_attempted) {
        const KModErr securebits_error = maplesu_restore_securebits(static_cast<uint32_t>(securebits));
        if (err == KModErr::OK && securebits_error != KModErr::OK) {
            err = securebits_error;
            first_errno = errno;
        }
    }
    const KModErr restore_error = guard.restore();
    if (err == KModErr::OK && restore_error != KModErr::OK) {
        err = restore_error;
        first_errno = errno;
    }
    if (err == KModErr::OK) output_result = candidate_result;
    else errno = first_errno;
    return err;
}

static KModErr execute_standard_on_legacy(const uint8_t* bytes, uint32_t size,
                                          uint64_t& output_result) {
    auto context = init_aarch64_asm();
    auto* a = context.assembler();
    maplesu_legacy_asm_func_start(a);
    const auto callback = a->newLabel();
    a->bl(callback);
    maplesu_legacy_asm_func_end(a, x0);
    a->bind(callback);
    if (a->offset() > std::numeric_limits<uint32_t>::max() ||
        size > std::numeric_limits<uint32_t>::max() - a->offset()) return KModErr::ERR_MODULE_ASM;
    a->embed(bytes, size);
    const auto code = aarch64_asm_to_bytes(a);
    if (context.has_error() || code.empty()) return KModErr::ERR_MODULE_ASM;
    return execute_legacy_frame(code.data(), static_cast<uint32_t>(code.size()), output_result);
}

KModErr maplesu_execute_legacy_credential_frame(const uint8_t* bytes, uint32_t size,
                                               uint64_t& result) {
    if (maplesu_request_owner_mode()) return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    if (!bytes || size < 64 || (size & 3U) || reinterpret_cast<uintptr_t>(bytes) >
        std::numeric_limits<uintptr_t>::max() - size || !standard_frame(bytes, size))
        return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    const auto error = maplesu_request_key_credential_begin();
    if (is_failed(error)) return error;
    uint64_t candidate = 0;
    KModErr execution_error;
    try { execution_error = execute_standard_on_legacy(bytes, size, candidate); }
    catch (const std::bad_alloc&) { execution_error = KModErr::ERR_NO_MEM; }
    const auto completed = maplesu_request_key_credential_end(execution_error);
    if (is_ok(completed)) result = candidate;
    return completed;
}

KModErr execute_kernel_asm_func_with_buf(const uint8_t* func_bytes, uint32_t size,
                                        uint64_t& output_result) {
    if (size == 0 || (size & 3U) != 0) return KModErr::ERR_MODULE_ASM;
    if (!func_bytes || size < 64 || reinterpret_cast<uintptr_t>(func_bytes) >
        std::numeric_limits<uintptr_t>::max() - size) return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    if (standard_candidate(func_bytes, size)) {
        if (!standard_frame(func_bytes, size)) return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
        if (maplesu_request_owner_mode())
            return maplesu_request_owner_execute(func_bytes, size, output_result);
        bool supported = false;
        const auto error = maplesu_request_key_execute(func_bytes, size, output_result, supported);
        if (is_failed(error) || supported) return error;
        // One compatibility adapter preserves old binaries' credential receipt.
        try {
            return execute_standard_on_legacy(func_bytes, size, output_result);
        } catch (const std::bad_alloc&) {
            return KModErr::ERR_NO_MEM;
        }
    }
    if (maplesu_request_owner_mode()) return KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
    return is_my_kernel_frame_func(func_bytes, size)
        ? execute_legacy_frame(func_bytes, size, output_result)
        : KModErr::ERR_MODULE_FUNC_NOT_STANDARD;
}

}  // namespace kernel_module

// maplesu_raw_execute —— 不装 guard 的裸执行入口。
//   714: 17ffffc0  b 0x614 <_ZN13kernel_moduleL22__exec_kernel_asm_funcEPKhjRm>
// 是一条纯尾调用，因此它只能定义在本 TU（__exec_kernel_asm_func 是内部链接）。
extern "C" KModErr maplesu_raw_execute(const uint8_t* func_bytes, uint32_t size,
                                       uint64_t& output_result) {
    if (kernel_module::maplesu_request_owner_mode())
        return kernel_module::execute_kernel_asm_func_with_buf(func_bytes, size, output_result);
    return kernel_module::__exec_kernel_asm_func(func_bytes, size, output_result);
}

// 以下三个函数是"内核态汇编函数模板"的组装器（asmjit 逐指令生成）。
// 指令级一致性另有 [C]（part2 的 232 字节预汇编表）逐字节佐证。
// 每个函数都只负责"往 Assembler 里发指令"，不产生运行期副作用。
namespace kernel_module {

// arm64_module_asm_func_start —— 函数入口帧
//   2) 保存 x19~x28（5 组 stp，sp 预减 16）
//   3) 从 x11 指向的"调用方上下文"取回 x10 / w12 / w13（偏移 68 / 76 / 80）
//   4) 再压入 {x10,x12} / {x13,x17} / {x29,x30}
//   5) 结束标记：b <end> ; embed(begin_flag,64) ; end:
//      —— 这段只是把 64 字节标记"绕过"正常执行流塞进代码里，
//         供 is_my_kernel_frame_func 在机器码中搜索。
void maplesu_legacy_asm_func_start(Assembler* a) {
    const uint32_t frame_head_insn = 0xD503245Fu;
    a->embed(&frame_head_insn, sizeof(frame_head_insn));

    a->stp(x19, x20, ptr(sp, -16).pre());
    a->stp(x21, x22, ptr(sp, -16).pre());
    a->stp(x23, x24, ptr(sp, -16).pre());
    a->stp(x25, x26, ptr(sp, -16).pre());
    a->stp(x27, x28, ptr(sp, -16).pre());

    a->ldr(x10, ptr(x11, 68));
    a->ldr(w12, ptr(x11, 76));
    a->ldr(w13, ptr(x11, 80));

    a->stp(x10, x12, ptr(sp, -16).pre());
    a->stp(x13, x17, ptr(sp, -16).pre());
    a->stp(x29, x30, ptr(sp, -16).pre());

    Label frame_begin_label = a->newLabel();
    a->b(frame_begin_label);
    a->embed(aarch64_my_frame_begin_flag, sizeof(aarch64_my_frame_begin_flag));
    a->bind(frame_begin_label);
}

// arm64_module_asm_func_end —— 函数出口（无返回值）
//   1) 结束标记：b <end> ; embed(end_no_ret_flag, 64) ; end:
//   2) 逆序恢复：x29/x30, x13/x17, x10/x12, x27/x28 ... x19/x20（8 组 ldp，sp 后加 16）
//   3) ret x30
void maplesu_legacy_asm_func_end(Assembler* a) {
    Label frame_end_label = a->newLabel();
    a->b(frame_end_label);
    a->embed(aarch64_my_frame_end_no_ret_flag,
             sizeof(aarch64_my_frame_end_no_ret_flag));
    a->bind(frame_end_label);

    a->ldp(x29, x30, ptr(sp, 16).post());
    a->ldp(x13, x17, ptr(sp, 16).post());
    a->ldp(x10, x12, ptr(sp, 16).post());
    a->ldp(x27, x28, ptr(sp, 16).post());
    a->ldp(x25, x26, ptr(sp, 16).post());
    a->ldp(x23, x24, ptr(sp, 16).post());
    a->ldp(x21, x22, ptr(sp, 16).post());
    a->ldp(x19, x20, ptr(sp, 16).post());
    a->ret(x30);
}

// arm64_module_asm_func_end(Assembler*, GpX) —— 函数出口（带返回值）
//     * 用 end_ret_flag 而不是 end_no_ret_flag；
//     * 先把返回值 mov 进 x0；
//     * 在恢复 x10/x12 之后，把返回值按 {0, w0, x0>>32, x0>>48} 的形状写进
//       x17 指向的"内核回信区"（out+0 / +1 / +5，然后 x17 += 24 再写 +0 / +0），
//       供 __exec_kernel_asm_func 读回结果；
//     * 之后才是 x27...x19 的恢复与 ret。
void maplesu_legacy_asm_func_end(Assembler* a, GpX return_x) {
    Label frame_end_label = a->newLabel();
    a->b(frame_end_label);
    a->embed(aarch64_my_frame_end_ret_flag,
             sizeof(aarch64_my_frame_end_ret_flag));
    a->bind(frame_end_label);

    a->mov(x0, return_x);

    a->ldp(x29, x30, ptr(sp, 16).post());
    a->ldp(x13, x17, ptr(sp, 16).post());
    a->ldp(x10, x12, ptr(sp, 16).post());

    a->str(xzr, ptr(x17, 0));
    a->str(w0, ptr(x17, 1));
    a->lsr(x1, x0, Imm(32));
    a->strh(w1, ptr(x17, 5));
    a->add(x17, x17, Imm(24));
    a->str(wzr, ptr(x17, 0));
    a->lsr(x1, x0, Imm(48));
    a->strh(w1, ptr(x17, 0));

    a->ldp(x27, x28, ptr(sp, 16).post());
    a->ldp(x25, x26, ptr(sp, 16).post());
    a->ldp(x23, x24, ptr(sp, 16).post());
    a->ldp(x21, x22, ptr(sp, 16).post());
    a->ldp(x19, x20, ptr(sp, 16).post());
    a->ret(x30);
}

void arm64_module_asm_func_start(Assembler* a) {
    const uint32_t bti = 0xd503245f;
    a->embed(&bti, sizeof(bti));
    a->stp(x19, x20, ptr(sp, -16).pre());
    a->stp(x21, x22, ptr(sp, -16).pre());
    a->stp(x23, x24, ptr(sp, -16).pre());
    a->stp(x25, x26, ptr(sp, -16).pre());
    a->stp(x27, x28, ptr(sp, -16).pre());
    a->stp(x29, x30, ptr(sp, -16).pre());
    const auto body = a->newLabel();
    a->b(body);
    const auto marker = maplesu_frame::marker(maplesu_frame::Kind::Begin);
    a->embed(&marker, sizeof(marker));
    a->bind(body);
}

static void standard_frame_end(Assembler* a, GpX result, maplesu_frame::Kind kind) {
    const auto finish = a->newLabel();
    a->b(finish);
    const auto marker = maplesu_frame::marker(kind);
    a->embed(&marker, sizeof(marker));
    a->bind(finish);
    a->mov(x0, result);
    a->ldp(x29, x30, ptr(sp, 16).post());
    a->ldp(x27, x28, ptr(sp, 16).post());
    a->ldp(x25, x26, ptr(sp, 16).post());
    a->ldp(x23, x24, ptr(sp, 16).post());
    a->ldp(x21, x22, ptr(sp, 16).post());
    a->ldp(x19, x20, ptr(sp, 16).post());
    a->ret(x30);
}

void arm64_module_asm_func_end(Assembler* a) {
    standard_frame_end(a, xzr, maplesu_frame::Kind::Void);
}

void arm64_module_asm_func_end(Assembler* a, GpX return_x) {
    standard_frame_end(a, return_x, maplesu_frame::Kind::U64);
}

}  // namespace kernel_module
