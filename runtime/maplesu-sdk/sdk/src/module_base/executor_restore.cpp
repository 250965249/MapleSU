// executor restore implementation.
//
#include <cstddef>
#include <cstdint>

#include "private_module_base_kernel_func_executor.h"

namespace {

// 232 字节常量表：一条完整的"内核态汇编函数"模板（58 条 AArch64 指令）。
//
// 它其实就是作者用 part1 的 arm64_module_asm_func_start / _end 预先汇编出来的：
//   字 0        d503245f  bti c                        <- start() 开头 embed 的帧头指令
//   字 1..5     a9bf53f3 a9bf5bf5 a9bf63f7 a9bf6bf9 a9bf73fb
//               stp x19,x20 / x21,x22 / x23,x24 / x25,x26 / x27,x28, [sp,#-16]!
//   字 6..8     f844416a b9404d6c b940516d
//               ldr x10,[x11,#0x44] / ldr w12,[x11,#0x4c] / ldr w13,[x11,#0x50]
//   字 9..11    a9bf33ea a9bf47ed a9bf7bfd
//               stp x10,x12 / x13,x17 / x29,x30, [sp,#-16]!
//   字 12       14000011  b <+0x44>（跨过 64 字节 begin 标记）
//   字 13..28   "05YWtaGvdCvO80RRK5wuYlPiP5khll8YcJ4P2zGL53FIK9VG3EJGBY20vkCz1kO\0"
//               begin 帧标记（与 part1 的 aarch64_my_frame_begin_flag 逐字节相同）
//   字 29       movz w10, #<securebits 低 16 位>      <- 占位 movz w10, #0x1234，运行时改写
//   字 30       movk w10, #<securebits 高 16 位>,lsl16 <- 占位 movk w10, #0，运行时改写
//   字 31       b9001a2a  str w10,[x17,#0x18]        （把 securebits 写进内核回信区 +24）
//   字 32       14000011  b <+0x44>（跨过 64 字节 end 标记）
//   字 33..48   "CtAjGglsdr80qLTmGyaXMBMorEA9tc2Mll62TwcifS6CujoERzZJVwtQtl3X20C\0"
//               end_no_ret 帧标记（与 part1 的同名常量逐字节相同）
//   字 49..57   a8c17bfd a8c147ed a8c133ea a8c173fb a8c16bf9 a8c163f7 a8c15bf5 a8c153f3 d65f03c0
//               ldp x29,x30 / x13,x17 / x10,x12 / x27,x28 / x25,x26 / x23,x24 / x21,x22 / x19,x20 ; ret
//
// 注意：字 13..28 / 33..48 是上面两个 64 字节 ASCII 标记按 little-endian 每 4 字节
// 打包的结果，不是手写的魔数（编译期由 static_assert 抽查关键字的拼接）。
constexpr uint32_t kSecurebitsPayload[] = {
    0xD503245FU, 0xA9BF53F3U, 0xA9BF5BF5U, 0xA9BF63F7U, 0xA9BF6BF9U, 0xA9BF73FBU,
    0xF844416AU, 0xB9404D6CU, 0xB940516DU,
    0xA9BF33EAU, 0xA9BF47EDU, 0xA9BF7BFDU,
    0x14000011U,
    // "05YW" "taGv" "dCvO" "80RR" "K5wu" "YlPi" "P5kh" "ll8Y"
    0x57593530U, 0x76476174U, 0x4F764364U, 0x52523038U,
    0x7577354BU, 0x69506C59U, 0x686B3550U, 0x59386C6CU,
    // "cJ4P" "2zGL" "53FI" "K9VG" "3EJG" "BY20" "vkCz" "1kO\0"
    0x50344A63U, 0x4C477A32U, 0x49463335U, 0x4756394BU,
    0x474A4533U, 0x30325942U, 0x7A436B76U, 0x004F6B31U,
    // 占位：movz w10, #0x1234 / movk w10, #0, lsl #16（运行时被改写为真实 securebits）
    0x5282468AU, 0x72A0000AU,
    0xB9001A2AU,   // str w10,[x17,#0x18]
    0x14000011U,
    // "CtAj" "Ggls" "dr80" "qLTm" "GyaX" "MBMo" "rEA9" "tc2M"
    0x6A417443U, 0x736C6747U, 0x30387264U, 0x6D544C71U,
    0x58617947U, 0x6F4D424DU, 0x39414572U, 0x4D326374U,
    // "ll62" "Twci" "fS6C" "ujoE" "RzZJ" "VwtQ" "tl3X" "20C\0"
    0x32366C6CU, 0x69637754U, 0x43365366U, 0x456F6A75U,
    0x4A5A7A52U, 0x51747756U, 0x58336C74U, 0x00433032U,
    // ldp x29,x30 / x13,x17 / x10,x12 / x27,x28 / x25,x26 / x23,x24 / x21,x22 / x19,x20 ; ret
    0xA8C17BFDU, 0xA8C147EDU, 0xA8C133EAU, 0xA8C173FBU,
    0xA8C16BF9U, 0xA8C163F7U, 0xA8C15BF5U, 0xA8C153F3U,
    0xD65F03C0U,
};

constexpr size_t kPayloadWordCount = sizeof(kSecurebitsPayload) / sizeof(uint32_t);

// securebits 的两个立即数补丁位置（字节偏移 0x74 / 0x78，即字 29 / 30）。
constexpr size_t kPatchWordLo = 0x74 / sizeof(uint32_t);  // 29：movz w10, #lo16
constexpr size_t kPatchWordHi = 0x78 / sizeof(uint32_t);  // 30：movk w10, #hi16, lsl 16

// 两条 mov-immediate 指令的固定编码位；imm16 字段在 bit[5..20]。
constexpr uint32_t kMovzW10 = 0x5280000AU;       // movz  w10, #imm16
constexpr uint32_t kMovkW10Lsl16 = 0x72A0000AU;  // movk  w10, #imm16, lsl #16
constexpr uint32_t kImm16Shift = 5;

static_assert(kSecurebitsPayload[0] == 0xD503245FU, "payload[0] 必须是帧头 bti c");
static_assert(kSecurebitsPayload[12] == 0x14000011U, "payload[12] 必须跨过 begin 标记");
static_assert(kSecurebitsPayload[32] == 0x14000011U, "payload[32] 必须跨过 end 标记");
static_assert(kSecurebitsPayload[31] == 0xB9001A2AU, "payload[31] 必须是 str w10,[x17,#0x18]");
static_assert(kSecurebitsPayload[kPayloadWordCount - 1] == 0xD65F03C0U,
              "payload 最后一条必须是 ret");
static_assert(kPayloadWordCount == 58, "232 字节 = 58 条指令");
static_assert((kMovzW10 & (0xFFFFU << kImm16Shift)) == 0U, "movz 立即数字段必须为空");
static_assert((kMovkW10Lsl16 & (0xFFFFU << kImm16Shift)) == 0U, "movk 立即数字段必须为空");

}  // namespace

// maplesu_restore_securebits —— 用内核执行通道把 securebits 写回。
extern "C" KModErr maplesu_restore_securebits(uint32_t securebits) {
    // 1) 复制模板（[A] +0x8c8..+0x8ec：4 字节步进、共 0xE8 字节）
    uint32_t payload[kPayloadWordCount];
    for (size_t i = 0; i < kPayloadWordCount; ++i) {
        payload[i] = kSecurebitsPayload[i];
    }

    // 2) 把 securebits 的 16 位立即数补进 movz / movk（[A] +0x8f0..+0x908）
    payload[kPatchWordLo] = kMovzW10 | ((securebits & 0xFFFFU) << kImm16Shift);
    payload[kPatchWordHi] = kMovkW10Lsl16 | ((securebits >> 16) << kImm16Shift);

    // 3) 交给裸执行入口（[A] +0x914/+0x918/+0x920）
    uint64_t output_result = 0;
    return maplesu_raw_execute(reinterpret_cast<const uint8_t*>(payload),
                               static_cast<uint32_t>(sizeof(payload)),
                               output_result);
}
