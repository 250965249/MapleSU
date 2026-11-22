// module min sdk implementation.
//
#include "maplesu/compat/native_module_abi.h"
#include "kernel_module_kit_umbrella.h"

#include <time.h>

namespace {

// 编译期最低支持 SDK 版本标记。
//
// 结构与 private_desc_parser.h 的 ___MOD_* 标记同构：
//   <64 hex tag_begin> + <版本文本> + <64 hex tag_end>
// 因此版本文本实测为 "4.3.7"（64+5+64 = 133）。
//
// 【推断，非实测】产生该标记的宏（形如 ___MOD_MIN_SDK_VER("4.3.7")）不在
// 随包头文件树里（runtime/maplesu-sdk/include 无此定义），所以这里把标记
// 文本，不依赖宏名。
#define MAPLE_MIN_SUPPORT_SDK_VER_MARKER                     \
    MAPLESU_MODULE_MINIMUM_SDK_TAG_BEGIN \
    "4.3.7"                                                  \
    MAPLESU_MODULE_MINIMUM_SDK_TAG_END

// 返回最低支持 SDK 版本标记。
//   _ZZL35get_module_min_support_sdk_ver_flagvE7min_ver
// 即“static 函数 get_module_min_support_sdk_ver_flag 内的 static 变量 min_ver”，
// 所以这里必须保持同样的嵌套形态（mangling 也是 ABI）。
const char* get_module_min_support_sdk_ver_flag() {
    static char min_ver[] = MAPLE_MIN_SUPPORT_SDK_VER_MARKER;
    return min_ver;
}

}  // namespace

//   define hidden void @__compile_save_min_support_sdk_ver() {
//     %1 = load i1, ptr @_ZZ34__compile_save_min_support_sdk_verE8is_first
//     br i1 %1, label %5, label %2
//   2: store i1 true, ptr @…is_first
//      %3 = tail call i64 @time(ptr null)
//      %4 = tail call i64 @__strlen_chk(ptr @…min_ver, i64 134)
//   5: ret void
//   }
//
// 实测语义：每次进程内只走一次“首次”分支；首次分支做两件事——
//   * time(nullptr)：取一次当前时间；
//   * strlen(标记)：校验标记非空。
// 下把校验结果丢掉了（release 断言/日志被裁掉）。为了不臆造行为，这里保持
// 同样的“调用但丢弃结果”，并把“为什么要调”写清楚：
//   - time() 让该 TU 保留一条可被 LTO 观察到的“首次执行时间点”调用；
//   - strlen() 保住对标记的引用（否则 -Oz 会把 min_ver 当死数据删掉，
//     安装器就再也读不到 4.3.7 这个下限）。
extern "C" void __compile_save_min_support_sdk_ver() {
    static bool is_first = false;
    if (is_first) {
        return;
    }
    is_first = true;

    (void)time(nullptr);

    const char* ver_flag = get_module_min_support_sdk_ver_flag();
    (void)strlen(ver_flag);
}
