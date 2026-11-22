// MapleSU installer implementation.
//
#include <cstdio>

// maplesu_installer.h 依赖 KModErr，但不自带该头（实测：直接包含会报
// "unknown type name 'KModErr'"），所以先引入错误码定义。
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_installer.h"

namespace maplesu::sdk {

namespace {

constexpr const char* kSdkVersionText = "4.6.5";
constexpr const char* kSdkVersionFormat = "%u.%u.%u";

}  // namespace

/***************************************************************************
 * get_sdk_version — 读取"本 SDK"的版本号（编译期常量，不是设备上已装版本）。
 *
 *   MapleSUSdkVersion v;         // 12 字节，三个 u32 全 0
 *   sscanf("4.6.5", "%u.%u.%u", &v.major, &v.minor, &v.patch);
 *   return v;                    // 以 2 个 i64 寄存器返回（[2 x i64]）
 *
 * 注意返回值是结构体按值返回（12 字节 → 寄存器成对返回），因此签名必须与
 * 头文件 maplesu_sdk/maplesu_installer.h 完全一致，不能改成写引用参数。
 * 失败行为：sscanf 理论上不会失败（格式与字面量都是常量）；若格式被改坏，
 * 未赋值的字段保持 0，不会返回未初始化内存。
 ***************************************************************************/
MapleSUSdkVersion get_sdk_version() {
    MapleSUSdkVersion ver{};
    ::sscanf(kSdkVersionText, kSdkVersionFormat, &ver.major, &ver.minor,
             &ver.patch);
    return ver;
}

//   maplesu::sdk::install_maplesu_environment(const char*, InstallMode, const InstallConfig&)
//   maplesu::sdk::uninstall_maplesu_environment(const char*)
//   maplesu::sdk::get_maplesu_environment_state(const char*)
//   maplesu::sdk::get_installed_maplesu_environment_version(const char*, MapleSUSdkVersion&)
//   maplesu::sdk::get_maplesu_sdk_ver_path()            (static)
//   maplesu::sdk::get_kernel_file_dir_path()           (static)
//   linux_reboot()                                   (static)
//   file_utils::{file_exists,write_text_file,create_empty_file,set_file_selinux_access_mode}
//   outlining 符号；且这些函数的语义分散在 129 个 W 符号与 42 个只读数据里，

}  // namespace maplesu::sdk
