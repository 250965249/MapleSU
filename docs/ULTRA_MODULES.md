# MapleSU_Ultra 原生模块开发指南

MapleSU_Ultra 原生模块以 ARM64 `.so` 动态库交付，通过静态链接原生 SDK，在 Android 用户态编写模块逻辑，并调用内核内存、内核函数、Hook 和结构体偏移接口。MapleSU 负责模块识别、安装、启动、状态管理、WebUI 和市场更新。

## 1. 模块能力与开发方式

| 能力 | 开发方式 |
| --- | --- |
| 用户态与内核协作 | 文件、网络和业务逻辑使用 Android 原生 C/C++；内核操作使用 `kernel_module` 命名空间下的 SDK 接口 |
| 跨内核适配 | 使用 `kernel_offsets/` 查询结构体偏移，通过符号查询和 BTF 接口获得目标内核的数据布局 |
| 内核 Hook | 使用 AArch64 汇编构造器、上下文保存与恢复，以及 Hook 安装、卸载接口 |
| 模块独立存储 | 通过 `module_private_dir` 访问模块文件，使用磁盘存储接口保存按模块区分的配置 |
| 原生 WebUI | 静态页面与 C++ HTTP 回调可以组合使用，Manager 提供模块页面入口 |
| 统一分发与维护 | 本地 ZIP 安装与模块市场共用原生身份识别；市场独立维护版本、安装包摘要、目录签名和更新来源 |

模块整体运行在用户态 EL0。需要内核能力时，通过 SDK 进入对应的内核执行通道；`.so` 中的普通 C++ 代码仍按用户态程序编写。模块开发使用共享库工程，交付物为包含原生入口的 ZIP。

### 原有 SKRoot(Pro) 模块兼容

MapleSU_Ultra 保留原有 SKRoot(Pro) SDK 的原生模块 ABI，包括入口导出、描述标记、模块身份、安装与卸载回调、WebUI 和底层调用符号。使用这套 ABI 的现有模块可以沿用原始 ZIP 安装，无需因为 MapleSU_Ultra 的命名重新编译或修改模块 ID。

新模块使用本仓库头文件中的 `MAPLESU_MODULE_*` 宏和 `maplesu_module_main`；兼容层负责生成加载器识别的导出。已有源码继续使用与其静态库配套的头文件。应用版本、SDK 版本和模块声明的最低 SDK 版本分别管理，安装器按 SDK 版本检查模块要求。涉及特定内核接口的模块，发布时列明所使用的接口与适配范围。

## 2. SDK 与运行流程

SDK 位于 [`runtime/maplesu-sdk/`](../runtime/maplesu-sdk/)。

```text
runtime/maplesu-sdk/
├── include/                          公共头文件
├── lib/arm64-v8a/
│   └── libkernel_module_kit_static.a  原生静态库
├── sdk/                              SDK 源码与构建工具
├── SDK-RELEASE.json                   SDK、helper 与 backend 的版本及摘要
└── SDK-SOURCES.json                   发布源码与静态库成员索引
```

模块调用链为：

```text
模块 ZIP
  → Manager 读取 ELF 导出与描述，确认模块身份
  → MapleSU_Ultra 后端安装模块文件和资源
  → 模块工作进程通过 dlopen 加载共享库
  → 加载器绑定模块身份并调用原生入口
  → maplesu_module_main(root_key, module_private_dir)
  → 模块通过 SDK 调用内核与模块服务
```

开机加载由 MapleSU_Ultra 的启动链发起；运行中的安装或启动由当前后端处理。入口按启动早期环境设计：初始化完成后及时返回，把依赖 Framework、网络或长时间等待的任务放入独立工作进程，并按实际服务状态安排执行。

SDK 输入与后端维护方式见[后端依赖与维护](NATIVE_DEPENDENCIES.md)，应用侧 Binder 接口见[应用 SDK](SDK.md)。

## 3. 头文件与 API

通常只需包含一个总入口头文件：

```cpp
#include "kernel_module_kit_umbrella.h"
```

| 头文件 | 用途与常用入口 |
| --- | --- |
| `module_descriptor.h` | `MAPLESU_MODULE_*` 元信息与 `maplesu_module_main` |
| `module_base_kernel_mem.h` | `read_kernel_mem`、`write_kernel_mem`、内核内存分配与释放 |
| `module_base_kernel_func_executor.h` | `execute_kernel_asm_func`，执行按 SDK 约定生成的 AArch64 代码 |
| `module_base_kernel_func_hook.h` | `install_kernel_function_before_hook`、`install_kernel_function_after_hook`、`uninstall_kernel_hook` |
| `module_base_kernel_symbol_kaddr.h` | `kallsyms_lookup_name`、系统调用地址查询 |
| `module_base_kernel_export_symbol.h` | 内核导出函数调用封装 |
| `module_base_kernel_string_ops.h` | 内核字符串与内存操作封装 |
| `module_base_kernel_btf_resolver.h` | `btf_resolve_member_offset`、结构体大小查询 |
| `kernel_offsets/` | `task_struct`、`cred`、`file`、`inode`、`mm_struct` 等结构体的字段查询 |
| `module_base_disk_storage.h` | `read_*_disk_storage`、`write_*_disk_storage`，模块配置持久化 |
| `module_base_install_callback.h` | 安装与卸载回调 |
| `module_base_change_status.h` | 运行状态与动态描述更新 |
| `module_web_ui_http_handler.h` | `kernel_module::WebUIHttpHandler`，原生 HTTP 回调 |
| `module_web_ui_http_utils.h` | `kernel_module::webui` 中的文本、JSON 与请求处理工具 |

多数 SDK 操作返回 `KModErr`，成功值为 `KModErr::OK`。先检查返回码，再使用输出参数。例如查询 `task_struct.comm` 的偏移：

```cpp
uint32_t comm_offset = 0;
KModErr err = kernel_module::get_task_struct_comm_offset(comm_offset);
if (err != KModErr::OK) {
    return static_cast<int>(err);
}
```

偏移查询由 SDK 统一处理，模块使用查询结果计算目标字段地址。BTF 查询使用设备提供的 `vmlinux` 类型信息，适用于开启 `CONFIG_DEBUG_INFO_BTF` 并提供相应数据的内核。SDK 的偏移查询接口与 BTF 查询接口可分别使用。

## 4. 第一个模块

新建 `module.cpp`：

```cpp
#include "kernel_module_kit_umbrella.h"
#include <cstdio>

MAPLESU_MODULE_NAME("MapleSU_Ultra Hello")
MAPLESU_MODULE_VERSION("1.0.0")
MAPLESU_MODULE_DESC("MapleSU_Ultra 原生模块示例")
MAPLESU_MODULE_AUTHOR("YourName")
MAPLESU_MODULE_ID32("e46a18d2c9074f63b85a9210d7ce304f")

int maplesu_module_main(const char* root_key, const char* module_private_dir) {
    std::printf("MapleSU_Ultra Hello: %s\n", module_private_dir);
    return 0;
}
```

| 项目 | 说明 |
| --- | --- |
| `NAME`、`VERSION`、`DESC`、`AUTHOR` | 模块列表中展示的名称、版本、描述和作者 |
| `ID32` | 新模块生成一次固定的 32 位 ASCII 字母数字 ID；后续更新沿用同一 ID |
| `root_key` | 加载器传入的 SDK 运行凭据，由入口包装层建立调用上下文 |
| `module_private_dir` | 本次加载对应的模块资源目录，直接使用该参数定位文件 |
| 入口返回值 | `0` 表示入口完成；非零值记录为模块入口异常 |

模块 ID 区分安装身份、更新目标和模块存储。复制示例创建其他模块时生成新 ID；升级同一模块时保持 ID。凭据保留在模块运行上下文中，日志和 WebUI 响应只输出业务所需信息。

## 5. 编译

使用 Android NDK、CMake 和 Ninja，目标为 `arm64-v8a`，C++ 标准为 C++20。SDK 头文件与静态库取自同一份仓库快照。

与 `module.cpp` 同目录创建 `CMakeLists.txt`：

```cmake
cmake_minimum_required(VERSION 3.22.1)
project(maplesu_ultra_hello LANGUAGES CXX)

set(MAPLESU_SDK_DIR "" CACHE PATH "MapleSU_Ultra SDK directory")

add_library(maplesu_ultra_sdk STATIC IMPORTED)
set_target_properties(maplesu_ultra_sdk PROPERTIES
    IMPORTED_LOCATION "${MAPLESU_SDK_DIR}/lib/arm64-v8a/libkernel_module_kit_static.a"
    INTERFACE_INCLUDE_DIRECTORIES "${MAPLESU_SDK_DIR}/include"
)

add_library(module_hello SHARED module.cpp)
target_compile_features(module_hello PRIVATE cxx_std_20)
target_compile_options(module_hello PRIVATE -fno-rtti -fvisibility=hidden -ffunction-sections -fdata-sections)
target_link_options(module_hello PRIVATE -Wl,--gc-sections)
target_link_libraries(module_hello PRIVATE maplesu_ultra_sdk log android dl z)
```

在 Windows PowerShell 中，将 `ANDROID_NDK_HOME` 指向已安装的 NDK，并按实际位置填写 `MAPLESU_SDK_DIR`：

```powershell
cmake -S . -B build -G Ninja `
  "-DCMAKE_TOOLCHAIN_FILE=$env:ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" `
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-21 `
  -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release `
  "-DMAPLESU_SDK_DIR=<MapleSU仓库>/runtime/maplesu-sdk"
cmake --build build
```

Linux 与 macOS 使用对应 NDK 工具链运行相同的 CMake 参数。输出文件为 `build/libmodule_hello.so`。`c++_static` 把 C++ 运行库链接进模块，`-fno-rtti` 与 SDK 内的 WebUI 库保持一致；SDK 宏负责导出加载器入口，发布时保留这些动态导出和 ELF 节表。

## 6. 打包与安装

最小包只需将 `libmodule_hello.so` 放在 ZIP 根目录。完整包可以使用以下结构：

```text
maplesu-ultra-hello.zip
├── libmodule_hello.so
├── payload/
│   ├── module.prop
│   ├── LICENSE
│   └── config.json
└── webroot/
    └── index.html
```

压缩目录中的内容，使 `.so` 直接位于 ZIP 根目录。`payload/module.prop` 供市场导入与展示使用，填写与库内描述一致的模块 ID、名称、版本和作者；加载身份来自原生库的导出与描述。

旧模块包携带根级 `module.prop` 时，Manager 以通过校验的原生入口和描述确定模块身份。新包采用上面的布局，便于维护原生载荷、市场元信息与附带资源。

资源按 ZIP 内的相对路径释放。例如 `payload/config.json` 安装后位于 `module_private_dir` 下的 `payload/config.json`：

```cpp
std::string config_path = std::string(module_private_dir) + "/payload/config.json";
```

在 MapleSU 的 Ultra 模式中打开模块页面，选择 ZIP 安装。Manager 读取归档和 ELF 信息后交给 MapleSU_Ultra 后端，并在模块列表中展示安装结果、启动状态和描述。模块发布前覆盖安装、更新、重新启动、禁用和卸载流程。

## 7. WebUI

### 静态页面

将页面放在 ZIP 的 `webroot/`，首页命名为 `index.html`。安装后由模块页面打开 WebUI，页面资源从模块目录提供。

### C++ HTTP 接口

继承 `kernel_module::WebUIHttpHandler`，通过 `MAPLESU_MODULE_WEB_UI` 注册。以下代码加入前面的 `module.cpp`：

```cpp
class HelloWebUI final : public kernel_module::WebUIHttpHandler {
public:
    bool handleGet(CivetServer* server, mg_connection* conn,
                   const std::string& path, const std::string& query) override {
        if (path == "/api/status") {
            return kernel_module::webui::send_json(
                conn, 200, R"({"module":"MapleSU_Ultra Hello","ready":true})");
        }
        return false;
    }
};

MAPLESU_MODULE_WEB_UI(HelloWebUI)
```

`handleGet`、`handlePost` 返回 `true` 表示已经完成响应，返回 `false` 继续交给静态文件服务。动态接口和 `webroot/index.html` 可以放在同一模块中，页面通过相对路径请求 `/api/status`。

`onPrepareCreate` 提供运行凭据、模块目录和监听端口；`onServerCreated` 提供服务器实例；`onBeforeServerExit` 返回服务器结束后的进程处理方式。各回调的完整签名见 `module_web_ui_http_handler.h`。

## 8. 安装、卸载与运行状态

安装和卸载回调通过宏注册：

```cpp
std::string on_install(const char* root_key, const char* module_private_dir) {
    return "";
}

void on_uninstall(const char* root_key, const char* module_private_dir) {
}

MAPLESU_MODULE_ON_INSTALL(on_install)
MAPLESU_MODULE_ON_UNINSTALL(on_uninstall)
```

安装回调在解包后执行，返回空字符串继续安装，返回非空文本终止安装并向用户展示该原因。卸载回调在删除模块前执行，用于停止模块自己的任务与清理额外创建的资源。运行中的后台工作进程由模块自行管理，确保重复启动与退出按同一套生命周期处理。

动态描述与状态使用以下接口：

```cpp
kernel_module::set_current_module_description("配置已加载");
kernel_module::set_current_module_run_state(maplesu::sdk::ModuleRunState::Running);
```

`ModuleRunState` 定义了 `NotRunning`、`Running`、`Abnormal` 和 `RemovedPendingReboot`。描述用于展示模块当前业务状态；模块列表同时保留加载器的执行结果。

## 9. 版本更新与市场提交

模块可以使用 `MAPLESU_MODULE_UPDATE_JSON(url)` 声明更新地址。更新时保持模块 ID，递增版本，发布完整 ZIP 并记录 SHA-256。市场中的版本、原生成员名与库内元信息对应同一份发布物。

投稿和后续维护在独立的[模块市场仓库](https://github.com/FengQiuFQ/maplesu-module-market)进行。维护者登记作者、维护账号、源码、许可证、模块 ID 和兼容模式，使用市场工具导入、检查并更新目录；原生模块使用 `MAPLESU` 类型，既有目录的兼容类型名继续由 Manager 识别。

完整步骤见[模块仓库上传与维护](MODULE_REPOSITORY.md)，按模块、SDK、内核和操作匹配的兼容记录见[模块兼容判定](MODULE_COMPATIBILITY.md)。

特别致谢 SKRoot 提供相关思路参考与贡献。
