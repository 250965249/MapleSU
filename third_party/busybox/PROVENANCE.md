# BusyBox 来源与维护

## 当前固定输入

| 项目 | 记录 |
| --- | --- |
| 本地路径 | `third_party/busybox/aarch64/busybox` |
| SHA-256 | `4d60ab3f5a59ebb2ca863f2f514e6924401b581e9b64f602665c008177626651` |
| 大小 | 1 710 600 字节 |
| 格式 | ELF 64-bit LSB executable，ARM aarch64，静态链接，Android 35 |
| 工具链标记 | NDK r27b（12297006），已 strip |
| Build ID | `sha1=2a65965584591f62f0fa7bd2f6dac88036328b6c` |

该文件取自 KernelSU 提交 `528bafc5696196f3a9500cee2e7e18497421cd32` 的固定快照，
上游路径为 `userspace/ksud/bin/aarch64/busybox`，由 `assets.rs` 的 `BUSYBOX_PATH` 使用。
它是上游二进制输入；MapleSU 构建校验固定摘要，并将其部署到自己的工具目录。

[SOURCE.json](SOURCE.json)固定上述来源、提交、路径、大小与摘要。`python tools/prepare_native_inputs.py` 可获取相同字节；`--check` 只验证现有输入。The retained file is also indexed by the complete-source input manifest.

## Source distribution

The complete source tree retains this exact input at the path above. Its byte
identity is checked by `release/native-inputs.json` and the source-export check.
The origin is the pinned KernelSU snapshot recorded in `SOURCE.json`; this file
is supplied as a prebuilt component. Component notices and source records are
maintained in the [dependency inventory](../DEPENDENCIES.md).

## 后续维护

自建版本需固定 BusyBox 源码版本、下载来源、摘要、完整 `.config` 和交叉工具链版本，
附构建命令及相应分发材料。编译器与 GNU make 使用构建环境的工具路径。

维护时核对静态链接方式、`CONFIG_ASH_STANDALONE` 及所需 applet；
`ASH_STANDALONE=1` 与当前运行器配套使用。新产物需验证 ARM64 格式、
shell 与模块脚本行为、部署路径及失败返回值，并同步更新打包摘要。
工具只安装到 MapleSU 自身目录，不覆盖其他 Root 管理器的工具。
