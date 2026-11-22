# 寄生模式 ELF 测试夹具

这里保留自有最小 JNI 测试宿主及其固定 `DT_NEEDED` 变换结果，供 `HiddenElfTest`
和 `HostSoPatchEngineTest` 验证解析、补丁、原子换入及恢复行为。测试只读取文件，
不加载或执行这两个 ARM64 ELF。来源、编译条件和完整摘要见 [SOURCE.json](SOURCE.json)。

| 文件 | 内容 | SHA-256 |
| --- | --- | --- |
| `libt2host.orig.so.bin` | 从同目录 `native/t2host.cpp` 构建的最小 JNI 库 | `2c1a26cccdd96275c78027a90b1d0ce27f3addc26c8970880c53db9d12e738b9` |
| `libt2host.patched.so.bin` | 增加 `libmsspike.so` 依赖后的固定基准 | `fe1be25deba3305a5a3d1795cc3440bc3557dce52ed111f7b2101640bf9fcb26` |

名称 `libmsspike.so` 只是测试写入的依赖字符串；本测试不需要该库。夹具不包含
实际应用或 SDK 工件。原始库已用所列 NDK 从公开的最小源文件重建并核对摘要。

## 重建原始库

使用 Android NDK `26.1.10909125`，以本目录为工作目录，将输出写到临时位置：

```shell
clang++ --target=aarch64-linux-android29 -shared -fPIC -O2 -static-libstdc++ -Wl,-z,noexecstack -o OUTPUT native/t2host.cpp -llog
```

这里的 `clang++` 指 NDK 工具链的编译器。按 `SOURCE.json` 核对结果；工具链变化
产生不同字节时，先审阅 ELF 和基准差异，再决定是否更新夹具。固定补丁结果用于
跨实现的逐字节比较，功能变更时同步审阅摘要、预期依赖、原始字节和回滚测试。

## 文件后缀

Android Gradle Plugin 会从 Java 测试资源中过滤 `.so` 后缀；使用 `.so.bin` 使字节
进入测试 classpath。`fixture()` 读取 `/parasite/<原名>.bin`，不执行原生装载。
