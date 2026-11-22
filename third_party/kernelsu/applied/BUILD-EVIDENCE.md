# applied/BUILD-EVIDENCE.md · MapleSU KSU 真实构建证据（W12d / P0 收尾）

> 本文件是**构建证据**（生成物，不进 `applied` 输入树 / 不计入 treeSha256；`apply_patches.py --clean`
> 会保留它）。记录 2026-10-30 在本机产出的真实 ELF 产物、命令、哈希与校验方式。
> 最后一节是目前**唯一 pending** 的 `kernelsu.ko` 的 CI 交付闭环。

## 0. 本机 LKM 可行性终审（结论：不可本机构建）

逐条实测（本机，2026-10-30）：

| 检查 | 命令 | 结果 |
|---|---|---|
| 目标 KMI 内核源码/预置树 | `find /d /c -maxdepth 3 -iname '*android15-6.6*'` | **空**（无任何匹配） |
| DDK 工具/缓存 | `which ddk`；`ls ~/.cache/ddk` | 均不存在（`no ddk in PATH` / `no ~/.cache/ddk`） |
| 内核/LKM 工具链 | `command -v clang make cmake ninja gcc ld.lld aarch64-linux-gnu-gcc` | **全部 MISSING**（PATH 上无内核构建器） |
| DDK 容器能力 | `docker images` | `failed to connect to the docker API ... dockerDesktopLinuxEngine`（daemon 未启动） |
| 内核源码树 | `ls third_party/android-kernel/` | 只有 `call-contracts.json`（自述非内核源码） |
| 内核镜像/符号 | `find /d -maxdepth 3 -iname 'vmlinux*' -o -iname 'Image.gz'` | 空 |
| 磁盘余量（下载红线） | `df -h /c` | C: 剩 **1.8 GB**（禁止下载大包） |

→ **结论：`android15-6.6_kernelsu.ko` 不可本机构建**。LKM 必须由 DDK 容器（CI）产出；
`ksu-payload.json` 对它的 `pending-ci` 状态**如实保留**，绝不写假哈希。

## 1. JNI（本机可产，真实产物）

```bash
export ANDROID_NDK_HOME='D:/Maple_Env/Android/Sdk/ndk/26.1.10909125'
export CMAKE_BIN='/d/Maple_Env/Android/Sdk/cmake/3.22.1/bin/cmake.exe'
export PATH="/d/Maple_Env/Android/Sdk/cmake/3.22.1/bin:$PATH"
bash third_party/kernelsu/scripts/build_jni.sh
```

| 产物 | 大小 | sha256 |
|---|---|---|
| `manager/src/main/jniLibs/arm64-v8a/libmaplesu_ksu.so` | 184,208 | `cf14e1da4e73af6718d2d49ebba1dc6d1a1ca9a4e11af00c0c78a3bec1098a46` |
| `manager/src/main/jniLibs/arm64-v8a/libadbroot.so` | 605,464 | `684d1d18d3a9d70d4c2d6b12d3007cdc028e9e53a63bfc6038ca5551d322d955` |

`llvm-readelf` / `llvm-nm` 校验摘要：

* `ELF 64-bit LSB shared object, ARM aarch64 ... for Android 31`（NDK r26b）
* 4 个 `LOAD` 段 **Align 全部 = 0x4000**（16KB page；NDK 26 默认 4KB，由
  `-Wl,-z,max-page-size=16384` 显式拉到 16KB）
* `NEEDED` 仅系统库：`liblog.so / libm.so / libdl.so / libc.so`
* **25 个**导出符号 `Java_dev_maplesu_manager_ksu_KsuNatives_*`（03 分册 §3.6）

## 2. 用户态 ksuinit + libksud_ksu.so（本机可产，真实产物）

```bash
export ANDROID_NDK_HOME='D:/Maple_Env/Android/Sdk/ndk/26.1.10909125'
export LIBCLANG_PATH='<含 libclang.dll 的目录>'   # bindgen 需要（NDK clang.exe 是静态的，无 libclang.dll）
export KSU_DLLTOOL_DIR='<含 dlltool.exe 的目录>'   # Windows 宿主 gnu 工具链需要
export KSU_HOST_BIN_DIR='<llvm-mingw bin 目录>'   # dlltool 是 wrapper，需要它的 bin 在 PATH
bash third_party/kernelsu/scripts/build_userland.sh
```

| 产物 | 大小 | sha256 | 类型/校验 |
|---|---|---|---|
| `third_party/kernelsu/artifacts/ksuinit` | 809,384 | `beace67a272778d8f9f0bf08284c47bff1a00f555c43fec80f3bd40ceb9e43ba` | `ELF 64-bit LSB executable, ARM aarch64, statically linked`；`LOAD align=0x4000` |
| `manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so` | 5,896,288 | `c53cffd33430964dd1196572140cb88df4a7d2108c9cfa1b90da3358fe9dfa6c` | `ELF 64-bit LSB pie executable, ARM aarch64`；`LOAD align=0x4000`；`NEEDED = liblog/libdl/libm/libc`（**W12d 单 KMI 产物**；5 KMI 重建见 §2.4） |

内容校验：`grep -ac 'dev.maplesu.manager' libksud_ksu.so` = **1**（03 §1.7 门禁）；
`grep -ac '32650'` = **2**（`VERSION_CODE=32650` = `30000 + 2650`，来自合成 git 历史，与
`KSU_VERSION_PIN=32650` 一致）。

### 2.1 澄清 ①：ksuinit 是 ET_EXEC 静态、非 PIE —— **这是预期，不是偏差**

* 上游 CI 的 ksuinit 构建参数（`applied/.github/workflows/ksuinit.yml:40`）与本次完全一致：
  `RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,-z,max-page-size=16384 ..."`
  —— **没有** `-C relocation-model=pic` / `-pie`；`+crt-static` 静态链接产物即 `ET_EXEC`。
* ksuinit 的职责是尽早 mount/exec（作为 ramdisk `/init`），加载器不需要 PIE；
  16KB page 对齐由 `-z,max-page-size=16384` 保证（实测 `LOAD align=0x4000` ✅）。
* 因此 `file` 输出 `ELF 64-bit LSB executable ... statically linked`（非 PIE）是**上游预期形态**；
  文档口径已由「静态 PIE」更正为「静态 ET_EXEC（非 PIE），16KB page」。

### 2.2 澄清 ②：libksud 里为何找不到 ksuinit 的逐字节副本 —— **预期（压缩内嵌）**

* 机制：`applied/userspace/ksud/Cargo.toml` 的
  `rust-embed = { features = ["debug-embed", "compression"] }`；`src/assets.rs` 用
  `#[derive(RustEmbed)] #[folder = "bin/aarch64"]`。release 构建时每个资产被
  **raw DEFLATE（libflate，经 include-flate/include-flate-compress）压缩**后写入 ELF rodata，
  运行期 `Asset::get()` 解压返回。
* ⇒ 二进制里**不存在**原始字节副本，答案不是「没嵌入」而是「压缩了」。
* **校验方法（已固化）**：
  ```bash
  python3 third_party/kernelsu/scripts/verify_embedded_asset.py       --lib manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so       --asset third_party/kernelsu/artifacts/ksuinit --offset 275550
  ```
  实测结果：offset `275550` 处存在 raw-deflate 流，解压后 **809,384 字节、与本资产逐字节一致**。
  （`--deep` 可全量扫描找偏移，CI 可选；无 `--offset/--deep` 时脚本明确报错。）
* 旁证：同一构建中 `bin/aarch64/waitsys` 也能以同样方式定位到压缩流（控制样本）；
  另做了「移出 ksuinit 后重编 ksud」的对照：体积 5,896,288 → 5,497,888（差 **398,400 B**
  ≈ ksuinit 的压缩体积），再次证明嵌入生效。

### 2.3 Windows 宿主构建链路的两个缺口（脚本已参数化；Linux CI 不需要）

1. **无 MSVC/Windows SDK** → 宿主 crate 的 `link.exe` 不存在（`/usr/bin/link` 是 coreutils）。
   解法：`cargo +stable-x86_64-pc-windows-gnu` + rustup 自带 `rust-lld`
   （`CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER`）。
2. **`windows-sys`/`getrandom` 的 raw-dylib 需要 `dlltool`**，bindgen 需要 `libclang.dll`：
   `KSU_DLLTOOL_DIR` 指向「命名为 dlltool.exe 的 llvm-mingw dlltool」、
   `KSU_HOST_BIN_DIR` 指向 llvm-mingw 的 bin（wrapper 依赖）、`LIBCLANG_PATH` 指向含
   `libclang.dll` 的目录（LLVM/llvm-mingw 或 `pip install libclang` 的 `clang/native`）。

### 2.4 W13 追加（2026-10-30）：5 KMI 内嵌重编 `libksud_ksu.so`

> 背景：§2 的 5,896,288 B 产物是**单 KMI**（仅 `android15-6.6`）内嵌。多 KMI 矩阵落地后
> 用同一条命令重编（`build_userland.sh --kmi all`，脚本默认值），把 `lkm/` 下 5 个
> `*_kernelsu.ko` 全量嵌入。详细收尾记录见 `docs/development/normal-kmi-matrix-2026-10-30.md §7`。

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export ANDROID_NDK_HOME='D:/Maple_Env/Android/Sdk/ndk/26.1.10909125'
export LIBCLANG_PATH='<repo>/.tmp/pylibclang/clang/native'   # pip libclang 18.1.1 的 libclang.dll
export KSU_DLLTOOL_DIR='/c/msys64/ucrt64/bin'                # 真 binutils dlltool（as/ld/ar 同目录）
export MAPLESU_PYTHON='/c/Python314/python.exe'
bash third_party/kernelsu/scripts/build_userland.sh --kmi all
```

| 产物 | 大小 | sha256 | 变化 |
|---|---|---|---|
| `manager/src/main/jniLibs/arm64-v8a/libksud_ksu.so` | **6,641,192** | `1e1f3d1f53e91cebf5f020296bb69f737e60be467c7aec14967a0a6d62586f68` | 旧 5,896,288 / `c53cffd3…`（+744,904 B） |
| `third_party/kernelsu/artifacts/ksuinit` | 809,384 | `beace67a272778d8f9f0bf08284c47bff1a00f555c43fec80f3bd40ceb9e43ba` | 无变化（重编后字节相同） |

* 内嵌压缩流偏移（`verify_embedded_asset.py --offset` 逐个 PASS，解压后与源文件逐字节一致）：
  `android12-5.10`=218,922 · `android14-6.1`=360,904 · `android15-6.6`=518,353 ·
  `android16-6.12`=649,510 · `ksuinit`=**1,892,735**（§2.2 的 275,550 只对旧库成立）·
  `android13-5.15`=2,295,906。
* 资产目录表（rodata 名字串，偏移 2,490,797 起）按序含 5 个 `<kmi>_kernelsu.ko`
  → `ksud boot-info supported-kmis` 的数据源已从 1 条变 5 条。
* **`verify_embedded_asset.py --deep` 的假阴性已修**：旧实现用 64 B 输入窗口试解压 4 B，
  libflate 的单 dynamic block 在 64 B 内产不出首字节（同一库上**新旧偏移都会**被判"未找到"）。
  现为 512 B 窗口 + `BTYPE=11` 剪枝，6.6 MB 全量扫描约 2 秒（W12d 文档里的 `--offset` 用不受影响）。
* 登记：`register_artifact.py` 扩展为也支持非 lkm 条目（按条目自身 `path` 契约回填真实
  sha256/size，不加 `kmi` 字段），本轮只改 payload 的 `libksud_ksu.so` 一条；
  `gen_payload.py --check` 无漂移、`verify_payload.py --quick` 全绿、applied 树仍 `7875ef3d…`。
* G6：APK 尚未重建（仓库内 `manager-debug.apk` 仍是旧库），`verify_dual_mode.py --skip-build`
  只剩 `apk-lib-sha:libksud_ksu.so` 一条红；`jniLibs` 暂存 sha 与 16 KB 对齐已就绪，
  下一次 `:manager:assembleDebug` 后应 15/15 全 True。

## 3. APK 打包验证

```bash
cmd //c "gradlew.bat :manager:assembleDebug --no-configuration-cache --max-workers=2"
```

* APK：`manager/build/outputs/apk/debug/manager-debug.apk` = **118,482,337 B**
  （本轮起点基线 114,418,092 B；上一轮仅 JNI 时 115,445,948 B）
* `unzip -l` 含 `lib/arm64-v8a/{libmaplesu_ksu.so, libadbroot.so, libksud_ksu.so}`
* `unzip -p <apk> lib/arm64-v8a/<lib> | sha256sum` 与 §1/§2 源文件哈希**逐字节一致**
  （`packaging.jniLibs.keepDebugSymbols` 已保护三库，strip 不改字节）。

## 4. 唯一 pending：`kernelsu.ko` 的 CI 交付闭环

1. CI 工作流（可复制到 `.github/workflows/`）：`third_party/kernelsu/ci/build-kernel.yml`
   * 固定 `UPSTREAM_COMMIT=528bafc…`、KMI `android15-6.6`、`KSU_VERSION_PIN=32650`；
   * 步骤：`apply_patches.py --clean` → `verify_payload.py --quick` → `scripts/build_lkm.sh`
     （DDK 容器）→ `scripts/register_artifact.py` → `verify_payload.py --quick` → 发布门禁
     （`strings ko | grep dev.maplesu.manager`）→ 上传 `ko + sha256 + payload + manifest + log`。
   * 证书指纹来自 secrets（`KSU_EXPECTED_SIZE/HASH`），缺失时 `build_lkm.sh` 明确失败。
2. `scripts/register_artifact.py`：**只接受真实文件**，计算 sha256/size 后回写 payload；
   名字必须在 payload 里已存在（防拼错绕过）、必须符合 `${kmi}_kernelsu.ko`、路径必须在仓库内；
   写后自动跑 `verify_payload.py --quick`。
   * 已验证：`--self-test` **通过**（临时 fixture 走完整 register/check/失败分支，真实 payload 未被修改）；
     `--dry-run` 通过（真实 payload 未变，`pending-ci` 保持不变）。
3. 本地 → CI → register 的可复现步骤：
   ```bash
   # CI（ubuntu）里：
   python3 third_party/kernelsu/scripts/apply_patches.py --clean
   python3 third_party/kernelsu/scripts/verify_payload.py --quick
   bash third_party/kernelsu/scripts/build_lkm.sh --kmi android15-6.6
   python3 third_party/kernelsu/scripts/register_artifact.py      --name android15-6.6_kernelsu.ko      --path third_party/kernelsu/lkm/android15-6.6_kernelsu.ko      --kmi android15-6.6 --built-by "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"
   python3 third_party/kernelsu/scripts/verify_payload.py --quick   # 必须转绿
   ```

## 5. 产物登记（ksu-payload.json 当前状态）

`present=5`：`libmaplesu_ksu.so`、`libadbroot.so`、`ksuinit`、`libksud_ksu.so`、
`assets/ksu_manager_gen2`；`pending-ci=1`：`android15-6.6_kernelsu.ko`。
设备端断言（03 §7.3）：`KsuNatives.version > 0 && isManager && kernelUAPIVersion == 7`
（需真机 + LKM，属 CI/设备门槛）。
