# KernelSU · Normal 后端

Normal 模式主要使用 [KernelSU](https://github.com/tiann/KernelSU) 的实现。管理器和用户态保留 GPL-3.0-or-later，内核部分保留 GPL-2.0-only；完整声明见原文件和 [upstream/LICENSE](upstream/LICENSE)、[upstream/kernel/LICENSE](upstream/kernel/LICENSE)。

固定基线为 `528bafc5696196f3a9500cee2e7e18497421cd32`。来源、原始文件哈希、补丁与本地适配记录由 [manifest.json](manifest.json) 统一描述。

## 目录

| 路径 | 用途 |
| --- | --- |
| `upstream/` | 固定版本的上游源码与通知 |
| `patches/7k/` | 按 `series` 顺序应用的适配补丁 |
| `scripts/` | 补丁应用、源码与产物核对、JNI/用户态/内核构建入口 |
| `ci/` | 原生与 KMI 构建所需配置 |
| `applied/` | 本机生成的应用补丁后源码，不作为另一份手工维护的源 |
| `lkm/`、`artifacts/`、`ksu-payload.json` | 本机构建与产物身份记录，不由公开源码树携带 |

## 重建输入与原生输出

`apply_patches.py` 从固定 `upstream/` 与补丁生成 `applied/`，在应用每个补丁前检查可应用性，并校验 UAPI 与路径。已有生成目录时须先确认内容；不要叠加重复补丁或手改清单摘要来通过验证。

```shell
python third_party/kernelsu/scripts/apply_patches.py --help
```

JNI、ksuinit/ksud 与内核模块分别由 `build_jni.sh`、`build_ksud.sh` / `build_userland.sh`、`build_lkm.sh` 构建。它们需要对应 NDK、Rust 依赖和内核/DDK输入；内核模块还与 KMI 和 Manager 签名身份相关。最终产物的摘要、来源和 APK 打包身份须一致。

The complete Manager retains its native SDK, provider and tool inputs. Follow the root [build guide](../../docs/BUILD.md) and verify the source archive before release.
