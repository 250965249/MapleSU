# 内核版本资产

此目录保存按完整内核 release 生成的 IR 计划、符号布局和回读记录。它们是与输入摘要绑定的离线分析资料，使用前重新校验目标镜像，不作为已验证可刷写镜像。

## 生成

在仓库根目录向生成器提供自己的输入清单与可用分析器：

```shell
python tools/ir-gen/make_release_assets.py --manifest manifest.json --out patch-engine/assets/releases --engine patch-engine/build/windows-x64/maplesu-kernel-analyze.exe
```

分析器的后端输入和当前公开构建状态见 [构建指南](../../../docs/BUILD.md)。生成结果保持 `flashableCandidate=false`；设备兼容性需要单独验证。

| 文件 | 内容 |
| --- | --- |
| `<release>.ir.spec` | 基础偏移、原始字节和替换字节 |
| `<release>.ir2.spec` | 扩展规则、ABI、结构与 cave 元信息 |
| `<release>.KernelSymbolOffset.json` | 符号、kallsyms 范围与结构偏移 |
| `<release>.readback.json` | 原始/替换块、dry-run、分析器计划结果与摘要 |
| `index.json` | release、输入身份、规则与资产摘要索引 |

`#kernel=` 与目标内核的完整 release 比较。改文件名不会改变支持范围；任意原始字节不匹配、分支越界或结构证据不足时结束生成。离线编码与回读成功仍需后续安装、启动、SU、撤权和模块生命周期验证。
