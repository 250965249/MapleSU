# 模块仓库上传与维护

[maplesu-module-market](https://github.com/FengQiuFQ/maplesu-module-market) 独立维护模块条目、版本、原始包、源码索引、维护登记和目录签名。Manager 负责接口与安装流程；模块作者通过 Fork/PR 或“模块投稿”Issue 提交更新。

开发入口：[脚本与 WebUI](MODULES.md)、[MapleSU_Ultra 原生模块](ULTRA_MODULES.md)。

## 1. 准备发布内容

每个版本提交原始 ZIP、对应源码与许可、ID、版本、作者、GitHub 维护账号、更新说明及运行模式。原 SKRoot(Pro) 模块沿用原生 ID 与安装包，新模块使用 MapleSU_Ultra SDK。

| 类型 | 身份来源 | 导入元信息 |
| --- | --- | --- |
| 脚本模块 | 根目录 `module.prop` | 同一份 `module.prop` |
| 原生模块 | ARM64 库内 ID 与描述 | `payload/module.prop` |

原生元信息填写本次发布的名称、版本与作者；`--native-id` 和 `--native-member` 指向真实库内身份与 ZIP 成员名。新原生条目使用 `MAPLESU`，既有 `SKROOT_PRO` 目录继续兼容。包内 `webroot/source.zip` 会自动保存为对应源码并记录摘要。

## 2. 导入模块

在市场仓库根目录执行，包文件保存在相邻的 `module-release/`：

```shell
python -m pip install -r requirements.txt
```

脚本模块：

```shell
python tools/market.py add-local --package ../module-release/example.zip --release-date 2026-11-22
```

原生模块，下列 ID 对应[开发指南的 Hello 示例](ULTRA_MODULES.md)：

```shell
python tools/market.py add-local --package ../module-release/hello.zip --native-id e46a18d2c9074f63b85a9210d7ce304f --native-member libmodule_hello.so --release-date 2026-11-22
```

工具保留包字节，生成 `packages/`、`sources/`、`changelogs/`、`modules/` 与来源快照，更新清单并移除旧签名。作者补充本次实际变更说明。

## 3. 登记维护者并提交

在 `maintainers.json` 的 `entries` 中使用同一模块 ID。维护记录示例：

```json
{
  "maintainers": ["FengQiuFQ"],
  "origin": "MapleSU_Ultra Hello source and package",
  "license": "GPL-3.0-or-later",
  "evidence": ["provenance/maplesu-hello.json"],
  "status": "ready"
}
```

账号、实际来源和许可按投稿填写，`evidence` 指向随 PR 提交的版本来源文件。运行检查：

```shell
python tools/market.py verify --allow-unsigned
python tools/check_maintainers.py
python tools/check_publish_tree.py
python -m unittest discover -s tools -p "test_*.py" -v
```

PR 包含包、源码、索引、维护登记和更新说明。`--allow-unsigned` 用于目录更新后的待签名检查；发布使用固定公钥验签。

## 4. 更新与交接

更新复用 ID，使用新版本，通过 `--select-latest` 明确选择当前版本：

```shell
python tools/market.py add-local --package ../module-release/hello-1.0.1.zip --native-id e46a18d2c9074f63b85a9210d7ce304f --native-member libmodule_hello.so --release-date 2026-11-22 --select-latest
```

同 ID、同版本对应固定字节。`modules/ID/module.json` 保存各版本、来源与摘要；切换当前版本时同步更新索引并签名。交接通过 PR 更新维护账号，关联原作者或现任维护者的交接记录，保留原作者署名及历史版本。

## 5. 签名与主备发布

维护者核对清单、包与来源索引后，使用仓库外的私钥签名：

```shell
python tools/market.py sign --private-key ../market-signing/private-key.pem
python tools/market.py verify --public-key trust/public-key.pem
```

提交 `market.json` 与 `market.json.sig` 后，`main` 的 Pages 工作流导出并部署静态树。`Sign catalog` 工作流也可使用 `MARKET_SIGNING_PRIVATE_KEY` Secret 生成签名 artifact，验签后提交。

| 源 | 清单 |
| --- | --- |
| 主源 | `https://fengqiufq.github.io/maplesu-module-market/market.json` |
| 备源 | `https://raw.githubusercontent.com/FengQiuFQ/maplesu-module-market/main/market.json` |

两源发布同一清单和签名，包按大小及 SHA-256 校验。个人源使用独立 HTTPS 地址和固定公钥，在应用中登记后采用同一格式。

详细流程见市场仓库 [PUBLISH.md](https://github.com/FengQiuFQ/maplesu-module-market/blob/main/PUBLISH.md)，字段见 [SCHEMA.md](https://github.com/FengQiuFQ/maplesu-module-market/blob/main/SCHEMA.md)。版权与移除请求通过该仓库 `COPYRIGHT.md` 和专用 Issue 处理。
