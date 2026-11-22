# 主题仓库上传与维护

MapleSU 主题源沿用 FinaSU 的 JSON 数组索引和 `.fpt` 容器，以便主题作者复用现有创作流程。主题资源通过主题导入器处理，与模块执行路径分开。

社区仓库：[maplesu-theme-market](https://github.com/FengQiuFQ/maplesu-theme-market)。主题格式和导入体验的主要参考：[FinaSU](https://github.com/LyraVoid/FinaSU)。

## 第一次投稿

1. Fork 主题仓库，阅读其中的 `CONTRIBUTING.md`。
2. 准备 `.fpt`、预览图、名称、作者、稳定主题 ID 和版本。
3. 提供原作链接，以及包内每种字体、图片、图标等资源的许可或使用证明。
4. 使用仓库工具导入并校验，在 `maintainers.json` 登记维护账号和来源。
5. 提交 PR，附上亮/暗模式、Material/Miuix 的实际预览和已验证应用版本。

不熟悉 Git 的作者可以使用仓库中的主题投稿 Issue；维护者核对材料后协助整理，不因此变更原作者署名。

## 导入与检查

以下命令在主题仓库根目录运行；`example.fpt` 和 `preview.png` 是投稿者准备好的文件：

```shell
python -m pip install -r requirements.txt
python tools/theme_market.py add --id author.example --package example.fpt --preview preview.png --origin https://github.com/author/example-theme --license CC-BY-4.0
python tools/theme_market.py check
python tools/check_maintainers.py
python -m unittest discover -s tools -p "test_*.py"
```

`--license` 填主题实际采用的许可，不将示例的 CC-BY-4.0 直接套用于其他作者资源。工具保留包摘要、大小、来源和版本，按 ID/版本/内容哈希保存 `.fpt`，由索引指向当前版本。

## 维护自己的主题

保持主题 ID 不变，在主题元信息中更新 `meta_version` 后重新导入。PR 说明资源变化、兼容范围和预览，保留旧版本文件。作者、版本、包摘要、预览和登记信息一起核对，不手改摘要来使旧包通过校验。

作者可申请接手或交接维护，通过原仓库账号、发布记录或其他可核对的作者证明确认。`maintainers.json` 是公开协作登记；仓库级审批与发布权限仍由仓库维护者管理。

## 发布与自定义源

仓库维护者在合并后导出新的静态树：

```shell
python tools/theme_market.py stage --out ../theme-pages-staging
```

输出目录应为新目录。发布时核对主备源的索引与包摘要，再验证实际下载和导入。应用支持 MapleSU、FinaSU 以及自定义 HTTPS JSON 数组索引；自定义源可使用同一字段契约和校验工具。

`.fpt` 的容器参数不是作者身份认证。包下载摘要用于完整性校验，资源许可和作者来源仍需单独记录。版权问题、重复投稿和删除请求统一通过仓库 Issue 处理，见仓库的 `COPYRIGHT.md`。
