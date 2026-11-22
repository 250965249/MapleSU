# 参与 MapleSU

欢迎修复问题、维护兼容性、改进翻译与文档。先阅读 [README](README.md) 和[架构说明](docs/ARCHITECTURE.md)，让一次改动围绕一个清楚的目标。

## 开始贡献

1. 搜索已有 Issue。描述问题时提供 MapleSU 版本、Android/内核版本、工作模式、复现步骤和预期结果。
2. Fork 仓库并创建分支，保留原作者、来源和文件中的许可说明。
3. 为行为变化补充相应验证，避免仅检查源码字符串或锁定布局实现的测试。
4. 提交 PR，说明问题、最终行为、验证结果及仍未覆盖的设备条件。

[构建](docs/BUILD.md)、[测试](docs/TESTING.md)、[SDK](docs/SDK.md)、[模块](docs/MODULES.md)和 [Ultra 原生模块](docs/ULTRA_MODULES.md)各有独立入口。主题与模块投稿分别在[主题仓库](docs/THEME_REPOSITORY.md)和[模块仓库](docs/MODULE_REPOSITORY.md)进行，以便作者持续维护自己的条目。

## 改动约定

- 沿用当前代码与双界面风格；新增提示同时维护英文默认资源与简体中文资源。
- 将运行状态、授权状态、静态识别和真实执行结果分别处理；失败时提供可操作的提示。
- 提交前运行 `python tools/check_architecture.py`。新增 Gradle 模块、原生库加载点、顶层目录或 `docs/` 指南时，在同一提交里更新检查规则和[架构说明](docs/ARCHITECTURE.md)；新增顶层目录同时提供自己的 `README.md`。
- 每个组件目录的 `README.md` 说明其内容、构建与测试方式；脚本与检查的入口见 [tools/](tools/README.md) 与 [scripts/](scripts/README.md)。`scripts/` 中被 SDK 记录固定的文件不要改名、移动或修改，需要变更时在同一提交重新固定 SDK 记录。
- 不提交本机路径、设备序列号、设备日志原件、凭据、发布密钥、研究样本或生成的安装包。脚本通过环境变量定位工具（见[构建指南](docs/BUILD.md#locating-tools)），`portable-paths` 规则会拒绝写死的本机路径。
- 引入第三方实现时记录仓库、固定版本、许可、修改范围和所需源码；预编译输入同时记录摘要和对应源码。
- PR 中声明新增图片、字体、图标和主题资源的作者与许可。

以现有许可提交贡献，不额外要求转让著作权。提交的内容应为本人创作或具备贡献所需权限的材料；第三方声明保持原样。

## 维护与发布

维护者审核源码、来源和验证结果后合并。维护范围、兼容记录和投稿接受条件见[维护说明](docs/MAINTENANCE.md)，发行版本须经过[发布流程](docs/RELEASING.md)。Telegram [@KernelMapleSU](https://t.me/KernelMapleSU)发布更新与公告；可复现的问题继续通过 GitHub Issue 跟踪。
