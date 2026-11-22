# Shark per-kernel runner（逐内核提权引擎）

来源：[Shark](https://github.com/Yunnijian/Shark) `v2.2.2`（commit
`2af72cb8959fae5f1c7f929a649db5e546334cef`，GPL-3.0）。

这里的 `runners/arm64-v8a/libk<版本>.so` 是上游发布的逐内核 runner，**按原字节**收录，
逐个记录 SHA-256；`upstream/exploit/` 是对应的 Rust/C 源码（重建与 GPL-3.0 合规用），
`manifest.json` 记录上游 commit、tag、每个 runner 与每个源文件的摘要。

## 它在这个项目里承担什么

只承担一件事：**拿到内核域 root 上下文（uid 0 + full caps + 可写内核）**，然后把控制权
交回 MapleSU 自己的接管批次。以下环节仍然是 `maplesu-93260` 原有的那一套，没有替换：

- SELinux 进入/恢复窗口；
- `bs --handover --target normal|ultra` 的模块 late-load；
- 共享接管回执（`maplesu.93260.source.v1`）与 `maplesu.handover.v1` 校验；
- 管理器接管、重启与后续验证。

## 为什么不用 runner 自带的 late-load

Shark 的 runner 在 fake-cred 子进程里用 `system()` 执行
`"$PYB110_KSUD" late-load --kmi ... --package-name <五家管理器之一>`（hooks-gated 内核
则是 `debug extract-binary`）。它把 `--package-name` 写死成那五家，而 MapleSU 的接管
late-load 包名是 `dev.maplesu.manager`（`bootstrap.c:74`）。直接跑 runner 会把 root 交给
别家管理器，MapleSU 的接管不会发生。

因此 `MapleSu93260Attempt` 直接用 **`__plant --auto`** 启动 runner 的提权阶段，并把
`PYB110_KSUD` 指向一个 wrapper：

```sh
#!/system/bin/sh
exec /system/bin/sh /data/local/tmp/maplesu-93260/batch.sh "$@"
```

fake-cred 子进程调到的就是它，于是我们原有的 handover 批次在同一个 root 上下文里执行：
`batch.sh` 会写回执、恢复 SELinux、调用 `bs --handover`。runner 自己的
late-load / 管理器收尾代码不会被触发（gate 内核上 wrapper 故意不生成 `ko.bin`，
`load_bound_ko` 随即跳过）。

### kallsyms 快照

我们的 ksud 补丁在 `MAPLESU_KALLSYMS_PATH` 存在时只认这个文件、不会回退到
`/proc/kallsyms`。保留引擎为 PD2546 打包了快照；Shark 引擎没有逐构建快照，所以 wrapper
在 fake-cred root 上下文里先 `cat /proc/kallsyms` 到 `/data/local/tmp/kall`，**只有**确认
`_text` 是真实非零地址时才导出该变量；否则删掉文件、不导出，让 ksud 走自己的
`/proc/kallsyms` 回退，并在不可读时以既有错误码失败——不会把全零表喂给 ksud。

> 这意味着 `kptr_restrict=2` 且没有逐构建快照的内核，handover 会失败并报明确错误。
> 当前受影响的只有两个 gate 构建（`g690108013dcc`、`6.6.127`）；其余构建与 Shark
> 自己一样依赖 root 上下文可读的 `/proc/kallsyms`。


## 覆盖范围

| runner | 覆盖的完整 `uname -r` |
| --- | --- |
| `libk61821.so` | `6.18.21-android17-5-gf957accaf563-ab15926176-4k`<br>`6.18.21-android17-5-g7fcbffcad3e1-ab16353812-4k` |
| `libk61269.so` | `6.12.69-android16-6-g242e1a07f878-ab15865446-4k`<br>`6.12.69-android16-6-g5fd39602326e-ab16372235-4k` |
| `libk61238.so` | `6.12.38-android16-5-g844001fb8721-ab14552068-4k` |
| `libk61258.so` | `6.12.58-android16-6-g7704a1ae279b-ab15213644-4k`<br>`6.12.58-android16-6-g0a092cc0037a-abogki521987229-4k`<br>`6.12.58-android16-6-g690108013dcc-abogki576129896-4k` |
| `libk61223.so` | `6.12.23-android16-5-g41f4cb1fa7c7-abogki465038634-4k` |
| `libk66118.so` | `6.6.118-android15-8-g9bc34d5b0c79-abogki537459655-4k`<br>`6.6.118-android15-8-gc4127a25dcf3-ab15863337-4k` |
| `libk66127.so` | `6.6.127-android15-8-gd489d4ad2a70-abogki567717946-4k` |

PD2546 的 `6.12.58-…-gdd6fd…` 仍走原来的 `louise` 引擎，行为不变。

## 重建

上游构建脚本是 `exploit/build-all.sh`（Rust `aarch64-linux-android` + Android NDK）。
本次收录的是上游 v2.2.2 的发布字节并逐个登记摘要；本仓库的构建直接使用这些字节，
不从 `.research` 或网络取任何二进制。需要重建时，用 `upstream/exploit` 按上游脚本构建，
更新 `manifest.json` 的摘要后再打包；`package.py` 会拒绝摘要不一致的 runner。
