# SDK 接入指南

`client/` 提供 Android Binder 客户端，面向需要在用户授权后执行 Root 命令的应用。它不携带 Root 凭据，不链接原生 SDK，也不为应用增加权限或组件。客户端可独立构建；实际会话依赖已安装 Manager 发布的可用执行器。

## 接入工程

当前最低版本为 Android 12 / API 31，工程使用 JDK 21、Android SDK 37。仓库内应用直接依赖客户端模块：

```kotlin
dependencies {
    implementation(project(":maplesu-client"))
}
```

独立工程可构建并导入 `maplesu-client-release.aar`：

```shell
./gradlew :maplesu-client:assembleRelease
```

```kotlin
dependencies {
    implementation(files("libs/maplesu-client-release.aar"))
}
```

目前没有发布 Maven 坐标。不要通过猜测坐标或版本引入其他同名库。

## 声明包可见性

在应用清单中声明 Manager 包名，以便客户端检查安装身份：

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <queries>
        <package android:name="dev.maplesu.manager" />
    </queries>
    <application />
</manifest>
```

客户端通过显式组件连接 `dev.maplesu.manager.runtime.NativeSuBrokerService`，action 为 `dev.maplesu.manager.action.NATIVE_SU_PEEK`。AIDL 包名是协议的一部分，保持 `dev.maplesu.manager.runtime`。

## 校验 Manager 签名

`CooperativeSuClient` 要求接入方传入信任的 Manager 签名证书 SHA-256 集合。使用发布渠道提供的证书摘要，或对自己构建并信任的 APK 执行：

```shell
apksigner verify --print-certs manager-release.apk
```

传入证书摘要的连续十六进制文本。APK 文件摘要和签名证书摘要是不同值；不要把启动时从未知安装包自动读取的值直接加入信任集合。项目当前未在文档中声明统一的发布证书。

## 执行一个短命令

下面的同步函数应在工作线程调用。`trustedManagerSigners` 由接入应用的可信配置提供，执行前先在 MapleSU 中为该应用设置授权。

```kotlin
import android.content.Context
import dev.maplesu.client.CooperativeSuClient
import dev.maplesu.client.SuRequest

fun readRootUid(context: Context, trustedManagerSigners: Set<String>): String {
    CooperativeSuClient(
        context = context,
        expectedSignerSha256 = trustedManagerSigners,
    ).use { client ->
        client.connect(timeoutMillis = 10_000)
        client.start(
            SuRequest(
                executable = "/system/bin/id",
                arguments = listOf("id", "-u"),
            ),
        ).use { session ->
            session.stdin.close()
            val output = session.stdout.bufferedReader().readText()
            val error = session.stderr.bufferedReader().readText()
            val exit = session.awaitExit(5_000)
            check(exit == 0) { "Root command failed: exit=$exit, stderr=$error" }
            return output.trim()
        }
    }
}
```

示例只执行输出很小的系统命令。通用命令应并发读取 stdout 与 stderr，避免管道写满，并为输出总量和执行时长设置边界。超时后调用 `cancel()`，随后关闭会话。

公开发现入口只返回已经发布的执行器。客户端会在连接期限内重试“未就绪”状态，连接本身不启动提权、不代替用户授权。

## 请求参数

| 参数 | 契约 |
| --- | --- |
| `executable` | 可执行文件的绝对路径 |
| `arguments` | 包含 `argv[0]`；1–256 项 |
| `environment` | `NAME=value` 条目，最多 512 项；默认空列表 |
| `directory` | 绝对工作目录，默认 `/` |
| `targetUid` | 子进程目标 UID，默认 0；由后端授权和能力决定 |
| `globalMount` | 请求全局 mount namespace，后端可以拒绝 |
| `terminals` | 位 0/1/2 分别选择 stdin/stdout/stderr 是否接入 PTY；0–7 |
| `window` | `rows, cols, xpixel, ypixel` 四项，均为 0–65535 |

字符串按 UTF-8 编码，拒绝 NUL 和有损编码。文本总量上限 131072 字节，编码帧上限 140000 字节。请求体不包含调用者身份和底层凭据；授权依据来自 Binder 的真实 UID。

## 会话与终端

| API | 行为 |
| --- | --- |
| `stdin` / `stdout` / `stderr` | 会话拥有的流，用完关闭 |
| `awaitExit(timeoutMillis)` | 等待 0–30000 ms；未结束返回 `null`，结束返回 0–255 |
| `exitCode` | 最近一次观察到的退出码，初始 `null` |
| `openTerminal()` | 认领 PTY master；每个会话最多一次 |
| `resize(rows, cols, xpixel, ypixel)` | 更新终端尺寸 |
| `signal(signal)` | 支持 INT、TERM、HUP、QUIT、TSTP、CONT |
| `cancel()` | 请求终止会话的进程组 |
| `close()` | 关闭远端会话与本地流，可重复调用 |

PTY 请求选中的流应从 `openTerminal()` 返回的描述符读写，不再从对应的普通管道等待数据；接入应用负责关闭该终端描述符。执行器重启后创建新的客户端连接，不复用失效的会话。

## 处理错误

捕获 `CooperativeSuException` 并按稳定的 `code` 分支。不要解析翻译后的提示文本，也不要把所有错误无限重试。

| 错误码 | 处理方式 |
| --- | --- |
| `SU_MANAGER_NOT_INSTALLED` | 提示安装受信任的 Manager |
| `SU_MANAGER_SIGNATURE_MISMATCH` | 停止连接并核对发布渠道或构建身份 |
| `SU_SIGNER_POLICY_EMPTY` | 修正接入应用的证书配置 |
| `SU_EXECUTOR_NOT_READY` / `SU_CONNECT_TIMEOUT` | 提示用户在 Manager 中检查运行状态 |
| `AUTH_NOT_GRANTED` / `AUTH_DISABLED` | 由用户在 Manager 中调整授权 |
| `AUTH_REVOKED` / `AUTH_IDENTITY_CHANGED` | 结束旧会话，重新确认授权身份 |
| `SU_SESSION_LIMIT` | 释放空闲会话后再申请 |
| `SU_EXECUTOR_DIED` / `SU_SESSION_CLOSED` | 关闭旧对象，在合适时机重新连接 |
| `SU_REQUEST_INVALID` / `SU_FRAME_TOO_LARGE` | 修正请求参数 |

源码入口是 `CooperativeSuClient`、`SuRequest`、`SuSession` 和 `CooperativeSuException`。完整接入示例及独立 UID 测试位于 `consumer/`。Ultra 原生模块接口属于另一条接入路径，见[原生模块指南](ULTRA_MODULES.md)。
