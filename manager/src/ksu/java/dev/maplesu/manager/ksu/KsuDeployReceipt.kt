// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * 部署回执（开发文档 T1：「部署成功后写 `filesDir/ksu_deploy.json`」）。
 *
 * 记的是**这一次部署实证过的事实**，不是意图：
 * ```
 * {sha256, version, uapiVersion, busyboxOk, deployedAt, kernelVersionAtDeploy}
 * ```
 *
 * 三条硬规则：
 * 1. **落点在 App 私有目录**（`context.filesDir`）。绝不写 `/data/adb/ksu`：
 *    那是 ksud 的安装目录，管理器只读；往那里写会与 `ksud install` 抢同一棵树。
 * 2. **写用 tmp + rename**：中途掉电只会留下 `*.tmp`，不会产生半截 JSON 让下次启动
 *    把"坏回执"当成"好回执"。
 * 3. **读失败返回 `null`**（缺失/坏 JSON/字段不合法），不抛、不猜。
 *
 * ⚠️ 回执**不是**部署判据：[KsuBootstrap.ensureDeployed] 每轮都重新实证内容摘要、
 * 版本与 busybox（T1 禁止"存在/有回执就算对"）。回执是给诊断与 T3 启动链自检用的
 * 事实记录。
 */
data class KsuDeployReceipt(
    /** 部署后 `/data/adb/ksud` 的实测 SHA-256（= APK 内 `libksud_ksu.so` 的摘要，G6）。 */
    val sha256: String,
    /** `ksud debug info` 的 `version`（部署时实证）。 */
    val version: Int,
    /** `ksud debug info` 的 `uapi_version`（部署时实证；本构建要求 7）。 */
    val uapiVersion: Int,
    /** `/data/adb/ksu/bin/busybox true` 退出码 == 0（A11）。 */
    val busyboxOk: Boolean,
    /** 部署完成时刻（epoch millis，`KsuBootstrap` 注入的 clock）。 */
    val deployedAt: Long,
    /** 部署时的内核版本（`kernelVersionAtDeploy`；默认 Android `os.version`）。 */
    val kernelVersionAtDeploy: String,
) {
    /** 稳定 JSON 形状（字段固定；便于设备上人工 `cat` 与测试逐字段断言）。 */
    fun toJson(): String = buildJsonObject {
        put("sha256", sha256)
        put("version", version)
        put("uapiVersion", uapiVersion)
        put("busyboxOk", busyboxOk)
        put("deployedAt", deployedAt)
        put("kernelVersionAtDeploy", kernelVersionAtDeploy)
    }.toString()

    companion object {
        /** App 私有目录下的文件名（`filesDir/ksu_deploy.json`）。 */
        const val FILE_NAME = "ksu_deploy.json"

        private val SHA256_PATTERN = Regex("^[0-9a-f]{64}$")

        private val json = Json { ignoreUnknownKeys = true; isLenient = true }

        /**
         * 解析回执 JSON；任何不合法（坏 JSON / 缺字段 / 摘要不是 64 位小写 hex）→ `null`。
         *
         * `busyboxOk`/`deployedAt`/`kernelVersionAtDeploy` 缺失时给出**保守默认**
         * （`false` / `0` / `""`）：它们不是身份字段，不值得把整份回执判成坏档；
         * 而 `sha256`/`version`/`uapiVersion` 缺失即"没有回执"。
         */
        fun parse(text: String): KsuDeployReceipt? {
            if (text.isBlank()) return null
            val obj = runCatching { json.parseToJsonElement(text) }
                .getOrNull() as? JsonObject ?: return null

            fun value(key: String): JsonPrimitive? = obj[key] as? JsonPrimitive

            val sha = value("sha256")?.contentOrNull?.trim() ?: return null
            if (!SHA256_PATTERN.matches(sha)) return null
            val version = value("version")?.intOrNull ?: return null
            val uapiVersion = value("uapiVersion")?.intOrNull ?: return null
            return KsuDeployReceipt(
                sha256 = sha,
                version = version,
                uapiVersion = uapiVersion,
                busyboxOk = value("busyboxOk")?.booleanOrNull ?: false,
                deployedAt = value("deployedAt")?.longOrNull ?: 0L,
                kernelVersionAtDeploy = value("kernelVersionAtDeploy")?.contentOrNull ?: "",
            )
        }

        /** 读回执；文件缺失/不可读/不是合法回执 → `null`（不抛）。 */
        fun read(file: File): KsuDeployReceipt? =
            runCatching { parse(file.readText()) }.getOrNull()

        /**
         * 原子写回执（tmp + rename）：先写 `<name>.tmp`，再 `renameTo` 目标。
         *
         * 返回 `false`（不抛）表示没写成——调用方必须把这条事实留在日志/结果里，
         * 但**不能**因为回执写失败就把已通过的部署改判成失败（部署结论由内容摘要、
         * 版本、busybox 三项实证决定）。
         */
        fun write(file: File, receipt: KsuDeployReceipt): Boolean {
            val parent = file.parentFile ?: return false
            if (!parent.isDirectory && !parent.mkdirs()) return false
            val tmp = File(parent, file.name + ".tmp")
            return try {
                tmp.writeText(receipt.toJson())
                // Android 的 renameTo 不保证覆盖已存在目标：先删旧档，失败即放弃。
                if (file.exists() && !file.delete()) return false
                tmp.renameTo(file)
            } catch (t: Throwable) {
                KsuLog.record("deploy-receipt", "${t.javaClass.simpleName}: ${t.message}")
                false
            } finally {
                // rename 成功后 tmp 已不存在；失败路径必须清掉半截文件。
                if (tmp.exists()) runCatching { tmp.delete() }
            }
        }
    }
}
