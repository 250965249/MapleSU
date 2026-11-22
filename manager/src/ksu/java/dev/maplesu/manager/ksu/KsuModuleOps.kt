// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.util.zip.ZipFile
import java.util.Collections
import java.util.Properties
import java.util.UUID
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * `ksud module list` JSON → 现有 UI 行形状（1:1 映射）。
 *
 * ksud 输出是 `Vec<HashMap<String,String>>`：`module.prop` 全部键 + 
 * `enabled/update/remove/web/action/mount`（**值是字符串 "true"/"false"**）+ 可选
 * `actionIcon/webuiIcon/managedFeatures`。UI 侧约定见 `KsuCli.listModules` 的行形状。
 */
object KsuModuleListMapper {
    const val BACKEND_TAG = "ksu_ksud"

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private fun JsonObject.str(key: String): String? =
        (this[key] as? JsonPrimitive)?.takeIf { it.isString || it.content.isNotEmpty() }?.content

    private fun JsonObject.bool(key: String): Boolean = str(key)?.equals("true", true) == true

    private fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject

    /** `["a","b"]` 原样；缺失/类型不符 → `[]`（"没有"而不是"未知"）。 */
    private fun JsonObject.stringArray(key: String): JsonArray? = this[key] as? JsonArray

    private fun JsonArray.strings(): List<String> = mapNotNull { element ->
        (element as? JsonPrimitive)?.content?.takeIf { it.isNotEmpty() }
    }

    /**
     * `ksud module list` 的 key 集合会随 ksud 版本略有增减；这里把**确实存在**的
     * 元数据原样透传，缺失时给"空"而不是编一个值：
     *
     * - `updateJson`：`module.prop` 的 `updateJson=` 键（`ModuleListParsers` 依赖它做更新检查，
     *   以前整列缺失 → 即使列表接上，更新检查也永远没有数据）；
     * - `props`：`{applied:[], failed:[]}`（ksud 若上报 prop 应用结果则透传）；
     * - `stages`：`{<stage>:{status,code?,detail?}}`（同上）。
     */
    fun toUiJson(ksudJson: String): String {
        val root: JsonElement = json.parseToJsonElement(ksudJson)
        val array = root as? JsonArray ?: error("KSU_MODULE_LIST_NOT_ARRAY")
        val rows = buildJsonArray {
            array.forEach { element ->
                val obj = element as? JsonObject ?: error("KSU_MODULE_LIST_INVALID_ROW")
                val id = obj.str("id")?.ifEmpty { null } ?: error("KSU_MODULE_LIST_ID_MISSING")
                add(buildJsonObject {
                    put("id", id)
                    put("name", obj.str("name")?.ifEmpty { null } ?: id)
                    put("version", obj.str("version") ?: "")
                    put("versionCode", obj.str("versionCode")?.toIntOrNull() ?: 0)
                    put("author", obj.str("author") ?: "")
                    put("description", obj.str("description") ?: "")
                    put("enabled", obj.bool("enabled"))
                    put("update", obj.bool("update"))
                    put("remove", obj.bool("remove"))
                    put("web", obj.bool("web"))
                    put("action", obj.bool("action"))
                    put("metamodule", obj.str("metamodule")?.trim().let {
                        it == "1" || it.equals("true", true)
                    })
                    put("runtimeStatus", obj.str("runtimeStatus") ?: "")
                    put("preinit", obj.str("preinit") ?: "")
                    put("updateJson", obj.str("updateJson") ?: "")
                    put("canToggle", true)
                    put("unsupported", buildJsonArray {
                        obj.stringArray("unsupported")?.strings()?.forEach { add(JsonPrimitive(it)) }
                    })
                    put("props", buildJsonObject {
                        put("applied", buildJsonArray {
                            obj.obj("props")?.stringArray("applied")?.strings()
                                ?.forEach { add(JsonPrimitive(it)) }
                        })
                        put("failed", buildJsonArray {
                            obj.obj("props")?.stringArray("failed")?.strings()
                                ?.forEach { add(JsonPrimitive(it)) }
                        })
                    })
                    put("stages", obj.obj("stages") ?: buildJsonObject { })
                    put("backend", BACKEND_TAG)
                    put("builtin", false)
                    obj.str("actionIcon")?.let { put("actionIcon", it) }
                    obj.str("webuiIcon")?.let { put("webuiIcon", it) }
                    obj.str("managedFeatures")?.let { put("managedFeatures", it) }
                })
            }
        }
        return rows.toString()
    }

    fun count(ksudJson: String): Int {
        return (json.parseToJsonElement(toUiJson(ksudJson)) as JsonArray).size
    }
}

/** Retain the exact command receipt when list execution or decoding fails. */
class KsuModuleListException(val receipt: KsuShellResult, cause: Throwable? = null) :
    IllegalStateException("KSU_MODULE_LIST_FAILED:${receipt.code}:${receipt.errText}", cause)

/**
 * KSU 模块后端（`ModuleOps`）。
 *
 * 语义与现有 Lite 函数一一对应：列表/启停/卸载/撤销卸载/action；
 * 所有写操作先过命令构造的硬拒绝（模块 id 白名单正则），失败返回 false。
 */
class KsuModuleOps(
    private val backend: KsuCommandBackend,
    private val moduleInstallTimeoutMs: Long = KsuTimeouts.MODULE_INSTALL_MS,
) {
    private val available: Boolean get() = backend.daemonExists()

    fun isAvailable(): Boolean = available

    fun listJson(): String {
        val receipt = backend.runCommand(
            KsuCommands.module(backend.daemonPath(), "list"), KsuTimeouts.COMMAND_MS,
        )
        if (receipt.code != 0) throw KsuModuleListException(receipt)
        return try {
            KsuModuleListMapper.toUiJson(receipt.outText)
        } catch (error: Exception) {
            throw KsuModuleListException(receipt, error)
        }
    }

    fun count(): Int = (Json.parseToJsonElement(listJson()) as JsonArray).size

    fun toggle(id: String, enable: Boolean): Boolean {
        if (!available) {
            KsuLog.unavailable("KsuModuleOps", "ksud missing")
            return false
        }
        val cmd = try {
            KsuCommands.module(backend.daemonPath(), if (enable) "enable" else "disable", id)
        } catch (e: KsuCommandRejectedException) {
            KsuLog.rejected("KsuModuleOps", e.token)
            return false
        }
        val result = backend.runCommand(cmd, KsuTimeouts.COMMAND_MS)
        if (result.code != 0) KsuLog.record("module-toggle-failed", "id=$id enabled=$enable code=${result.code} err=${result.errText}")
        return result.code == 0
    }

    fun uninstall(id: String): Boolean = uninstallResult(id).code == 0

    fun uninstallResult(id: String): KsuShellResult = mutationResult("uninstall", id)

    fun undoUninstall(id: String): Boolean = undoUninstallResult(id).code == 0

    fun undoUninstallResult(id: String): KsuShellResult = mutationResult("undo-uninstall", id)

    private fun mutationResult(action: String, id: String): KsuShellResult {
        val cmd = try {
            KsuCommands.module(backend.daemonPath(), action, id)
        } catch (e: KsuCommandRejectedException) {
            KsuLog.rejected("KsuModuleOps", e.token)
            return KsuShellResult(-1, emptyList(), listOf("KSU_MODULE_ID_REJECTED:${e.token}"))
        }
        val result = backend.runCommand(cmd, KsuTimeouts.COMMAND_MS)
        if (result.code != 0) {
            KsuLog.record("module-$action-failed", "id=$id code=${result.code} err=${result.errText}")
        }
        return result
    }

    /**
     * `ksud module action <id>`：**不带 `-g`**，在**全局挂载命名空间**的 root shell 里执行，
     * 并把脚本的真实 stdout/stderr/退出码原样返回。
     *
     * 三处都与上游一一对应（开发文档 §10.3 D3/D4）：
     * - 命令形态：`"${ksud} module action $id"`（上游 `KsuCli.kt:283`）；
     * - 命名空间：`withNewRootShell(true)`（上游 `KsuCli.kt:282`）→ [KsuCommandBackend.runCommandInGlobalMount]；
     * - 输出：`to(stdoutCallback, stderrCallback)`（上游 `KsuCli.kt:284`）→ [KsuModuleActionResult.out]/[KsuModuleActionResult.err]。
     */
    fun action(
        id: String,
        onStdout: (String) -> Unit = {}, onStderr: (String) -> Unit = {},
    ): KsuModuleActionResult {
        val cmd = try {
            KsuCommands.moduleAction(backend.daemonPath(), id)
        } catch (e: KsuCommandRejectedException) {
            KsuLog.rejected("KsuModuleOps", e.token)
            return KsuModuleActionResult.rejected(e.token).also { onStderr(it.err) }
        }
        val result = backend.runCommandStreaming(cmd, KsuTimeouts.COMMAND_MS, globalMnt = true, onStdout, onStderr)
        if (result.code != 0) {
            KsuLog.record(
                "module-action-failed",
                "id=$id code=${result.code} err=${result.errText}",
            )
        }
        return KsuModuleActionResult(result.code, result.outText, result.errText)
    }

    fun install(zip: java.io.File): Boolean = installResult(zip).code == 0

    /** Like upstream moduleNeedsReboot: hot installs leave no live update marker. */
    fun needsReboot(zip: File): Boolean {
        val id = archiveModuleId(zip) ?: return true
        val dir = "/data/adb/modules/$id"
        return runCatching {
            backend.runCommand(
                listOf("/system/bin/sh", "-c", "[ -d '$dir' ] && [ ! -e '$dir/update' ]"),
                KsuTimeouts.COMMAND_MS,
            ).code != 0
        }.getOrDefault(true)
    }

    private fun archiveModuleId(zip: File): String? = runCatching {
        ZipFile(zip).use { archive ->
            val entry = archive.getEntry("module.prop") ?: return@use null
            val properties = Properties()
            archive.getInputStream(entry).reader(Charsets.UTF_8).use(properties::load)
            properties.getProperty("id")?.trim()?.takeIf(MODULE_ID_PATTERN::matches)
        }
    }.getOrNull()

    /** argv 和命令回执原样保留；负值表示未取得命令退出码。 */
    fun installResult(
        zip: java.io.File,
        onStdout: (String) -> Unit = {}, onStderr: (String) -> Unit = {},
    ): KsuShellResult {
        val out = Collections.synchronizedList(mutableListOf<String>())
        val err = Collections.synchronizedList(mutableListOf<String>())
        val nonce = UUID.randomUUID().toString().replace("-", "")
        val eventPrefix = "__MAPLESU_MODULE_LIVE_V1__$nonce:"
        val moduleId = archiveModuleId(zip)
        val retired = AtomicBoolean(false)
        fun consumeEvent(line: String): Boolean {
            if (!line.startsWith(eventPrefix)) return false
            val id = line.removePrefix(eventPrefix)
            if (id != moduleId) return false
            if (retired.compareAndSet(false, true)) ModuleWebUiSessions.committed(id)
            return true
        }
        return try {
            when {
                !zip.isFile -> KsuShellResult(
                    -1, emptyList(), listOf("MODULE_INSTALL_ARCHIVE_NOT_FILE:${zip.absolutePath}"),
                ).also { it.err.forEach(onStderr) }
                else -> {
                    val command = listOf(backend.daemonPath(), "module", "install", zip.absolutePath)
                    KsuLog.record(
                        "module-install-command",
                        "argv=${JsonArray(command.map { JsonPrimitive(it) })} timeoutMs=$moduleInstallTimeoutMs",
                    )
                    val invocation = listOf("/system/bin/env", "KSUD_MODULE_LIVE_EVENT=$nonce") + command
                    val result = backend.runCommandStreaming(invocation, moduleInstallTimeoutMs,
                        onStdout = { out.add(it); onStdout(it) },
                        onStderr = { if (!consumeEvent(it)) { err.add(it); onStderr(it) } })
                    val businessErrors = result.err.filterNot(::consumeEvent)
                    KsuLog.record("module-install-result", "code=${result.code}")
                    if (businessErrors.size == result.err.size) result else result.copy(err = businessErrors)
                }
            }
        } catch (error: Exception) {
            val causes = generateSequence(error as Throwable) { it.cause }.take(8).toList()
            if (causes.any { it is InterruptedException }) Thread.currentThread().interrupt()
            val failureCode = when {
                causes.any { it is TimeoutException } -> "MODULE_INSTALL_TIMEOUT"
                causes.any { it is InterruptedException } -> "MODULE_INSTALL_INTERRUPTED"
                causes.any { it is CancellationException } -> "MODULE_INSTALL_CANCELLED"
                out.isNotEmpty() || err.isNotEmpty() -> "MODULE_INSTALL_EXECUTION_FAILED"
                else -> "MODULE_INSTALL_START_FAILED"
            }
            val message = "$failureCode:" + causes.joinToString(" <- ") { "${it.javaClass.simpleName}:${it.message.orEmpty()}" }
            KsuLog.record("module-install-failed", message)
            onStderr(message)
            KsuShellResult(-1, synchronized(out) { out.toList() }, synchronized(err) { err.toList() } + message)
        }
    }

    companion object {
        private val MODULE_ID_PATTERN = Regex("^[a-zA-Z][a-zA-Z0-9._-]+$")

        fun unavailable(reason: String): KsuModuleOps {
            KsuLog.unavailable("KsuModuleOps", reason)
            return KsuModuleOps(KsuCommandBackend.unavailable(reason))
        }
    }
}
