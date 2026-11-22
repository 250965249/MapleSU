// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.modules

import com.maplesu.core.data.model.Module
import org.json.JSONArray
import org.json.JSONObject

/**
 * 模块列表一行的**原始取值**（JSON 层语义已按旧实现解析完毕：`optString` 默认值、
 * `optInt`、`optBoolean`、`getBoolean` 的必需性、`runtimeExitCode` 的 null/缺失区分）。
 *
 * 纯 Kotlin、无 Android 依赖 → 字段映射 ([ModuleRowMapper]) 可在 JVM 主机单测里与
 * 旧解析实现做逐字段等价性比对（`ModuleListParserEquivalenceTest`）。
 */
data class ModuleListRow(
    val id: String,
    val name: String,
    val author: String,
    val version: String,
    val versionCode: Int,
    val description: String,
    val enabled: Boolean,
    val update: Boolean,
    val remove: Boolean,
    val updateJson: String,
    val hasWebUi: Boolean,
    val hasActionScript: Boolean,
    val metamodule: Boolean,
    val actionIconPath: String?,
    val webUiIconPath: String?,
    val runtimeStatus: String,
    val runtimeExitCode: Int?,
    val canToggle: Boolean,
    val unsupported: List<String>,
    val propsApplied: List<String>,
    val propsFailed: List<String>,
    val builtin: Boolean,
    val needsReboot: Boolean = false,
    val preinit: String = "",
    val webUiInfoJson: String? = null,
)

/**
 * `ModuleListRow` → `Module` 的**纯映射**（无 JSON/Android 依赖）。
 *
 * 每条表达式与改动前 `ModuleRepositoryImpl.parseModules` 中的同名参数一一对应；
 * 等价性由 `ModuleListParserEquivalenceTest` 用旧实现（逐字复制）做字段级断言。
 */
object ModuleRowMapper {
    fun map(row: ModuleListRow): Module = Module(
        id = row.id,
        name = row.name,
        author = row.author,
        version = row.version,
        versionCode = row.versionCode,
        description = row.description,
        enabled = row.enabled,
        update = row.update,
        remove = row.remove,
        updateJson = row.updateJson,
        hasWebUi = row.hasWebUi,
        hasActionScript = row.hasActionScript,
        metamodule = row.metamodule,
        actionIconPath = row.actionIconPath,
        webUiIconPath = row.webUiIconPath,
        runtimeStatus = row.runtimeStatus,
        runtimeExitCode = row.runtimeExitCode,
        canToggle = row.canToggle,
        unsupported = row.unsupported,
        propsApplied = row.propsApplied,
        propsFailed = row.propsFailed,
        builtin = row.builtin,
        needsReboot = row.needsReboot,
        preinit = row.preinit,
        webUiInfoJson = row.webUiInfoJson,
    )
}

/**
 * 模块列表 JSON → 领域模型的生产解析器（W13）。
 *
 * 两层：`org.json` 取值（[fromJson]，与改动前 `parseModules` 的 opt/get 调用逐条一致）
 * + 纯映射 [ModuleRowMapper]。JVM 单测注入 [ModuleListParser] fake，避免 android.jar stub 的
 * `Method length in org.json.JSONArray not mocked`；映射层由主机等价性测试直接覆盖。
 */
object JsonModuleListParser : ModuleListParser {
    override fun parse(json: String): List<Module> {
        val array = JSONArray(json)
        return (0 until array.length())
            .asSequence()
            .map { array.getJSONObject(it) }
            .map(::fromJson)
            .map(ModuleRowMapper::map)
            .toList()
    }

    /** 与旧实现逐条一致的 org.json 取值；字段顺序/默认值不得改动。 */
    internal fun fromJson(obj: JSONObject): ModuleListRow = ModuleListRow(
        id = obj.getString("id"),
        name = obj.optString("name"),
        author = obj.optString("author", "Unknown"),
        version = obj.optString("version", "Unknown"),
        versionCode = obj.optInt("versionCode", 0),
        description = obj.optString("description"),
        enabled = obj.getBoolean("enabled"),
        update = obj.optBoolean("update"),
        remove = obj.getBoolean("remove"),
        updateJson = obj.optString("updateJson"),
        hasWebUi = obj.optBoolean("web"),
        hasActionScript = obj.optBoolean("action"),
        metamodule = (obj.optInt("metamodule") != 0) || obj.optBoolean("metamodule"),
        actionIconPath = obj.optString("actionIcon").takeIf { it.isNotBlank() },
        webUiIconPath = obj.optString("webuiIcon").takeIf { it.isNotBlank() },
        runtimeStatus = obj.optString("runtimeStatus"),
        runtimeExitCode = if (obj.has("runtimeExitCode") && !obj.isNull("runtimeExitCode")) {
            obj.getInt("runtimeExitCode")
        } else {
            null
        },
        canToggle = obj.optBoolean("canToggle", true),
        // T4: capability and property receipts are part of the module
        // contract; an empty list is a real "none", not "unknown".
        unsupported = obj.optJSONArray("unsupported").toStringList(),
        propsApplied = obj.optJSONObject("props")?.optJSONArray("applied").toStringList(),
        propsFailed = obj.optJSONObject("props")?.optJSONArray("failed").toStringList(),
        builtin = obj.optBoolean("builtin", false),
        needsReboot = obj.optBoolean("needsReboot", false),
        preinit = obj.optString("preinit"),
        webUiInfoJson = if (obj.optBoolean("web")) obj.toString() else null,
    )

    private fun JSONArray?.toStringList(): List<String> =
        if (this == null) emptyList() else (0 until length()).map { optString(it) }
}
