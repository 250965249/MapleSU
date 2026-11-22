// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.modules

import com.maplesu.core.data.model.Module
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Lite 模块列表解析的**字段级等价性测试**（W13 审计项）。
 *
 * 目的：证明「内联 `JSONArray` 解析」重构为 `JsonModuleListParser`（org.json 取值）
 * + [ModuleRowMapper]（纯映射）后，**同一输入行的每个字段输出完全一致**。
 *
 * JVM 主机无法加载 Android 的 `org.json`（android.jar 是 stub），因此：
 * - 旧实现 = 下面 [LegacyLiteModuleParser]，**逐字复制**改动前 `ModuleRepositoryImpl.parseModules`
 *   的字段表达式，运行在 [LegacyJsonObject]（纯 Kotlin，语义对齐 org.json 的
 *   `getString/optString/optInt/getBoolean/optBoolean/has/isNull/getInt/optJSONArray/optJSONObject`）上；
 * - 新实现 = [fromRawRow]（与 `JsonModuleListParser.fromJson` 逐条一致的取值镜像）
 *   + 生产映射 [ModuleRowMapper.map]；
 * - 两侧对**同一批边界行**做 `assertEquals(Module, Module)`（data class 即逐字段比较）。
 *
 * 真实 JSON 字符串 → `JsonModuleListParser.parse()` 的整链等价由设备侧
 * `androidTest/.../ModuleListParserEquivalenceAndroidTest.kt` 覆盖（那里 org.json 可用）。
 */
class ModuleListParserEquivalenceTest {

    // ── 旧实现（逐字复制自改动前 ModuleRepositoryImpl.parseModules）────────────

    private class LegacyArray(private val items: List<String>) {
        fun length(): Int = items.size
        fun optString(index: Int): String = items[index]
        fun toStringList(): List<String> = items
    }

    private class LegacyJsonObject(private val raw: Map<String, Any?>) {
        fun getString(key: String): String = raw[key] as? String
            ?: throw IllegalArgumentException("no string: $key")

        fun optString(key: String): String = raw[key] as? String ?: ""
        fun optString(key: String, def: String): String = raw[key] as? String ?: def
        fun optInt(key: String): Int = raw[key] as? Int ?: 0
        fun optInt(key: String, def: Int): Int = raw[key] as? Int ?: def
        fun getBoolean(key: String): Boolean = raw[key] as? Boolean
            ?: throw IllegalArgumentException("no boolean: $key")

        fun optBoolean(key: String): Boolean = raw[key] as? Boolean ?: false
        fun optBoolean(key: String, def: Boolean): Boolean = raw[key] as? Boolean ?: def
        fun has(key: String): Boolean = raw.containsKey(key)
        fun isNull(key: String): Boolean = raw.containsKey(key) && raw[key] == null
        fun getInt(key: String): Int = raw[key] as? Int
            ?: throw IllegalArgumentException("no int: $key")

        fun optJSONArray(key: String): LegacyArray? {
            val list = raw[key] as? List<*> ?: return null
            return LegacyArray(list.map { it?.toString() ?: "" })
        }

        fun optJSONObject(key: String): LegacyJsonObject? {
            val map = raw[key] as? Map<*, *> ?: return null
            return LegacyJsonObject(map.entries.associate { (k, v) -> k.toString() to v })
        }
    }

    /** 改动前 `parseModules` 的字段表达式，逐字保留（仅把 JSONObject 换成 LegacyJsonObject）。 */
    private object LegacyLiteModuleParser {
        fun parse(rows: List<Map<String, Any?>>): List<Module> {
            return rows.map { raw ->
                val obj = LegacyJsonObject(raw)
                Module(
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
                    unsupported = obj.optJSONArray("unsupported")?.toStringList() ?: emptyList(),
                    propsApplied = obj.optJSONObject("props")?.optJSONArray("applied")?.toStringList() ?: emptyList(),
                    propsFailed = obj.optJSONObject("props")?.optJSONArray("failed")?.toStringList() ?: emptyList(),
                    builtin = obj.optBoolean("builtin", false),
                )
            }
        }
    }

    // ── 新实现：与 JsonModuleListParser.fromJson 逐条一致的取值镜像（org.json 调用 → Map 取值）──

    private fun fromRawRow(raw: Map<String, Any?>): ModuleListRow {
        fun str(key: String): String = raw[key] as? String ?: ""
        fun str(key: String, def: String): String = raw[key] as? String ?: def
        fun int(key: String, def: Int): Int = raw[key] as? Int ?: def
        fun bool(key: String, def: Boolean): Boolean = raw[key] as? Boolean ?: def
        fun requiredBool(key: String): Boolean = raw[key] as? Boolean
            ?: throw IllegalArgumentException("no boolean: $key")
        fun requiredInt(key: String): Int = raw[key] as? Int
            ?: throw IllegalArgumentException("no int: $key")
        fun stringList(key: String): LegacyArray? {
            val list = raw[key] as? List<*> ?: return null
            return LegacyArray(list.map { it?.toString() ?: "" })
        }

        return ModuleListRow(
            id = raw["id"] as? String ?: throw IllegalArgumentException("no id"),
            name = str("name"),
            author = str("author", "Unknown"),
            version = str("version", "Unknown"),
            versionCode = int("versionCode", 0),
            description = str("description"),
            enabled = requiredBool("enabled"),
            update = bool("update", false),
            remove = requiredBool("remove"),
            updateJson = str("updateJson"),
            hasWebUi = bool("web", false),
            hasActionScript = bool("action", false),
            metamodule = (int("metamodule", 0) != 0) || bool("metamodule", false),
            actionIconPath = str("actionIcon").takeIf { it.isNotBlank() },
            webUiIconPath = str("webuiIcon").takeIf { it.isNotBlank() },
            runtimeStatus = str("runtimeStatus"),
            runtimeExitCode = if (raw.containsKey("runtimeExitCode") && raw["runtimeExitCode"] != null) {
                requiredInt("runtimeExitCode")
            } else {
                null
            },
            canToggle = bool("canToggle", true),
            unsupported = stringList("unsupported")?.toStringList() ?: emptyList(),
            propsApplied = (raw["props"] as? Map<*, *>)?.let { props ->
                val map = props.entries.associate { (k, v) -> k.toString() to v }
                LegacyJsonObject(map).optJSONArray("applied")?.toStringList() ?: emptyList()
            } ?: emptyList(),
            propsFailed = (raw["props"] as? Map<*, *>)?.let { props ->
                val map = props.entries.associate { (k, v) -> k.toString() to v }
                LegacyJsonObject(map).optJSONArray("failed")?.toStringList() ?: emptyList()
            } ?: emptyList(),
            builtin = bool("builtin", false),
        )
    }

    private fun newParse(rows: List<Map<String, Any?>>): List<Module> =
        rows.map { ModuleRowMapper.map(fromRawRow(it)) }

    // ── 边界行 ────────────────────────────────────────────────────────────

    private fun row(vararg pairs: Pair<String, Any?>): Map<String, Any?> = mapOf(*pairs)

    private val minimalRow = row("id" to "min", "enabled" to true, "remove" to false)

    private val fullRow = row(
        "id" to "t4-module",
        "name" to "T4 Module",
        "author" to "Maple",
        "version" to "1.2.3",
        "versionCode" to 123,
        "description" to "desc",
        "enabled" to false,
        "update" to true,
        "remove" to true,
        "updateJson" to "https://example/update.json",
        "web" to true,
        "action" to true,
        "metamodule" to 1,
        "actionIcon" to "/data/adb/modules/t4/action.png",
        "webuiIcon" to "/data/adb/modules/t4/webui.png",
        "runtimeStatus" to "running",
        "runtimeExitCode" to 0,
        "canToggle" to false,
        "unsupported" to listOf("stop", "in-place-update"),
        "props" to mapOf("applied" to listOf("a=1"), "failed" to listOf("b=2:reason")),
        "builtin" to true,
    )

    private val rows: Map<String, Map<String, Any?>> = mapOf(
        "minimal defaults" to minimalRow,
        "full row" to fullRow,
        "runtimeExitCode absent" to minimalRow + ("runtimeStatus" to "x"),
        "runtimeExitCode null" to minimalRow + ("runtimeExitCode" to null),
        "runtimeExitCode positive" to minimalRow + ("runtimeExitCode" to 137),
        "runtimeExitCode zero" to minimalRow + ("runtimeExitCode" to 0),
        "props missing" to minimalRow + ("runtimeStatus" to ""),
        "props applied only" to minimalRow + ("props" to mapOf("applied" to listOf("k=v"))),
        "props failed only" to minimalRow + ("props" to mapOf("failed" to listOf("k=v:err"))),
        "props empty lists" to minimalRow + ("props" to mapOf("applied" to emptyList<Any>(), "failed" to emptyList<Any>())),
        "metamodule bool true" to minimalRow + ("metamodule" to true),
        "metamodule int zero bool false" to minimalRow + ("metamodule" to 0),
        "icons blank" to (minimalRow + mapOf("actionIcon" to "", "webuiIcon" to "   ")),
        "unsupported empty" to minimalRow + ("unsupported" to emptyList<Any>()),
        "canToggle absent" to minimalRow,
        "builtin absent" to minimalRow,
        "version defaults" to row("id" to "v", "enabled" to false, "remove" to false),
        "web/action false" to (minimalRow + mapOf("web" to false, "action" to false)),
    )

    @Test
    fun everyFieldMatchesLegacyParserAcrossBoundaryRows() {
        val expected = LegacyLiteModuleParser.parse(rows.values.toList())
        val actual = newParse(rows.values.toList())
        assertEquals("row count", expected.size, actual.size)
        rows.keys.zip(expected.zip(actual)).forEach { (name, pair) ->
            assertEquals("$name: parsed Module must be field-by-field identical", pair.first, pair.second)
        }
    }

    @Test
    fun defaultsAndNullSemanticsArePreserved() {
        val minimal = newParse(listOf(minimalRow)).single()
        assertEquals("", minimal.name)
        assertEquals("Unknown", minimal.author)
        assertEquals("Unknown", minimal.version)
        assertEquals(0, minimal.versionCode)
        assertEquals("", minimal.description)
        assertEquals("", minimal.updateJson)
        assertNull(minimal.runtimeExitCode)
        assertTrue(minimal.canToggle)
        assertTrue(minimal.unsupported.isEmpty())
        assertTrue(minimal.propsApplied.isEmpty())
        assertTrue(minimal.propsFailed.isEmpty())
        assertEquals(false, minimal.builtin)
        assertNull(minimal.actionIconPath)
        assertNull(minimal.webUiIconPath)
    }

    @Test
    fun runtimeExitCodeNullAndAbsentBothMapToNullButZeroIsKept() {
        assertNull(newParse(listOf(minimalRow + ("runtimeExitCode" to null))).single().runtimeExitCode)
        assertNull(newParse(listOf(minimalRow)).single().runtimeExitCode)
        assertEquals(0, newParse(listOf(minimalRow + ("runtimeExitCode" to 0))).single().runtimeExitCode)
        assertEquals(137, newParse(listOf(minimalRow + ("runtimeExitCode" to 137))).single().runtimeExitCode)
    }

    @Test
    fun metamoduleAcceptsIntAndBooleanForms() {
        assertEquals(true, newParse(listOf(minimalRow + ("metamodule" to 1))).single().metamodule)
        assertEquals(true, newParse(listOf(minimalRow + ("metamodule" to 2))).single().metamodule)
        assertEquals(true, newParse(listOf(minimalRow + ("metamodule" to true))).single().metamodule)
        assertEquals(false, newParse(listOf(minimalRow + ("metamodule" to 0))).single().metamodule)
        assertEquals(false, newParse(listOf(minimalRow + ("metamodule" to false))).single().metamodule)
    }

    @Test
    fun t4ReceiptFieldsSurviveMapping() {
        val full = newParse(listOf(fullRow)).single()
        assertEquals(listOf("stop", "in-place-update"), full.unsupported)
        assertEquals(listOf("a=1"), full.propsApplied)
        assertEquals(listOf("b=2:reason"), full.propsFailed)
        assertTrue(full.builtin)
        assertEquals(false, full.canToggle)
        assertEquals("/data/adb/modules/t4/action.png", full.actionIconPath)
        assertEquals("/data/adb/modules/t4/webui.png", full.webUiIconPath)
        assertEquals(0, full.runtimeExitCode)
    }
}
