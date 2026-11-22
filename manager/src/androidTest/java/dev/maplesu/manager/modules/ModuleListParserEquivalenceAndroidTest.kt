// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.modules

import com.maplesu.core.data.model.Module
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Lite 模块列表解析的设备侧整链等价性（W13 审计项）。
 *
 * 主机 JVM 用假 `org.json` 无法执行真实 JSON；这里在设备上对**同一 JSON 字符串**比较：
 * - 旧实现：本文件 [legacyParse]，逐字复制改动前 `ModuleRepositoryImpl.parseModules` 的
 *   `JSONArray`/`JSONObject` 表达式；
 * - 新实现：[JsonModuleListParser.parse]（org.json 取值 + [ModuleRowMapper]）。
 *
 * 覆盖边界行：缺省字段、`runtimeExitCode` 缺失/null/0/正整数、props 缺失/部分/空表、
 * `metamodule` int/boolean、图标空串、`builtin`、以及含引号/换行/Unicode 转义的描述。
 * `Module` 是 data class，`assertEquals` 即逐字段比较。
 */
class ModuleListParserEquivalenceAndroidTest {

    private val boundaryJson = """
        [
          {"id":"min","enabled":true,"remove":false},
          {"id":"full","name":"Full","author":"Maple","version":"1.2.3","versionCode":123,
           "description":"desc","enabled":false,"update":true,"remove":true,
           "updateJson":"https://example/update.json","web":true,"action":true,
           "metamodule":1,"actionIcon":"/a.png","webuiIcon":"/w.png",
           "runtimeStatus":"running","runtimeExitCode":0,"canToggle":false,
           "unsupported":["stop","in-place-update"],
           "props":{"applied":["a=1"],"failed":["b=2:reason"]},"builtin":true},
          {"id":"exit-null","enabled":true,"remove":false,"runtimeExitCode":null},
          {"id":"exit-positive","enabled":true,"remove":false,"runtimeExitCode":137},
          {"id":"props-partial","enabled":true,"remove":false,"props":{"applied":["k=v"]}},
          {"id":"props-empty","enabled":true,"remove":false,"props":{"applied":[],"failed":[]}},
          {"id":"metamodule-bool","enabled":true,"remove":false,"metamodule":true},
          {"id":"metamodule-zero","enabled":true,"remove":false,"metamodule":0},
          {"id":"icons-blank","enabled":true,"remove":false,"actionIcon":"","webuiIcon":"   "},
          {"id":"escaped","name":"a\"b\nc\\d","description":"中文 · é · \u00e9","enabled":true,"remove":false}
        ]
    """.trimIndent()

    @Test
    fun newParserMatchesLegacyInlineMappingOnSameJson() {
        assertEquals(legacyParse(boundaryJson), JsonModuleListParser.parse(boundaryJson))
    }

    /** 改动前 `ModuleRepositoryImpl.parseModules` 的逐字副本（仅提取为测试方法）。 */
    private fun legacyParse(result: String): List<Module> {
        val array = JSONArray(result)
        return (0 until array.length())
            .asSequence()
            .map { array.getJSONObject(it) }
            .map { obj ->
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
                    unsupported = obj.optJSONArray("unsupported").toStringList(),
                    propsApplied = obj.optJSONObject("props")?.optJSONArray("applied").toStringList(),
                    propsFailed = obj.optJSONObject("props")?.optJSONArray("failed").toStringList(),
                    builtin = obj.optBoolean("builtin", false),
                )
            }.toList()
    }

    private fun JSONArray?.toStringList(): List<String> =
        if (this == null) emptyList() else (0 until length()).map { optString(it) }
}
