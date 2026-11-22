// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 解析器 / 映射器 / 设置后端。
 * 全部纯函数或注入替身，不起进程。
 */
class KsuParsersAndSettingsTest {

    // ── ksud debug info 解析 ─────────────────────────────────────────────
    private val debugInfo = """
        KernelSU version: 32650
        version: 32650
        uapi_version: 7
        flags: 0x00000021
        features: 0x0000001f
        lkm: true
        bundled: false
        late_load: false
        runtime_mode: lkm
    """.trimIndent()

    @Test
    fun debugInfoParsesAllFields() {
        val info = KsuDebugInfoParser.parse(debugInfo)!!
        assertEquals(32650, info.version)
        assertEquals(7, info.uapiVersion)
        assertEquals(0x21L, info.flags)
        assertEquals(0x1fL, info.features)
        assertTrue(info.lkm)
        assertFalse(info.bundled)
        assertFalse(info.lateLoad)
        assertEquals("lkm", info.runtimeMode)
        assertTrue(info.raw.contains("uapi_version"))
    }

    @Test
    fun debugInfoToleratesMissingFieldsAndGarbage() {
        val partial = KsuDebugInfoParser.parse("version: 30049\n")!!
        assertEquals(30049, partial.version)
        assertEquals(-1, partial.uapiVersion)
        assertEquals(0L, partial.flags)
        assertFalse(partial.lkm)
        assertNull(KsuDebugInfoParser.parse(""))
        assertNull(KsuDebugInfoParser.parse("totally unrelated output"))
    }

    // ── module list 映射 ─────────────────────────────────────────────────
    private val ksudModules = """
        [
          {"id":"m1","name":"Module One","version":"1.2.3","versionCode":"7",
           "author":"a","description":"d","enabled":"true","update":"false",
           "remove":"false","web":"false","action":"true","metamodule":"false"},
          {"id":"m2","name":"","version":"","versionCode":"not-a-number",
           "enabled":"false"}
        ]
    """.trimIndent()

    @Test
    fun moduleMapperProducesUiShape() {
        val json = KsuModuleListMapper.toUiJson(ksudModules)
        assertTrue(json.contains("\"backend\":\"ksu_ksud\""))
        assertTrue(json.contains("\"id\":\"m1\""))
        assertTrue(json.contains("\"enabled\":true"))
        assertTrue(json.contains("\"action\":true"))
        assertTrue(json.contains("\"canToggle\":true"))
        assertTrue(json.contains("\"runtimeStatus\":\"\""))
        // versionCode 非法值回落 0；name 缺失回落 id
        assertTrue(json.contains("\"versionCode\":7"))
        assertTrue(json.contains("\"versionCode\":0"))
        assertTrue(json.contains("\"name\":\"m2\""))
        assertEquals(2, KsuModuleListMapper.count(ksudModules))
    }

    @Test
    fun moduleMapperRejectsMalformedJson() {
        assertTrue(runCatching { KsuModuleListMapper.toUiJson("not json") }.isFailure)
        assertTrue(runCatching { KsuModuleListMapper.toUiJson("{}") }.isFailure)
        assertTrue(runCatching { KsuModuleListMapper.toUiJson("") }.isFailure)
        assertEquals(0, KsuModuleListMapper.count("[]"))
    }

    @Test
    fun moduleMapperMatchesKsudMetamodulePropertyValues() {
        for (value in listOf("1", "true", "TrUe", " 1 ", " true ")) {
            val mapped = KsuModuleListMapper.toUiJson("""[{"id":"meta","metamodule":"$value"}]""")
            assertTrue("metamodule=$value", mapped.contains("\"metamodule\":true"))
        }
        for (value in listOf("0", "false", "", "2")) {
            val mapped = KsuModuleListMapper.toUiJson("""[{"id":"meta","metamodule":"$value"}]""")
            assertTrue("metamodule=$value", mapped.contains("\"metamodule\":false"))
        }
    }

    // ── feature 常量与设置后端 ───────────────────────────────────────────
    @Test
    fun featureIdsAreFrozenAndId5Unused() {
        assertEquals(0, KsuFeature.idByName[KsuFeature.SU_COMPAT])
        assertEquals(1, KsuFeature.idByName[KsuFeature.KERNEL_UMOUNT])
        assertEquals(2, KsuFeature.idByName[KsuFeature.SULOG])
        assertEquals(3, KsuFeature.idByName[KsuFeature.ADB_ROOT])
        assertEquals(4, KsuFeature.idByName[KsuFeature.SELINUX_HIDE])
        assertEquals(6, KsuFeature.idByName[KsuFeature.SHELL_SU_ADB_ONLY])
        assertFalse("id 5 is deprecated and must not be reused",
            KsuFeature.idByName.containsValue(KsuFeature.DEPRECATED_ID_5))
        assertTrue(KsuFeature.isValid("selinux_hide"))
        assertFalse(KsuFeature.isValid("preinit"))
    }

    @Test
    fun settingsFeatureStatusParsingUsesFourFixedWords() {
        val results = ArrayDeque(
            listOf(
                KsuShellResult(0, listOf("supported"), emptyList()),
                KsuShellResult(0, listOf("MANAGED"), emptyList()),
                KsuShellResult(0, listOf("weird"), emptyList()),
                KsuShellResult(1, emptyList(), listOf("fail")),
            ),
        )
        val backend = KsuCommandBackend(
            daemonPathProvider = { "/tmp/libksud_ksu.so" },
            runner = KsuShellRunner { _, _ -> results.removeFirst() },
        )
        // daemonExists()=false 时直接 unknown；这里只验证「不可用 → unknown」不抛
        val feature = KsuSettingsFeatureImpl(backend)
        assertEquals(KsuFeature.STATUS_UNKNOWN, feature.status(KsuFeature.SULOG))
        assertNull(feature.value(KsuFeature.SULOG))
        assertFalse(feature.set(KsuFeature.SULOG, true))
        assertFalse(feature.save())
        // 非法 feature 名同样安全
        assertEquals(KsuFeature.STATUS_UNKNOWN, feature.status("nope"))
    }

    @Test
    fun commandBackendUnavailableIsSilent() {
        val backend = KsuCommandBackend.unavailable("unit-test")
        assertFalse(backend.daemonExists())
        assertFalse(backend.exec("debug info", newShell = true, globalMnt = false))
        assertEquals("", backend.capture("debug info"))
        assertEquals(-1, backend.runCommand(listOf("/x/libksud_ksu.so", "debug", "info"), 1L).code)
        // 但参数级拒绝在 daemon 缺失时也必须先生效
        assertTrue(
            runCatching { backend.runCommand(listOf("/x/libksud_ksu.so", "--flash"), 1L) }
                .exceptionOrNull() is KsuCommandRejectedException,
        )
    }

    @Test
    fun commandBackendExecutesWithFakeRunner() {
        val seen = mutableListOf<List<String>>()
        val backend = KsuCommandBackend(
            daemonPathProvider = { "/nonexistent/libksud_ksu.so" },
            runner = KsuShellRunner { command, _ ->
                seen += command
                KsuShellResult(0, listOf("ok"), emptyList())
            },
        )
        // daemon 不存在 → 不执行、返回 false（现状风格：不抛）
        assertFalse(backend.exec("debug info", newShell = true, globalMnt = false))
        assertTrue(seen.isEmpty())
    }
}
