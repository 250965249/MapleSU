package dev.maplesu.manager.recovery

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.util.zip.ZipInputStream

/** 开机钩子模块 zip：结构/脚本内容/无密令；Ultra 格式审计与证据判定。 */
class BootHookModuleTest {
    private fun entries(): Set<String> {
        val names = mutableSetOf<String>()
        ZipInputStream(ByteArrayInputStream(BootHookModule.buildZip())).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                names += entry.name
            }
        }
        return names
    }

    private fun content(name: String): String {
        ZipInputStream(ByteArrayInputStream(BootHookModule.buildZip())).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                if (entry.name == name) return zip.readBytes().toString(Charsets.UTF_8)
            }
        }
        return ""
    }

    @Test
    fun zipContainsStandardModuleStructure() {
        assertEquals(
            setOf("module.prop", "service.sh", "post-fs-data.sh", "uninstall.sh"),
            entries(),
        )
        assertTrue(content("module.prop").contains("id=${BootHookModule.MODULE_ID}"))
    }

    @Test
    fun serviceScriptStartsDaemonFromRecoveryCopy() {
        val script = content("service.sh")
        assertTrue(script.contains(BootHookModule.RECOVERY_APK))
        assertTrue(script.contains(BootHookModule.DAEMON_CLASS))
        assertTrue(script.contains("app_process"))
        assertTrue(script.contains("--nice-name=maplesu-liteweb"))
        assertTrue(script.contains(BootHookModule.BOOT_LOG))
        assertTrue(script.contains(BootHookModule.PROBE_LOG))
        assertFalse("script must not reference installed APK sourceDir", script.contains("sourceDir"))
    }

    @Test
    fun scriptsNeverContainSecrets() {
        for (name in entries()) {
            val text = content(name)
            assertFalse("$name leaked token", text.contains("token="))
            assertFalse("$name leaked rootKey", text.contains("rootKey"))
            assertFalse("$name leaked 48-char key", Regex("[A-Za-z0-9]{48}").containsMatchIn(text))
        }
    }

    @Test
    fun uninstallScriptStopsDaemon() {
        assertTrue(content("uninstall.sh").contains("kill"))
    }

    @Test
    fun ultraModuleFormatRequiresDescriptorElf() {
        // 纯脚本 zip 不是合法 Ultra 模块（参考 zip 根级有 libmodule_*.so）；不得假装可安装。
        assertTrue(UltraModuleFormat.REQUIRES_DESCRIPTOR_ELF)
    }

    @Test
    fun evidenceProvenOnlyWhenScriptRanAndDaemonListening() {
        val base = BootHookEvidence(
            bootId = "boot-1", recordedAt = 1L, daemonPid = 123, port = 18427,
            moduleLog = "started", serviceScriptRan = true, daemonListening = true,
        )
        assertTrue(BootHookEvidence.proven(base))
        assertFalse(BootHookEvidence.proven(base.copy(serviceScriptRan = false)))
        assertFalse(BootHookEvidence.proven(base.copy(daemonListening = false)))
        assertFalse(BootHookEvidence.proven(base.copy(daemonPid = null)))
        assertFalse(BootHookEvidence.proven(null))
    }

    @Test
    fun evidenceJsonRoundTripsFields() {
        val evidence = BootHookEvidence(
            bootId = "boot-42", recordedAt = 99L, daemonPid = 7, port = 18437,
            moduleLog = "line1\nline2", serviceScriptRan = true, daemonListening = true,
        )
        val json = evidence.evidenceJson()
        assertTrue(json.contains("\"bootId\":\"boot-42\""))
        assertTrue(json.contains("\"daemonPid\":7"))
        assertTrue(json.contains("\"port\":18437"))
        assertTrue(json.contains("line1\\nline2"))
    }
}
