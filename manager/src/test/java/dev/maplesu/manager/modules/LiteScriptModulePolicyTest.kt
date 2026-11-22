package dev.maplesu.manager.modules

import dev.maplesu.manager.ModuleArchiveInspector
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class LiteScriptModulePolicyTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun report(vararg files: Pair<String, String>): ModuleArchiveInspector.Report {
        val file = temporary.newFile()
        ZipOutputStream(file.outputStream()).use { output ->
            (listOf("module.prop" to "id=maple_script_fixture\nname=Fixture\nversionCode=1\n") + files).forEach { (name, value) ->
                output.putNextEntry(ZipEntry(name)); output.write(value.toByteArray()); output.closeEntry()
            }
        }
        return ModuleArchiveInspector.inspect(file)
    }

    @Test fun scriptRedirectionWorksAndOptionalToolsAreCheckedBeforeInstallation() {
        val scripts = mapOf("customize.sh" to "echo ready >&2\nbusybox true\nresetprop fixture value\n")
        assertEquals(setOf("busybox", "resetprop"), LiteScriptModulePolicy.check(report("customize.sh" to scripts.getValue("customize.sh")), scripts))
    }

    /** Requirements are executed by consumers; inventory never rejects a selected package. */
    @Test fun acceptedStagesAndBackgroundWorkAreReportedNotRejected() {
        assertEquals(emptySet<String>(),
            LiteScriptModulePolicy.check(report("post-fs-data.sh" to "echo early"), mapOf("post-fs-data.sh" to "echo early")))
        assertEquals(emptySet<String>(),
            LiteScriptModulePolicy.check(report("system/etc/fixture" to "data"), emptyMap()))
        assertEquals(emptySet<String>(),
            LiteScriptModulePolicy.check(report("service.sh" to "sleep 1 &"), mapOf("service.sh" to "sleep 1 &")))
    }

    @Test fun moduleRequestedCommandsAreNotBlockedByTextScanning() {
        val script = "/system/bin/setenforce 0\n"
        assertEquals(emptySet<String>(),
            LiteScriptModulePolicy.check(report("service.sh" to script), mapOf("service.sh" to script)))
        assertEquals(emptySet<String>(),
            LiteScriptModulePolicy.check(report("init.fixture.rc" to "on boot\n"), emptyMap()))
    }
}
