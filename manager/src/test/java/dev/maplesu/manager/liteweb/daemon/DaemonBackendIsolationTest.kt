package dev.maplesu.manager.liteweb.daemon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class DaemonBackendIsolationTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun backend(root: File, source: DaemonRuntimeSource = UnavailableDaemonRuntimeSource): DaemonLiteWebBackend = DaemonLiteWebBackend(
        adbRoot = root.absolutePath,
        modulesRoot = File(root, "modules").absolutePath,
        selfUid = { 0 },
        runtimeSource = source,
    )

    @Test fun unknownSourceDoesNotExposeNormalModules() {
        val root = temporary.newFolder("adb")
        File(root, "modules/normal-only").mkdirs()
        File(root, "modules/normal-only/module.prop").writeText("id=normal-only\nname=Normal only\n")
        backend(root).use {
            assertFalse("Unknown source leaked Normal modules: ${it.modulesJson()}", it.modulesJson().contains("normal-only"))
        }
    }

    @Test fun unknownSourceDoesNotClaimUltra() {
        backend(temporary.newFolder("adb")).use {
            assertEquals("UNKNOWN", it.status().mode)
            assertEquals("UNKNOWN", it.modeBackend().mode().mode)
            assertEquals("UNKNOWN", it.workModePort().read().mode)
        }
    }

    @Test fun runningSdkOnlyReadsUltraEvenWithCommittedNormalMetadata() {
        val root = temporary.newFolder("adb")
        val normalModule = File(root, "modules/normal-only")
        normalModule.mkdirs()
        File(normalModule, "module.prop").writeText("id=normal-only\n")
        var ultraReads = 0
        val source = object : DaemonRuntimeSource {
            override fun snapshot() = DaemonRuntimePolicy.resolve(
                DaemonUltraState.RUNNING, DaemonCommittedMode("now", "now", "B", "B", false), "now",
            )
            override fun ultraModules(): DaemonModulesSnapshot {
                ultraReads++
                return DaemonUltraModuleList.render(listOf(DaemonUltraModule("ultra-only", "Ultra", "", "", "", "Running", false)))
            }
        }
        backend(root, source).use {
            val json = it.modulesJson()
            assertTrue(json, json.contains("maplesu:ultra-only"))
            assertFalse(json, json.contains("normal-only"))
            assertEquals("LITE", it.status().mode)
            assertEquals("LITE", it.modeBackend().mode().mode)
            assertEquals("LITE", it.diagnosticsPort().read().mode)
            assertEquals("LITE", it.workModePort().read().mode)
            assertEquals(1, it.status().moduleCount)
            assertTrue(it.toggleModule("normal-only", false) is dev.maplesu.manager.liteweb.LiteWebToggleView.Unavailable)
            assertFalse(File(normalModule, "disable").exists())
        }
        assertTrue(ultraReads > 0)
    }

    @Test fun sdkErrorWithSameBootNormalMetadataReadsNoModuleBackend() {
        val root = temporary.newFolder("adb")
        val normalModule = File(root, "modules/normal-only")
        normalModule.mkdirs()
        File(normalModule, "module.prop").writeText("id=normal-only\n")
        var ultraReads = 0
        val source = object : DaemonRuntimeSource {
            override fun snapshot() = DaemonRuntimePolicy.resolve(
                DaemonUltraState.UNKNOWN, DaemonCommittedMode("now", "now", "B", "B", false), "now",
            )
            override fun ultraModules(): DaemonModulesSnapshot { ultraReads++; error("must not read") }
        }
        backend(root, source).use {
            assertTrue(it.modulesJson().contains("DAEMON_MODE_UNRESOLVED"))
            assertFalse(it.modulesJson().contains("normal-only"))
            assertEquals("UNKNOWN", it.status().mode)
            assertEquals("DAEMON_MODE_UNRESOLVED", it.status().moduleCountError)
            assertTrue(it.toggleModule("normal-only", false) is dev.maplesu.manager.liteweb.LiteWebToggleView.Unavailable)
            assertFalse(File(normalModule, "disable").exists())
        }
        assertEquals(0, ultraReads)
    }

    @Test fun sdkListFailureNeverFallsBackToNormalDirectory() {
        val root = temporary.newFolder("adb")
        val normalModule = File(root, "modules/normal-only")
        normalModule.mkdirs()
        File(normalModule, "module.prop").writeText("id=normal-only\n")
        val source = object : DaemonRuntimeSource {
            override fun snapshot() = DaemonRuntimePolicy.resolve(DaemonUltraState.RUNNING)
            override fun ultraModules() = DaemonModulesSnapshot(error = "ULTRA_MODULES_UNAVAILABLE")
        }
        backend(root, source).use {
            assertEquals("ULTRA_MODULES_UNAVAILABLE", it.status().moduleCountError)
            assertTrue(it.modulesJson().contains("\"ok\":false"))
            assertFalse(it.modulesJson().contains("normal-only"))
        }
    }

    @Test fun explicitNotInstalledWithCommittedNormalReadsOnlyNormal() {
        val root = temporary.newFolder("adb")
        val normalModule = File(root, "modules/normal-only")
        normalModule.mkdirs()
        File(normalModule, "module.prop").writeText("id=normal-only\n")
        val source = object : DaemonRuntimeSource {
            override fun snapshot() = DaemonRuntimePolicy.resolve(
                DaemonUltraState.NOT_INSTALLED, DaemonCommittedMode("now", "now", "B", "B", false), "now",
            )
            override fun ultraModules(): DaemonModulesSnapshot = error("must not read")
        }
        backend(root, source).use {
            assertTrue(it.modulesJson().contains("normal-only"))
            assertEquals("KSU", it.status().mode)
        }
    }
}
