package dev.maplesu.manager.modules

import android.content.Context
import android.content.ContextWrapper
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files

/** Real production marker/receipt/deletion code, confined to an app-owned fixture. */
class ModuleRemovalAndroidTest {
    private val base = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun existingModuleCanBeMarkedReopenedCancelledAndDeletedAfterUninstall() = fixture { backend, folder, module ->
        val original = File(module, "data.txt").readText()
        assertTrue(backend.markRemove("removal_fixture", true))
        assertTrue(File(module, "remove").isFile)
        assertTrue(backend.listJson().contains("remove_pending"))
        val receipt = File(folder, "files/module-runtime/receipts").listFiles()!!.single()
        val state = LiteModuleRuntimeState.read(receipt)
        assertNotNull(state.removalIdentity)
        assertTrue(state.pendingStages(state.removeRequestedBootId!!, true, listOf("service")).isEmpty())
        assertTrue(backend.markRemove("removal_fixture", false))
        assertFalse(File(module, "remove").exists())
        assertNull(LiteModuleRuntimeState.read(receipt).removalIdentity)
        assertEquals(original, File(module, "data.txt").readText())
        assertTrue(backend.markRemove("removal_fixture", true))
        val pending = LiteModuleRuntimeState.read(receipt)
        val nextBoot = "00000000-0000-0000-0000-000000000003"
        assertEquals(listOf("uninstall"), pending.pendingStages(nextBoot, true, listOf("service")))
        // Feed the same verified uninstall completion used by runBootTask into deletion.
        pending.withStage("uninstall", nextBoot, "ok", 0).save(receipt)
        removeInstalled(backend)
        assertFalse(module.exists())
        assertTrue(receipt.isFile)
        assertTrue(backend.listJson().let { it == "[]" })
        assertEquals("keep", File(folder, "unrelated.txt").readText())
    }

    @Test fun retainedKsuModuleKeepsItsFlagsAndDoesNotRequireARebootOrAnExecutionReceipt() = fixture { backend, folder, module ->
        File(module, "service.sh").writeText("exit 0\n")
        File(module, "update").writeText("") // inherited marker, not an installation this boot
        val row = org.json.JSONArray(backend.listJson()).getJSONObject(0)
        assertTrue(row.getBoolean("enabled"))
        assertTrue(row.getBoolean("canToggle"))
        assertFalse(row.getBoolean("update"))
        assertFalse(row.getBoolean("needsReboot"))
        assertEquals("", row.getString("runtimeStatus"))
        assertTrue(backend.setEnabled("removal_fixture", false))
        assertTrue(File(module, "disable").isFile)
        val disabled = org.json.JSONArray(backend.listJson()).getJSONObject(0)
        assertFalse(disabled.getBoolean("enabled"))
        assertEquals("disabled", disabled.getString("runtimeStatus"))
        assertTrue(backend.setEnabled("removal_fixture", true))
        assertFalse(File(module, "disable").exists())
        assertTrue("Editing flags must not adopt boot execution", File(folder, "files/module-runtime/receipts").listFiles()!!.isEmpty())
        assertFalse(File(module, RootModuleTree.OWNER).exists())
        assertEquals("module data", File(module, "data.txt").readText())
    }

    @Test fun cancellingRetainedModuleRemovalDoesNotInventAnInstallThisBoot() = fixture { backend, _, _ ->
        assertTrue(backend.markRemove("removal_fixture", true))
        assertTrue(backend.markRemove("removal_fixture", false))
        val row = org.json.JSONArray(backend.listJson()).getJSONObject(0)
        assertTrue(row.getBoolean("enabled"))
        assertTrue(row.getBoolean("canToggle"))
        assertFalse(row.getBoolean("needsReboot"))
        assertEquals("", row.getString("runtimeStatus"))
    }

    @Test fun directoryReplacedAfterInventoryIsNotDeleted() = fixture { backend, folder, module ->
        assertTrue(backend.markRemove("removal_fixture", true))
        Files.move(module.toPath(), File(folder, "original-module").toPath())
        module.mkdirs()
        File(module, "module.prop").writeText("id=removal_fixture\nname=Replacement\n")
        File(module, "keep.txt").writeText("replacement")
        try { removeInstalled(backend); fail("A stale removal must fail") }
        catch (error: InvocationTargetException) { assertTrue(error.cause is IllegalStateException) }
        assertEquals("replacement", File(module, "keep.txt").readText())
    }

    @Test fun standardRemoveMarkerWithoutPrivateReceiptSchedulesOnlyUninstall() = fixture { backend, folder, module ->
        File(module, "service.sh").writeText("exit 0\n")
        File(module, "remove").writeText("")
        assertTrue(File(folder, "files/module-runtime/receipts").listFiles()!!.isEmpty())
        val prepared = backend.prepareBootTasks()
        val tasks = prepared.filter { it.id == "removal_fixture" }
        assertEquals(listOf("uninstall"), tasks.map { it.stage })
        val receipt = File(folder, "files/module-runtime/receipts").listFiles()!!.single()
        assertNotNull(LiteModuleRuntimeState.read(receipt).removalIdentity)
        prepared.forEach(backend::abandonBootTask)
    }

    @Test fun finalRemovalClearsSameIdUpdateAndConfigWhileKeepingOtherModules() = fixture { backend, folder, module ->
        val pending = File(folder, "modules_update/removal_fixture").apply { mkdirs() }
        File(pending, "module.prop").writeText("id=removal_fixture\nversionCode=2\n")
        val config = File(folder, "ksu/module_configs/removal_fixture").apply { mkdirs() }
        val other = File(folder, "modules_update/other").apply { mkdirs() }
        assertTrue(backend.markRemove("removal_fixture", true))
        removeInstalled(backend)
        assertFalse(module.exists())
        assertFalse(pending.exists())
        assertFalse(config.exists())
        assertTrue(other.isDirectory)
    }

    private fun removeInstalled(backend: LiteScriptModuleBackend) {
        val type = backend.javaClass
        val entries = type.getDeclaredField("diskEntries").apply { isAccessible = true }.get(backend) as Map<*, *>
        val entry = entries.values.single()!!
        val report = entry.javaClass.getDeclaredField("report").apply { isAccessible = true }.get(entry)
        type.getDeclaredMethod("removeInstalled", report.javaClass).apply { isAccessible = true }.invoke(backend, report)
    }

    private fun fixture(test: (LiteScriptModuleBackend, File, File) -> Unit) {
        val folder = Files.createTempDirectory(base.cacheDir.toPath(), "module-removal-").toFile()
        val context = object : ContextWrapper(base) {
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = File(folder, "files").apply { mkdirs() }
            override fun createDeviceProtectedStorageContext(): Context = this
        }
        val modules = File(folder, "modules").apply { mkdirs() }
        val module = File(modules, "removal_fixture").apply { mkdirs() }
        File(module, "module.prop").writeText("id=removal_fixture\nname=Removal fixture\nversionCode=1\n")
        File(module, "data.txt").writeText("module data")
        File(folder, "unrelated.txt").writeText("keep")
        val runner = ModuleScriptRunner { script ->
            val process = ProcessBuilder("/system/bin/sh", "-c", script).start()
            val out = process.inputStream.bufferedReader().readText()
            val err = process.errorStream.bufferedReader().readText()
            ModuleScriptOutput(process.waitFor(), out, err)
        }
        val backend = LiteScriptModuleBackend(context, runner)
        backend.javaClass.getDeclaredField("rootTrees").apply { isAccessible = true }
            .set(backend, RootModuleTree(runner, modules.absolutePath, File(folder, "transactions").absolutePath))
        try { test(backend, folder, module) } finally { folder.deleteRecursively() }
    }
}
