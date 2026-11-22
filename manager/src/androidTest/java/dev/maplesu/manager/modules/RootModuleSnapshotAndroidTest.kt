package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.core.app.ActivityScenario
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** Executes the production snapshot in Android sh, using app-owned files only. */
class RootModuleSnapshotAndroidTest {
    @Test fun pairedSdkSnapshotPreservesLargeMetadataWithoutOpeningAStreamingShell() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySdkSnapshot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            assertEquals(WorkMode.LITE, runBlocking { ModeRuntime.awaitPageMode(15_000) })
            assertTrue(UltraEnvironmentProbe.usesUltraBackend(context))
            val folder = Files.createTempDirectory(context.cacheDir.toPath(), "sdk-snapshot-").toFile()
            try {
                val modules = File(folder, "modules").apply { mkdir() }
                val expected = (0 until 8).associate { index ->
                    val id = "sdk_fixture_$index"
                    val metadata = "id=$id\nname=模块\\literal+%\nversionCode=1\ndescription=" +
                        "0123456789abcdef".repeat(3_700) + "\n"
                    File(modules, id).apply { mkdir() }.resolve("module.prop").writeText(metadata)
                    id to metadata
                }
                val runner = ManagementModuleScriptRunner(context)
                val tree = RootModuleTree(runner, modules.absolutePath, File(folder, "transactions").absolutePath)
                val snapshot = tree.snapshot(expected.keys, discover = true)
                assertEquals(expected.keys, snapshot.keys)
                expected.forEach { (id, metadata) -> assertEquals(id, metadata, snapshot.getValue(id).metadata) }
                assertNull("A read-only snapshot must not open the streaming transport",
                    runner.javaClass.getDeclaredField("shell").apply { isAccessible = true }.get(runner))
            } finally { folder.deleteRecursively() }
        }
    }

    @Test fun builtinRowsAndPortableRowsPreserveTheSameSnapshotWithoutPerRowProcesses() {
        val base = InstrumentationRegistry.getInstrumentation().targetContext
        val folder = Files.createTempDirectory(base.cacheDir.toPath(), "module-snapshot-").toFile()
        try {
            val modules = File(folder, "modules").apply { mkdir() }
            val module = File(modules, "fixture").apply { mkdir() }
            val metadata = "id=fixture\nname=模块\\literal\nversionCode=7\n\n"
            File(module, "module.prop").writeText(metadata)
            File(module, "service.sh").writeText(":\n")
            File(module, "disable").writeText("")
            File(module, RootModuleTree.OWNER).writeText("a".repeat(64) + "\n")
            Files.createSymbolicLink(File(module, "remove").toPath(), File(module, "disable").toPath())
            File(module, "webroot").mkdir()
            File(module, "webroot/index.html").writeText("fixture")
            File(module, "zygisk").mkdir()
            File(module, "zygisk/arm64-v8a.so").writeBytes(byteArrayOf(0)) // Never loaded.
            val legacy = File(folder, "legacy\\target").apply { mkdir() }
            File(legacy, "module.prop").writeText("id=legacy_fixture\nname=Legacy\n")
            Files.createSymbolicLink(File(modules, "legacy_fixture").toPath(), legacy.toPath())

            val formatterCalls = File(folder, "formatter-calls")
            var portable = false
            val runner = ModuleScriptRunner { source ->
                val script = if (portable) {
                    val condition = "if [ -n \"\${KSH_VERSION:-}\" ]; then"
                    check(source.contains(condition))
                    source.replace(condition, "if false; then")
                } else source
                val count = formatterCalls.absolutePath.replace("'", "'\\''")
                val track = "printf() { print -r -- call >> '$count'; command printf \"\$@\"; }\n"
                val process = ProcessBuilder("/system/bin/sh", "-c", track + script).start()
                val out = process.inputStream.bufferedReader().readText()
                val err = process.errorStream.bufferedReader().readText()
                ModuleScriptOutput(process.waitFor(), out, err)
            }
            val tree = RootModuleTree(runner, modules.absolutePath, File(folder, "transactions").absolutePath)
            val ids = listOf("fixture", "legacy_fixture")
            val fast = tree.snapshot(ids, discover = true)
            assertTrue("Per-row external printf returned", formatterCalls.readLines().size <= 6)
            portable = true
            assertEquals(fast, tree.snapshot(ids, discover = true))
            val state = fast.getValue("fixture")
            assertEquals(metadata, state.metadata)
            assertEquals("a".repeat(64), state.revision)
            assertFalse(state.enabled)
            assertFalse(state.removed)
            assertTrue(state.zygisk)
            assertTrue("service.sh" in state.files && "webroot" in state.directories)
            assertEquals(legacy.absolutePath, fast.getValue("legacy_fixture").legacyTarget)
        } finally { folder.deleteRecursively() }
    }
}
