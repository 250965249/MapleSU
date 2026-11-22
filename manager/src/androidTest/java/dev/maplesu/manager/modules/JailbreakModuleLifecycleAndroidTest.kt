package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Opt-in three-phase test. The caller performs a real production soft reboot between phases. */
class JailbreakModuleLifecycleAndroidTest {
    @Test(timeout = 90_000) fun moduleLifecycleUsesTheLiveHookAndFrameworkBoot() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("verifyJailbreakModules") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = RootExec.execute(context, "/system/bin/id -u; /system/bin/getenforce")
        assertEquals("This test requires the existing Hook, not another root source", RootBackend.HOOK, root.backend)
        assertEquals("0\nEnforcing", root.output.trim())
        val deadline = System.currentTimeMillis() + 20_000
        while (ModeRuntime.active == null && System.currentTimeMillis() < deadline) Thread.sleep(100)
        assertEquals(WorkMode.LITE, ModeRuntime.active)
        val backend = LiteScriptModuleBackend(context)
        val evidence = File(context.filesDir, "jailbreak-module-fixture.json")
        val phase = args.getString("modulePhase") ?: error("modulePhase required")
        fun root(command: String): String = RootExec.execute(context, command).let {
            assertEquals(it.detail, 0, it.code)
            it.output.trim()
        }
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        fun listed(id: String) = JSONArray(backend.listJson()).let { rows ->
            (0 until rows.length()).map { rows.getJSONObject(it) }.single { it.getString("id") == id }
        }
        when (phase) {
            "install" -> {
                assertFalse("Previous fixture needs cleanup first", evidence.exists())
                val id = "maplesu_jailbreak_check_${UUID.randomUUID().toString().replace("-", "")}"
                val zip = File.createTempFile("jailbreak-module-", ".zip", context.cacheDir)
                try {
                    ZipOutputStream(zip.outputStream()).use { out ->
                        val files = linkedMapOf("module.prop" to
                            "id=$id\nname=Jailbreak lifecycle fixture\nversion=1\nversionCode=1\nauthor=MapleSU\ndescription=Temporary verification fixture\n")
                        LiteScriptModuleBackend.bootScripts.forEach { stage ->
                            files["$stage.sh"] = "dir=\${0%/*}\nprintf '$stage:%s\\n' \"\$(/system/bin/id -u)\" >> \"\$dir/stages\"\n"
                        }
                        files["action.sh"] = "printf 'FIXTURE_FAILURE\\n' >&2\nexit 37\n"
                        files["system/etc/maplesu-jailbreak-fixture"] = "Projection skipped by the module\n"
                        files["skip_mount"] = ""
                        files.forEach { (name, content) ->
                            out.putNextEntry(ZipEntry(name)); out.write(content.toByteArray()); out.closeEntry()
                        }
                    }
                    val report = ModuleArchiveInspector.inspect(zip)
                    val key = MessageDigest.getInstance("SHA-256")
                        .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
                        .joinToString("") { "%02x".format(it.toInt() and 255) }
                    val revision = File(context.filesDir, "module-runtime/revisions/$key")
                    // Persist before install so cleanup remains possible after any test failure.
                    val result = JSONObject().put("id", id).put("key", key).put("revision", revision.absolutePath)
                        .put("installedEpoch", LiteModuleBootEpoch.read(context))
                        .put("kernelBoot", File("/proc/sys/kernel/random/boot_id").readText().trim())
                    evidence.writeText(result.toString())
                    val output = mutableListOf<String>()
                    val installed = backend.install(zip, report, output::add, output::add)
                    assertEquals(output.joinToString("\n"), 0, installed.code)
                    assertTrue(installed.needsReboot)
                    assertEquals("late_pending", listed(id).getString("runtimeStatus"))
                    assertEquals(37, backend.action(id, output::add, output::add))
                    assertEquals("failed", listed(id).getString("runtimeStatus"))
                    assertEquals("37", listed(id).getJSONObject("stages").getJSONObject("action").getString("code"))
                    assertEquals("0", root("if [ -f ${quote("${revision.absolutePath}/stages")} ]; then echo 1; else echo 0; fi"))
                    result.put("installed", true).put("failureCodePreserved", true)
                    evidence.writeText(result.toString())
                } finally { zip.delete() }
            }
            "verify" -> {
                val result = JSONObject(evidence.readText())
                val id = result.getString("id")
                assertEquals(result.getString("kernelBoot"), File("/proc/sys/kernel/random/boot_id").readText().trim())
                assertNotEquals(result.getString("installedEpoch"), LiteModuleBootEpoch.read(context))
                val wait = System.currentTimeMillis() + 40_000
                while (listed(id).getString("runtimeStatus") != "late_completed" && System.currentTimeMillis() < wait) Thread.sleep(200)
                val row = listed(id)
                assertEquals(row.toString(), "late_completed", row.getString("runtimeStatus"))
                val marker = "${result.getString("revision")}/stages"
                val expected = LiteScriptModuleBackend.bootScripts.joinToString("\n") { "$it:0" }
                assertEquals(expected, root("cat ${quote(marker)}"))
                // A repeated request or app restart in the same epoch must not rerun scripts.
                LiteModuleBootService.request(context)
                Thread.sleep(2_000)
                assertEquals(expected, root("cat ${quote(marker)}"))
                assertEquals("0", root("if [ -e /system/etc/maplesu-jailbreak-fixture ]; then echo 1; else echo 0; fi"))
                assertFalse(row.getJSONArray("unsupported").toString().contains("mount"))
                result.put("verified", true).put("loadedEpoch", LiteModuleBootEpoch.read(context))
                    .put("stageOrder", expected).put("sameEpochDeduplicated", true)
                    .put("skipMountRespected", true).put("moduleRow", row)
                evidence.writeText(result.toString())
            }
            "cleanup" -> {
                val result = JSONObject(evidence.readText())
                val id = result.getString("id")
                val revision = File(result.getString("revision"))
                assertEquals(File(context.filesDir, "module-runtime/revisions").canonicalPath, revision.parentFile!!.canonicalPath)
                assertTrue(id.startsWith("maplesu_jailbreak_check_"))
                ModuleTree.unlink(context, id, revision.absolutePath)
                root("rm -rf -- ${quote(revision.absolutePath)}")
                ModuleCatalog(File(context.filesDir, "module-catalog")).uninstall(ModuleArchiveInspector.ModuleType.KERNEL_SU, id)
                File(context.filesDir, "module-runtime/receipts/${result.getString("key")}.properties").delete()
                assertTrue(evidence.delete())
            }
            else -> error("Unknown modulePhase")
        }
        println("MAPLESU_JAILBREAK_MODULE_PHASE:$phase:passed")
    }
}
