package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
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

/** Opt-in: install -> production soft reboot -> verify/disable -> soft reboot -> cleanup. */
class ModuleDemandAndroidTest {
    @Test(timeout = 120_000) fun moduleRequestedPolicyAndMountsUseTheProductionBackend() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("verifyModuleDemand") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        Thread {
            Thread.sleep(15_000)
            val stacks = JSONArray()
            Thread.getAllStackTraces().forEach { (thread, frames) ->
                if (frames.any { it.className.startsWith("dev.maplesu.") || it.className.contains("NativeBridge") }) {
                    stacks.put(JSONObject().put("thread", thread.name).put("frames", JSONArray(frames.map { it.toString() })))
                }
            }
            File(context.filesDir, "module-demand-threads.json").writeText(stacks.toString())
        }.apply { isDaemon = true; start() }
        context.packageManager.getLaunchIntentForPackage(context.packageName)?.let {
            context.startActivity(it.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        }
        Thread.sleep(5_000)
        fun root(command: String): String = RootExec.execute(context, command).let {
            assertEquals(it.detail + "\n" + it.output, 0, it.code)
            it.output.trim()
        }
        assertEquals("0\nEnforcing", root("id -u; getenforce"))
        val deadline = System.currentTimeMillis() + 20_000
        while (ModeRuntime.active == null && System.currentTimeMillis() < deadline) Thread.sleep(100)
        assertEquals(WorkMode.LITE, ModeRuntime.active)
        val trace = File(context.filesDir, "module-demand-trace.jsonl")
        val backend = LiteScriptModuleBackend(context, ModuleScriptRunner { script ->
            val policy = script.contains("' apply --rules")
            val label = if (policy) "policy" else if (script.contains("MAPLESU_TOOL_HOST:")) "tools" else "module"
            val start = System.currentTimeMillis()
            trace.appendText(JSONObject().put("operation", label).put("start", start).toString() + "\n")
            RootExecModuleScriptRunner.run(script).also { result ->
                trace.appendText(JSONObject().put("operation", label).put("elapsed", System.currentTimeMillis() - start)
                    .put("code", result.code).put("out", result.out).put("err", result.err).toString() + "\n")
            }
        })
        val evidence = File(context.filesDir, "module-demand-fixture.json")
        fun row(id: String): JSONObject = JSONArray(backend.listJson()).let { rows ->
            (0 until rows.length()).map(rows::getJSONObject).single { it.getString("id") == id }
        }
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        when (val phase = args.getString("moduleDemandPhase")) {
            "install" -> {
                assertFalse("Cleanup the previous fixture first", evidence.exists())
                val id = "maple_demand_${UUID.randomUUID().toString().replace("-", "")}"
                val zip = File.createTempFile("module-demand-", ".zip", context.cacheDir)
                try {
                    ZipOutputStream(zip.outputStream()).use { out ->
                        linkedMapOf(
                            "module.prop" to "id=$id\nname=Module demand fixture\nversion=1\nversionCode=1\nauthor=MapleSU\n",
                            "sepolicy.rule" to "type $id domain\nallow $id self process getattr\n",
                            "system/etc/$id" to "$id\n",
                            "webroot/index.html" to "<html><body>MAPLESU_MODULE_DEMAND_WEBUI</body></html>",
                            "post-mount.sh" to "test \"\$(cat /system/etc/$id)\" = $id\n",
                        ).forEach { (name, content) ->
                            out.putNextEntry(ZipEntry(name)); out.write(content.toByteArray()); out.closeEntry()
                        }
                    }
                    val report = ModuleArchiveInspector.inspect(zip)
                    val key = MessageDigest.getInstance("SHA-256")
                        .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
                        .joinToString("") { "%02x".format(it.toInt() and 255) }
                    val state = JSONObject().put("id", id).put("key", key)
                        .put("boot", File("/proc/sys/kernel/random/boot_id").readText().trim())
                        .put("installedEpoch", LiteModuleBootEpoch.read(context))
                        .put("hostsBefore", root("sha256sum /system/etc/hosts"))
                    evidence.writeText(state.toString())
                    val output = mutableListOf<String>()
                    val installed = backend.install(zip, report, output::add, output::add)
                    state.put("installOutput", JSONArray(output)); evidence.writeText(state.toString())
                    assertEquals(output.joinToString("\n"), 0, installed.code)
                    assertTrue(installed.needsReboot)
                    assertTrue("Policy must be committed, not only checked", output.any {
                        runCatching { JSONObject(it).optBoolean("committed") }.getOrDefault(false)
                    })
                    assertTrue(row(id).getBoolean("web"))
                    assertEquals("ok", row(id).getJSONObject("stages").getJSONObject("policy").getString("status"))
                    assertEquals("absent", root("if [ -e /system/etc/$id ]; then echo present; else echo absent; fi"))
                } finally { zip.delete() }
            }
            "verify-disable" -> {
                val state = JSONObject(evidence.readText())
                val id = state.getString("id")
                assertEquals(state.getString("boot"), File("/proc/sys/kernel/random/boot_id").readText().trim())
                assertNotEquals(state.getString("installedEpoch"), LiteModuleBootEpoch.read(context))
                LiteModuleBootService.request(context)
                val wait = System.currentTimeMillis() + 60_000
                while (row(id).getString("runtimeStatus") != "late_completed" && System.currentTimeMillis() < wait) Thread.sleep(200)
                val result = row(id)
                state.put("loadedRow", result); evidence.writeText(state.toString())
                assertEquals(result.toString(), "late_completed", result.getString("runtimeStatus"))
                assertEquals(id, root("cat /system/etc/$id"))
                assertEquals(id, File("/system/etc/$id").readText().trim())
                assertEquals(state.getString("hostsBefore"), root("sha256sum /system/etc/hosts"))
                assertTrue(result.getBoolean("web"))
                assertTrue(backend.setEnabled(id, false))
                state.put("disabled", true); evidence.writeText(state.toString())
            }
            "cleanup" -> {
                val state = JSONObject(evidence.readText())
                val id = state.getString("id")
                require(id.matches(Regex("maple_demand_[a-f0-9]{32}")))
                LiteModuleBootService.request(context)
                val wait = System.currentTimeMillis() + 60_000
                while (File("/system/etc/$id").exists() && System.currentTimeMillis() < wait) Thread.sleep(200)
                assertFalse("Disabled module projection must be removed", File("/system/etc/$id").exists())
                assertEquals(state.getString("hostsBefore"), root("sha256sum /system/etc/hosts"))
                val revision = File(context.filesDir, "module-runtime/revisions/${state.getString("key")}")
                ModuleTree.unlink(context, id, revision.absolutePath)
                root("rm -rf -- ${quote(revision.absolutePath)}")
                ModuleCatalog(File(context.filesDir, "module-catalog")).uninstall(ModuleArchiveInspector.ModuleType.KERNEL_SU, id)
                File(context.filesDir, "module-runtime/receipts/${state.getString("key")}.properties").delete()
                assertTrue(evidence.delete())
            }
            else -> error("Unknown moduleDemandPhase: $phase")
        }
        assertEquals("Enforcing", root("getenforce"))
        println("MAPLESU_MODULE_DEMAND_PHASE:${args.getString("moduleDemandPhase")}:passed")
    }
}
