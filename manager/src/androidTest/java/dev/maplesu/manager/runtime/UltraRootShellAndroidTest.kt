package dev.maplesu.manager.runtime

import android.content.Intent
import android.net.Uri
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ui.webui.WebUIActivity
import com.topjohnwu.superuser.io.SuFile
import com.topjohnwu.superuser.io.SuFileInputStream
import dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Opt-in regression for Ultra module WebUI's real streaming shell and file transport. */
class UltraRootShellAndroidTest {
    private fun requireUltra(): android.content.Context {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyUltraWebUI") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        context.startActivity(context.packageManager.getLaunchIntentForPackage(context.packageName)!!
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(20)
        while (ModeRuntime.active == null && System.nanoTime() < deadline) Thread.sleep(100)
        assertEquals(WorkMode.LITE, ModeRuntime.active)
        assertTrue("This regression requires the paired SDK backend", UltraEnvironmentProbe.usesUltraBackend(context))
        return context
    }

    @Test(timeout = 120_000) fun sdkShellPreservesNamespaceStreamsFilesAndRepeatedSessions() {
        val context = requireUltra()
        repeat(6) {
            RootManagement.openShell(context, true).use { shell ->
                val result = shell.newJob().add("id -u", "printf 'stream-error\\n' >&2", "(exit 17)")
                    .to(ArrayList<String>(), ArrayList<String>()).exec()
                assertEquals(listOf("0"), result.out)
                assertEquals(listOf("stream-error"), result.err)
                assertEquals(17, result.code)
                assertEquals(listOf("still-alive"), shell.newJob().add("echo still-alive")
                    .to(ArrayList<String>(), null).exec().out)
                val path = "/data/adb/maplesu-webui-test-${UUID.randomUUID()}"
                try {
                    assertTrue(shell.newJob().add("umask 077; printf '\\000\\377\\001\\012' > '$path'").exec().isSuccess)
                    val file = SuFile(path).apply { setShell(shell) }
                    SuFileInputStream.open(file).use { input ->
                        assertArrayEquals(byteArrayOf(0, -1, 1, 10), input.readBytes())
                    }
                    // WebUI's asset shell stays open while JS opens a separate command shell.
                    RootManagement.openShell(context, true).use { command ->
                        assertEquals(listOf("0"), command.newJob().add("id -u")
                            .to(ArrayList<String>(), null).exec().out)
                    }
                } finally {
                    assertTrue(shell.newJob().add("rm -f -- '$path'").exec().isSuccess)
                }
            }
        }
        println("MAPLESU_ULTRA_WEBUI_SHELL: namespace, stdio, exit, binary file, concurrent and repeated sessions passed")
    }

    @Test(timeout = 120_000) fun installedModulePageSupportsExecAndStreamingSpawn() {
        val context = requireUltra()
        val module = runBlocking { ModuleRepositoryImpl().getModules().getOrThrow() }
            .firstOrNull { it.hasWebUi && it.enabled && !it.update && !it.remove }
        assertNotNull("An enabled installed module with WebUI is required", module)
        val intent = Intent(context, WebUIActivity::class.java)
            .setData(Uri.parse("ksu://webui?id=${Uri.encode(module!!.id)}"))
        repeat(2) {
            ActivityScenario.launch<WebUIActivity>(intent).use { scenario ->
                var view: WebView? = null
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(40)
                while (view == null && System.nanoTime() < deadline) {
                    scenario.onActivity { view = findWebView(it.window.decorView) }
                    if (view == null) Thread.sleep(100)
                }
                val web = requireNotNull(view) { "Module WebUI did not open" }
                val pageDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
                var loaded = false
                while (!loaded && System.nanoTime() < pageDeadline) {
                    loaded = evaluate(web, "document.readyState==='complete' && location.origin==='https://mui.kernelsu.org' && document.body.innerHTML.length>0") == "true"
                    if (!loaded) Thread.sleep(100)
                }
                assertTrue("The real module page must load", loaded)
                assertEquals("\"0\"", evaluate(web, "ksu.exec('id -u')"))
                evaluate(web, "window.ultraEvents=[];window.ultraExec=function(c,o,e){ultraEvents.push(['exec',c,o,e]);};" +
                    "ksu.exec('printf ultra-out; printf ultra-err >&2; (exit 23)','{}','ultraExec');")
                val exec = awaitEvents(web, 1).getJSONArray(0)
                assertEquals("exec", exec.getString(0))
                assertEquals(23, exec.getInt(1))
                assertEquals("ultra-out", exec.getString(2))
                assertEquals("ultra-err", exec.getString(3))
                evaluate(web, "window.ultraEvents=[];window.ultraChild={" +
                    "stdout:{emit:function(n,v){ultraEvents.push(['out',v]);}}," +
                    "stderr:{emit:function(n,v){ultraEvents.push(['err',v]);}}," +
                    "emit:function(n,v){ultraEvents.push([n,n==='error'?v.exitCode:v]);}};" +
                    "ksu.spawn('/system/bin/sh',JSON.stringify(['-c','echo spawn-out; echo spawn-err >&2; sleep 1; exit 7']),'{}','ultraChild');")
                val events = awaitEvents(web, 4)
                val rows = (0 until events.length()).map { events.getJSONArray(it).toString() }.toSet()
                assertTrue(events.toString(), rows.contains("[\"out\",\"spawn-out\"]"))
                assertTrue(events.toString(), rows.contains("[\"err\",\"spawn-err\"]"))
                assertTrue(events.toString(), rows.contains("[\"exit\",7]"))
                assertTrue(events.toString(), rows.contains("[\"error\",7]"))
            }
        }
        println("MAPLESU_ULTRA_WEBUI_PAGE:${module.id}: load, sync exec, async exec, streaming spawn and reopen passed")
    }

    private fun findWebView(view: View): WebView? {
        if (view is WebView) return view
        if (view is ViewGroup) for (i in 0 until view.childCount) {
            findWebView(view.getChildAt(i))?.let { return it }
        }
        return null
    }

    private fun evaluate(view: WebView, script: String): String {
        val ready = CountDownLatch(1)
        var result = ""
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            view.evaluateJavascript(script) { result = it; ready.countDown() }
        }
        assertTrue("JavaScript evaluation timed out", ready.await(30, TimeUnit.SECONDS))
        return result
    }

    private fun awaitEvents(view: WebView, count: Int): JSONArray {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (System.nanoTime() < deadline) {
            val events = JSONArray(evaluate(view, "JSON.stringify(window.ultraEvents)")
                .let { JSONArray("[$it]").getString(0) })
            if (events.length() >= count) return events
            Thread.sleep(50)
        }
        error("Module WebUI callbacks timed out")
    }
}
