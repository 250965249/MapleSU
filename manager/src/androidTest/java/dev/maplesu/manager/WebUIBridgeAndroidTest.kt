package dev.maplesu.manager

import android.os.SystemClock
import android.view.WindowManager
import android.view.ViewGroup
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.webui.WebUIState
import com.maplesu.core.ui.webui.WebViewInterface
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.R
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch

/** Command serialization is exercised with an ordinary app-UID shell, never a root shell. */
@RunWith(AndroidJUnit4::class)
class WebUIBridgeAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun prefix(options: JSONObject): String {
        val bridge = WebViewInterface(WebUIState())
        val method = WebViewInterface::class.java.getDeclaredMethod(
            "processOptions", StringBuilder::class.java, String::class.java)
        method.isAccessible = true
        val command = StringBuilder()
        method.invoke(bridge, command, options.toString())
        return command.toString()
    }

    private fun run(command: String): Pair<Int, String> {
        val process = ProcessBuilder("/system/bin/sh", "-c", command).redirectErrorStream(true).start()
        try {
            assertTrue("App-UID shell timed out", process.waitFor(10, TimeUnit.SECONDS))
            return process.exitValue() to process.inputStream.bufferedReader().use { it.readText() }
        } finally { process.destroy() }
    }

    @Test fun workingDirectoryAndEnvironmentValuesRemainLiteral() {
        val directory = File(context.cacheDir, "webui bridge 'literal-${System.nanoTime()}")
        assertTrue(directory.mkdir())
        try {
            val marker = File(directory, "must-not-execute")
            val value = "a b '\"; \$(touch ${marker.absolutePath})\nnext"
            val command = prefix(JSONObject().put("cwd", directory.absolutePath)
                .put("env", JSONObject().put("MAPLE_VALUE", value))) +
                "printf '%s\\n%s' \"\$PWD\" \"\$MAPLE_VALUE\""
            val result = run(command)
            assertEquals(0, result.first)
            assertEquals(directory.absolutePath + "\n" + value, result.second)
            assertFalse(marker.exists())
        } finally { directory.deleteRecursively() }
    }

    @Test fun missingWorkingDirectoryStopsBeforeTheCommand() {
        val marker = File(context.cacheDir, "webui-cwd-must-not-run-${System.nanoTime()}")
        try {
            for (options in listOf(JSONObject().put("cwd", marker.absolutePath + "/missing"),
                    JSONObject().put("cwd", marker.absolutePath + "/missing")
                        .put("env", JSONObject().put("MAPLE_VALUE", "value")))) {
                val result = run(prefix(options) + "touch '${marker.absolutePath}'")
                assertNotEquals(0, result.first)
                assertFalse(marker.exists())
            }
        } finally { marker.delete() }
    }

    @Test fun missingWorkingDirectoryStopsEveryStatement() {
        val marker = File(context.cacheDir, "webui-cwd-statements-${System.nanoTime()}")
        try {
            val result = run(prefix(JSONObject().put("cwd", marker.absolutePath + "/missing")) +
                "printf ignored; touch '${marker.absolutePath}'")
            assertNotEquals(0, result.first)
            assertFalse(marker.exists())
        } finally { marker.delete() }
    }

    @Test fun relativeWorkingDirectoriesStartingWithDashRemainLiteral() {
        val directory = File(context.cacheDir, "webui-dash-${System.nanoTime()}")
        assertTrue(directory.mkdir())
        try {
            for (name in listOf("-", "-P", "--")) {
                assertTrue(File(directory, name).mkdir())
                val command = "cd '${directory.absolutePath}'; " +
                    prefix(JSONObject().put("cwd", name)) + "printf '%s' \"\$PWD\""
                val result = run(command)
                assertEquals(0, result.first)
                assertEquals(File(directory, name).absolutePath, result.second)
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun environmentNamesAreValidatedBeforeBuildingAShellCommand() {
        val exception = assertThrows(InvocationTargetException::class.java) {
            prefix(JSONObject().put("env", JSONObject().put("BAD;NAME", "value")))
        }
        assertTrue(exception.cause is IllegalArgumentException)
    }

    @Test fun nulInOptionsIsRejectedBeforeShellExecution() {
        for (options in listOf(JSONObject().put("cwd", "bad\u0000directory"),
                JSONObject().put("env", JSONObject().put("MAPLE_VALUE", "bad\u0000value")))) {
            val exception = assertThrows(InvocationTargetException::class.java) { prefix(options) }
            assertTrue(exception.cause is IllegalArgumentException)
        }
    }

    @Test fun spawnArgumentsPreserveBoundariesAndShellMetacharacters() {
        val marker = File(context.cacheDir, "webui-argv-must-not-run-${System.nanoTime()}")
        try {
            val values = listOf("space value", "", "single'quote", "\$(touch ${marker.absolutePath})", "\";\nnext")
            val args = JSONArray().put("<%s>\\n").apply { values.forEach { put(it) } }
            val bridge = WebViewInterface(WebUIState())
            val method = WebViewInterface::class.java.getDeclaredMethod(
                "buildSpawnCommand", String::class.java, String::class.java, String::class.java)
            method.isAccessible = true
            val command = method.invoke(bridge, "/system/bin/printf", args.toString(), null) as String
            val result = run(command)
            assertEquals(0, result.first)
            assertEquals(values.joinToString("") { "<$it>\n" }, result.second)
            assertFalse(marker.exists())
        } finally { marker.delete() }
    }

    private fun withBridge(block: (WebView) -> Unit) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(MainActivity::class.java).use { foreground ->
            val ready = CountDownLatch(1)
            lateinit var view: WebView
            foreground.onActivity { activity ->
                activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                val state = WebUIState().apply { modDir = context.cacheDir.absolutePath }
                view = WebView(activity).apply {
                    settings.javaScriptEnabled = true
                    webViewClient = object : WebViewClient() {
                        override fun onPageFinished(view: WebView, url: String) { ready.countDown() }
                    }
                    state.webView = this
                    addJavascriptInterface(WebViewInterface(state), "ksu")
                    loadDataWithBaseURL("https://mui.kernelsu.org/", "<html></html>", "text/html", "utf-8", null)
                }
                activity.addContentView(view, ViewGroup.LayoutParams(1, 1))
            }
            try {
                assertTrue("Bridge fixture did not load", ready.await(10, TimeUnit.SECONDS))
                block(view)
            } finally {
                instrumentation.runOnMainSync {
                    (view.parent as? ViewGroup)?.removeView(view)
                    view.removeJavascriptInterface("ksu")
                    view.destroy()
                }
            }
        }
    }

    private fun evaluate(view: WebView, script: String): String {
        val done = CountDownLatch(1)
        var value = ""
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            view.evaluateJavascript(script) { value = it; done.countDown() }
        }
        assertTrue("JavaScript evaluation timed out", done.await(5, TimeUnit.SECONDS))
        return value
    }

    private fun awaitEvents(view: WebView, count: Int): JSONArray {
        val deadline = SystemClock.uptimeMillis() + 5_000
        while (SystemClock.uptimeMillis() < deadline) {
            val events = JSONArray(evaluate(view, "JSON.stringify(window.events)").let { JSONArray("[$it]").getString(0) })
            if (events.length() >= count) return events
            SystemClock.sleep(20)
        }
        throw AssertionError("Bridge callbacks were not delivered")
    }

    @Test fun spawnExitCleanupDoesNotDiscardTheErrorEvent() = withBridge { view ->
        evaluate(view, "window.events=[]; window.childProbe={emit:function(name,value){" +
            "events.push([name,name==='error'?value.exitCode:value]);" +
            "if(name==='exit') delete window.childProbe;}}; ksu.spawn('printf','[]','{}','childProbe');")
        assertEquals("exit", awaitEvents(view, 1).getJSONArray(0).getString(0))
        val events = awaitEvents(view, 2)
        assertEquals("exit", events.getJSONArray(0).getString(0))
        assertEquals("error", events.getJSONArray(1).getString(0))
        assertEquals(-1, events.getJSONArray(0).getInt(1))
        assertEquals(-1, events.getJSONArray(1).getInt(1))
    }

    @Test fun invalidExecOptionsReturnUsageFailureThroughTheRealBridge() = withBridge { view ->
        val options = JSONObject().put("env", JSONObject().put("BAD;NAME", "value")).toString()
        evaluate(view, "window.events=[]; window.execProbe=function(code,out,err){events.push([code,out,err]);};" +
            "ksu.exec('printf ignored',${JSONObject.quote(options)},'execProbe');")
        val result = awaitEvents(view, 1).getJSONArray(0)
        assertEquals(64, result.getInt(0))
        assertEquals("", result.getString(1))
        assertTrue(result.getString(2).isNotBlank())
    }

    @Test fun callbackNamesAreDataAndUnavailableExecKeepsItsFailure() = withBridge { view ->
        val callback = "callback-name');window.injected=true;//"
        evaluate(view, "window.events=[]; window.injected=false; window[${JSONObject.quote(callback)}]=" +
            "function(code,out,err){events.push([code,out,err]);};" +
            "ksu.exec('printf ignored','{}',${JSONObject.quote(callback)});")
        val result = awaitEvents(view, 1).getJSONArray(0)
        assertEquals(-1, result.getInt(0))
        assertEquals(context.getString(R.string.root_install_required), result.getString(2))
        assertEquals("false", evaluate(view, "window.injected"))
    }
}
