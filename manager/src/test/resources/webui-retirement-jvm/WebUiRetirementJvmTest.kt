package com.maplesu.core.ui.webui

import android.app.Activity
import android.net.Uri
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.ValueCallback
import android.webkit.WebView
import com.maplesu.core.ui.util.fixtureModuleList
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.io.SuFileInputStream
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Exercises current production entrypoints; Android/libsu boundaries are isolated fixtures. */
class WebUiRetirementJvmTest {
    private fun state(activity: Activity, id: String) = WebUIState().also {
        it.modDir = activity.cacheDir.path
        it.webView = WebView(activity)
        assertTrue(it.bindModuleSession(activity, id))
    }

    private fun await(condition: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (!condition()) {
            if (System.nanoTime() >= until) fail("Resource cleanup did not finish")
            Thread.sleep(2)
        }
    }

    @Test fun synchronousExecDropsOutputReturnedAfterModuleRetirement() {
        val activity = Activity()
        val state = state(activity, "retire:sync")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val shell = Shell().apply { fastCmdGate = { entered.countDown(); check(release.await(3, TimeUnit.SECONDS)) } }
        val bridge = WebViewInterface(state) { shell }.also { state.javascriptBridge = it }
        val answer = AtomicReference<String>()
        val worker = Thread { answer.set(bridge.exec("fixture-output")) }
        try {
            worker.start()
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            ModuleWebUiSessions.committed("retire:sync")
            release.countDown()
            worker.join(3000)
            assertFalse(worker.isAlive)
            assertEquals("", answer.get())
            await { shell.closes.get() == 1 }
            assertFalse(state.isDisposed)
        } finally { release.countDown(); state.dispose(activity); activity.cacheDir.deleteRecursively() }
    }

    @Test fun moduleMetadataStopsNewReadsAndDropsAnInFlightReadAfterRetirement() {
        val activity = Activity()
        val state = state(activity, "retire:metadata")
        val bridge = WebViewInterface(state) { error("Metadata must not open a shell") }
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var reads = 0
        fixtureModuleList = { reads++; entered.countDown(); check(release.await(3, TimeUnit.SECONDS)); "[]" }
        val answer = AtomicReference<String>()
        val worker = Thread { answer.set(bridge.moduleInfo()) }
        try {
            worker.start()
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            ModuleWebUiSessions.committed("retire:metadata")
            release.countDown(); worker.join(3000)
            assertFalse(worker.isAlive)
            assertEquals("{}", answer.get())
            assertEquals("{}", bridge.moduleInfo())
            assertEquals(1, reads)
        } finally { release.countDown(); fixtureModuleList = { "[]" }; bridge.destroy(); state.dispose(activity); activity.cacheDir.deleteRecursively() }
    }

    @Test fun dialogAndFileResultsRemainRetiredAfterExitAndLateChromeCallbacks() {
        val activity = Activity()
        val state = state(activity, "retire:chrome")
        val view = state.webView!!
        val chrome = moduleWebChromeClient(state)
        val alert = JsResult()
        val prompt = JsPromptResult()
        val fileResults = mutableListOf<Array<Uri>?>()
        try {
            assertTrue(chrome.onJsAlert(view, "", "alert", alert))
            assertTrue(chrome.onJsPrompt(view, "", "prompt", "", prompt))
            assertEquals(1, alert.cancelled)
            assertTrue(chrome.onShowFileChooser(view, ValueCallback { fileResults += it }, null))
            assertEquals(1, prompt.cancelled)
            state.requestExit()
            assertEquals(1, fileResults.size)
            val lateBridge = WebViewInterface(state) { error("Exited page opened a shell") }
            assertEquals("", lateBridge.exec("late"))
            assertFalse(state.attachRootShell(Shell()))
            lateBridge.destroy()
            assertNull(fileResults.single())
            state.onAlertResult(); state.onConfirmResult(true); state.onPromptResult("late")
            state.onFileChooserResult(arrayOf(Uri.parse("content://late")))
            val late = JsResult()
            assertTrue(chrome.onJsConfirm(view, "", "late", late))
            assertEquals(1, late.cancelled)
            assertEquals(0, late.confirmed)
            assertEquals(WebUIEvent.Close, state.uiEvent)
            assertEquals(1, fileResults.size)
        } finally { state.dispose(activity); activity.cacheDir.deleteRecursively() }
    }

    @Test fun javascriptExitRunsOnThePageQueueAndNeverClosesAReplacementView() {
        val activity = Activity()
        val state = state(activity, "retire:exit-queue")
        val view = state.webView!!
        var shellOpens = 0
        val bridge = WebViewInterface(state) { shellOpens++; error("Exit must not open a shell") }
        state.javascriptBridge = bridge
        try {
            val alert = JsResult()
            assertTrue(moduleWebChromeClient(state).onJsAlert(view, "", "alert", alert))
            bridge.exit()
            assertEquals(0, alert.cancelled)
            assertEquals(1, view.queued.size)
            val replacement = WebView(activity)
            state.webView = replacement
            view.drain()
            assertEquals(0, alert.cancelled)
            assertTrue(state.uiEvent is WebUIEvent.ShowAlert)
            assertFalse(state.isDisposed)

            val replacementBridge = WebViewInterface(state) { shellOpens++; error("Exit must not open a shell") }
            state.javascriptBridge = replacementBridge
            replacementBridge.exit()
            assertEquals(0, alert.cancelled)
            replacement.drain()
            assertEquals(WebUIEvent.Close, state.uiEvent)
            assertEquals(1, alert.cancelled)
            assertEquals(0, shellOpens)
        } finally { bridge.destroy(); state.dispose(activity); activity.cacheDir.deleteRecursively() }
    }

    @Test fun moduleRetirementClosesDownloadsAndRootBeforeUiCleanupAndKeepsOtherPages() {
        val activity = Activity()
        val otherActivity = Activity()
        val state = state(activity, "retire:downloads")
        val other = state(otherActivity, "retire:other")
        val shell = Shell()
        state.rootShell = shell
        val downloads = WebUIDownloadInterface(state).also { state.downloadBridge = it }
        val otherDownloads = WebUIDownloadInterface(other).also { other.downloadBridge = it }
        try {
            val id = downloads.startChunkedDownload("first", null)
            assertTrue(id.isNotEmpty())
            assertTrue(downloads.writeDownloadChunk(id, "AQID"))
            ModuleWebUiSessions.committed("retire:downloads")
            assertFalse(state.isDisposed)
            assertEquals("", downloads.startChunkedDownload("late", null))
            assertFalse(downloads.writeDownloadChunk(id, "AA=="))
            assertFalse(downloads.completeChunkedDownload(id))
            downloads.openExternal("https://example.invalid/")
            assertTrue(activity.externalIntents.isEmpty())
            await { shell.closes.get() == 1 && activity.cacheDir.listFiles()!!.isEmpty() }
            assertTrue(otherDownloads.startChunkedDownload("other", null).isNotEmpty())
            assertFalse(other.isDisposed)
            activity.drain()
            assertEquals(1, shell.closes.get())
        } finally {
            state.dispose(activity); other.dispose(otherActivity)
            await { otherActivity.cacheDir.listFiles()!!.isEmpty() }
            activity.cacheDir.deleteRecursively(); otherActivity.cacheDir.deleteRecursively()
        }
    }

    @Test fun assetResponsesOwnStreamsAndRejectReadsBeforeQueuedPageCleanup() {
        val activity = Activity()
        val state = state(activity, "retire:assets")
        val file = java.io.File(activity.cacheDir, "fixture.txt").apply { writeText("fixture") }
        val view = state.webView!!
        val before = SuFileInputStream.closes.get()
        val handler = SuFilePathHandler(activity, activity.cacheDir, Shell(), { state.currentInsets }, null) { state.acceptsPage(view) }
        state.assetHandler = handler
        try {
            val response = handler.handle(file.name)
            val input = response.data!!
            assertEquals('f'.code, input.read())
            ModuleWebUiSessions.committed("retire:assets")
            assertThrows(IOException::class.java) { input.read() }
            assertNull(handler.handle(file.name).data)
            await { SuFileInputStream.closes.get() == before + 1 }
            input.close()
            activity.drain()
            assertEquals(before + 1, SuFileInputStream.closes.get())
        } finally { state.dispose(activity); activity.cacheDir.deleteRecursively() }
    }

    @Test fun assetOpenReturnedAfterRetirementClosesWithoutPublishingAStream() {
        val activity = Activity()
        val state = state(activity, "retire:asset-open")
        val file = java.io.File(activity.cacheDir, "fixture.txt").apply { writeText("fixture") }
        val view = state.webView!!
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val before = SuFileInputStream.closes.get()
        val handler = SuFilePathHandler(activity, activity.cacheDir, Shell(), { state.currentInsets }, null) { state.acceptsPage(view) }
        state.assetHandler = handler
        SuFileInputStream.openGate = { entered.countDown(); check(release.await(3, TimeUnit.SECONDS)) }
        val result = AtomicReference<android.webkit.WebResourceResponse>()
        val worker = Thread { result.set(handler.handle(file.name)) }
        try {
            worker.start(); assertTrue(entered.await(3, TimeUnit.SECONDS))
            ModuleWebUiSessions.committed("retire:asset-open")
            release.countDown(); worker.join(3000)
            assertFalse(worker.isAlive)
            assertNull(result.get().data)
            assertEquals(before + 1, SuFileInputStream.closes.get())
        } finally {
            release.countDown(); SuFileInputStream.openGate = null
            state.dispose(activity); activity.cacheDir.deleteRecursively()
        }
    }
}
