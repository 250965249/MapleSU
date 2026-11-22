package dev.maplesu.manager

import android.net.Uri
import android.os.SystemClock
import android.view.ViewGroup
import android.webkit.JavascriptInterface
import android.webkit.RenderProcessGoneDetail
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.webkit.WebViewAssetLoader
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.webui.ModuleWebViewClient
import com.maplesu.core.ui.webui.WebUIState
import com.maplesu.core.ui.webui.WebViewInterface
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Real WebView renderer, production client and bridge; responses are in-memory, without root/network. */
@RunWith(AndroidJUnit4::class)
class WebUIOriginAndroidTest {
    class Probe {
        val hits = CopyOnWriteArrayList<String>()
        @JavascriptInterface fun hit(value: String) { hits += value }
    }

    private class Fixture(val view: WebView, val client: ModuleWebViewClient) {
        val probe = Probe()
        val externalLinks = CopyOnWriteArrayList<Uri>()
        val remoteRequests = CopyOnWriteArrayList<String>()
        val pages = CopyOnWriteArrayList<String>()
        val requests = CopyOnWriteArrayList<String>()
        val blockedRequests = CopyOnWriteArrayList<String>()
        val consumedNavigations = CopyOnWriteArrayList<String>()
        var rendererGone = false
    }

    private fun html(value: String, headers: Map<String, String> = emptyMap()) =
        WebResourceResponse("text/html", "utf-8", 200, "OK", headers, value.byteInputStream())

    private fun withPage(restrictDocuments: Boolean = true, normalCompatibility: Boolean = false,
                         block: (Fixture) -> Unit) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            val ready = CountDownLatch(1)
            lateinit var fixture: Fixture
            scenario.onActivity { activity ->
                val assets = WebViewAssetLoader.Builder().setDomain("mui.kernelsu.org")
                    .addPathHandler("/") { path ->
                        if (path == "index.html") html("<html><body></body></html>")
                        else if (path == "child.html") html("<script>probe.hit('child')</script>")
                        else if (path == "worker.js") WebResourceResponse("application/javascript", "utf-8",
                            "self.onmessage=e=>self.postMessage('same-origin:'+e.data);".byteInputStream())
                        else if (path == "static/style.css") WebResourceResponse("text/css", "utf-8",
                            "#static-fixture { color: rgb(19, 37, 73); }".byteInputStream())
                        else if (path == "static/main.js") WebResourceResponse("application/javascript", "utf-8",
                            ("const r=await fetch(new URL('./nested/value.json?rev=1',import.meta.url));" +
                                "const v=await r.json();document.querySelector('#static-fixture').textContent=v.message;" +
                                "window.staticFixtureReady=true;").byteInputStream())
                        else if (path == "static/nested/value.json") WebResourceResponse("application/json", "utf-8",
                            "{\"message\":\"Normal static WebUI loaded\"}".byteInputStream())
                        else WebResourceResponse("text/plain", "utf-8", 404, "Not Found", emptyMap(), null)
                    }.build()
                val view = WebView(activity)
                val client = object : ModuleWebViewClient(assets, { fixture.externalLinks += it },
                    { fixture.rendererGone = true }, normalCompatibility) {
                    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                        val consumed = restrictDocuments && super.shouldOverrideUrlLoading(view, request)
                        if (consumed) fixture.consumedNavigations += request.url.toString()
                        return consumed
                    }

                    override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                        fixture.requests += request.url.toString()
                        val response = if (restrictDocuments) super.shouldInterceptRequest(view, request)
                            else assets.shouldInterceptRequest(request.url)
                        response?.let {
                            if (it.statusCode == 403) fixture.blockedRequests += request.url.toString()
                            return it
                        }
                        fixture.remoteRequests += request.url.toString()
                        return when (request.url.path) {
                            "/script.js" -> WebResourceResponse("text/javascript", "utf-8",
                                "probe.hit('cdn');".byteInputStream())
                            "/value.json" -> WebResourceResponse("application/json", "utf-8", 200, "OK",
                                mapOf("Access-Control-Allow-Origin" to "https://mui.kernelsu.org"),
                                "{\"value\":42}".byteInputStream())
                            else -> html("<script>probe.hit('foreign')</script>")
                        }
                    }

                    override fun onPageStarted(view: WebView, url: String?, favicon: android.graphics.Bitmap?) {
                        if (restrictDocuments) super.onPageStarted(view, url, favicon)
                        fixture.pages += url ?: ""
                    }

                    override fun onPageFinished(view: WebView, url: String) {
                        if (url == "https://mui.kernelsu.org/index.html") ready.countDown()
                    }
                }
                fixture = Fixture(view, client)
                view.settings.javaScriptEnabled = true
                view.webViewClient = client
                val state = WebUIState().apply {
                    modDir = activity.cacheDir.absolutePath
                    webView = view
                }
                view.addJavascriptInterface(WebViewInterface(state), "ksu")
                view.addJavascriptInterface(fixture.probe, "probe")
                activity.addContentView(view, ViewGroup.LayoutParams(1, 1))
                view.loadUrl("https://mui.kernelsu.org/index.html")
            }
            try {
                assertTrue("Module page did not load", ready.await(10, TimeUnit.SECONDS))
                block(fixture)
            } finally {
                instrumentation.runOnMainSync {
                    if (!fixture.rendererGone) {
                        fixture.view.removeJavascriptInterface("ksu")
                        fixture.view.removeJavascriptInterface("probe")
                        (fixture.view.parent as? ViewGroup)?.removeView(fixture.view)
                        fixture.view.destroy()
                    }
                }
            }
        }
    }

    private fun evaluate(view: WebView, script: String): String {
        val done = CountDownLatch(1)
        var result = ""
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            view.evaluateJavascript(script) { result = it; done.countDown() }
        }
        assertTrue("JavaScript evaluation timed out", done.await(5, TimeUnit.SECONDS))
        return result
    }

    private fun awaitCondition(message: String, condition: () -> Boolean) {
        val deadline = SystemClock.uptimeMillis() + 5_000
        while (SystemClock.uptimeMillis() < deadline) {
            if (condition()) return
            SystemClock.sleep(20)
        }
        fail(message)
    }

    @Test fun modulePageKeepsTheKsuBridgeAndLocalResources() = withPage { fixture ->
        assertEquals("object", evaluate(fixture.view, "typeof ksu").let { JSONObject("{\"v\":$it}").getString("v") })
        assertEquals("true", evaluate(fixture.view, "Array.isArray(JSON.parse(ksu.listPackages('all')))"))
        assertEquals("true", evaluate(fixture.view, "window.isSecureContext"))
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    @Test fun staticHtmlUsesLocalCssModuleJavascriptAndJsonWithRelativeAndRootPaths() = withPage { fixture ->
        evaluate(fixture.view, "document.body.innerHTML='<p id=\"static-fixture\">Loading</p>';" +
            "var css=document.createElement('link');css.rel='stylesheet';css.href='static/style.css?rev=1';document.head.append(css);" +
            "var script=document.createElement('script');script.type='module';script.src='/static/main.js?rev=1';document.body.append(script);")
        awaitCondition("Static module JavaScript did not run") {
            evaluate(fixture.view, "window.staticFixtureReady===true") == "true"
        }
        assertEquals("\"Normal static WebUI loaded\"", evaluate(fixture.view, "document.querySelector('#static-fixture').textContent"))
        assertEquals("\"rgb(19, 37, 73)\"", evaluate(fixture.view, "getComputedStyle(document.querySelector('#static-fixture')).color"))
        assertTrue(fixture.requests.containsAll(listOf(
            "https://mui.kernelsu.org/static/style.css?rev=1",
            "https://mui.kernelsu.org/static/main.js?rev=1",
            "https://mui.kernelsu.org/static/nested/value.json?rev=1",
        )))
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    @Test fun externalNavigationOpensTheBrowserAndLeavesTheModulePage() = withPage { fixture ->
        evaluate(fixture.view, "location.href='https://outside.invalid/docs';")
        awaitCondition("External link was not handed to the browser") { fixture.externalLinks.size == 1 }
        assertEquals("https://outside.invalid/docs", fixture.externalLinks.single().toString())
        assertEquals("\"https://mui.kernelsu.org/index.html\"", evaluate(fixture.view, "location.href"))
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    @Test fun foreignFramesAndObjectsDoNotExecuteWithTheBridge() = withPage { fixture ->
        evaluate(fixture.view, "var f=document.createElement('iframe'); f.src='https://outside.invalid/frame'; document.body.append(f);" +
            "var o=document.createElement('object'); o.data='https://outside.invalid/object'; document.body.append(o);" +
            "window.frameCheckDone=false; setTimeout(()=>{window.frameCheckDone=true},250);")
        awaitCondition("Frame check did not finish") { evaluate(fixture.view, "window.frameCheckDone") == "true" }
        assertTrue("Embedded document reached a native bridge: ${fixture.probe.hits}", fixture.probe.hits.isEmpty())
        assertTrue("Embedded content reached the network: ${fixture.remoteRequests}", fixture.remoteRequests.isEmpty())
    }

    @Test fun unrestrictedControlLoadsForeignFrameAndReachesTheNativeBridge() = withPage(false) { fixture ->
        evaluate(fixture.view, "var f=document.createElement('iframe'); f.src='https://outside.invalid/frame'; document.body.append(f);")
        awaitCondition("Unrestricted control did not reach its native bridge") { fixture.probe.hits.contains("foreign") }
        assertTrue(fixture.remoteRequests.contains("https://outside.invalid/frame"))
    }

    @Test fun moduleAuthoredSrcdocKeepsModuleTrustButCannotEmbedForeignPages() = withPage { fixture ->
        val nested = "<script>probe.hit('srcdoc')</script><iframe src='https://outside.invalid/nested'></iframe>"
        evaluate(fixture.view, "var s=document.createElement('iframe'); s.srcdoc=${JSONObject.quote(nested)}; document.body.append(s);")
        awaitCondition("Module-authored srcdoc did not run") { fixture.probe.hits.contains("srcdoc") }
        evaluate(fixture.view, "window.nestedCheckDone=false; setTimeout(()=>{window.nestedCheckDone=true},250);")
        awaitCondition("Nested frame check did not finish") { evaluate(fixture.view, "window.nestedCheckDone") == "true" }
        assertEquals(listOf("srcdoc"), fixture.probe.hits.toList())
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    @Test fun moduleFramesLoadWhileTheUltraWorkerPolicyRemainsBlocked() = withPage { fixture ->
        evaluate(fixture.view, "var f=document.createElement('iframe'); f.src='/child.html'; document.body.append(f);" +
            "window.workerBlocked=false; try { var w=new Worker('/child.html'); w.onerror=()=>{window.workerBlocked=true}; }" +
            "catch(e) { window.workerBlocked=true; }" +
            "window.localFrameCheckDone=false; setTimeout(()=>{window.localFrameCheckDone=true},250);")
        awaitCondition("Local frame check did not finish") { evaluate(fixture.view, "window.localFrameCheckDone") == "true" }
        assertEquals(listOf("child"), fixture.probe.hits.toList())
        awaitCondition("Worker was not rejected") { evaluate(fixture.view, "window.workerBlocked") == "true" }
    }

    @Test fun normalAllowsSameOriginAndBlobWorkersWithoutForeignFrames() = withPage(normalCompatibility = true) { fixture ->
        evaluate(fixture.view, "window.workerResults=[]; window.workerErrors=[];" +
            "var same=new Worker('/worker.js');same.onmessage=e=>{workerResults.push(e.data);same.terminate()};" +
            "same.onerror=e=>workerErrors.push(e.message);same.postMessage('normal');" +
            "var source=URL.createObjectURL(new Blob([\"self.onmessage=e=>self.postMessage('blob:'+e.data);\"],{type:'application/javascript'}));" +
            "var blob=new Worker(source);blob.onmessage=e=>{workerResults.push(e.data);blob.terminate();URL.revokeObjectURL(source)};" +
            "blob.onerror=e=>workerErrors.push(e.message);blob.postMessage('normal');" +
            "var foreign=document.createElement('iframe');foreign.src='https://outside.invalid/frame';document.body.append(foreign);")
        awaitCondition("Normal workers did not respond") { evaluate(fixture.view, "workerResults.length") == "2" }
        assertEquals("[\"blob:normal\",\"same-origin:normal\"]", evaluate(fixture.view, "workerResults.sort()"))
        assertEquals("[]", evaluate(fixture.view, "workerErrors"))
        assertTrue(fixture.remoteRequests.isEmpty())
        assertTrue(fixture.probe.hits.isEmpty())
    }

    @Test fun moduleFetchAndExplicitScriptImportsStillWork() = withPage { fixture ->
        evaluate(fixture.view, "window.networkValue=null; fetch('https://outside.invalid/value.json')" +
            ".then(r=>r.json()).then(v=>{window.networkValue=v.value;});" +
            "var s=document.createElement('script'); s.src='https://outside.invalid/script.js'; document.body.append(s);")
        awaitCondition("Module JSON fetch did not finish") { evaluate(fixture.view, "window.networkValue") == "42" }
        awaitCondition("Module script import did not run") { fixture.probe.hits.contains("cdn") }
        assertEquals(setOf("https://outside.invalid/value.json", "https://outside.invalid/script.js"), fixture.remoteRequests.toSet())
    }

    @Test fun appInitiatedForeignDocumentNeverLoadsRemoteContent() = withPage { fixture ->
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            fixture.view.loadUrl("https://outside.invalid/foreign")
        }
        awaitCondition("Foreign navigation was not observed") {
            fixture.requests.contains("https://outside.invalid/foreign") ||
                fixture.consumedNavigations.contains("https://outside.invalid/foreign")
        }
        assertTrue(fixture.probe.hits.isEmpty())
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    @Test fun appInitiatedForeignInlineDocumentIsBlockedBeforeItsScriptRuns() = withPage { fixture ->
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            fixture.view.loadDataWithBaseURL("https://outside.invalid/inline",
                "<script>probe.hit('inline')</script>", "text/html", "utf-8", null)
        }
        awaitCondition("Inline document was not blocked") {
            fixture.blockedRequests.any { it.startsWith("data:") }
        }
        assertTrue(fixture.probe.hits.isEmpty())
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    private fun request(value: String, mainFrame: Boolean = true, verb: String = "GET") = object : WebResourceRequest {
        override fun getUrl() = Uri.parse(value)
        override fun isForMainFrame() = mainFrame
        override fun isRedirect() = false
        override fun hasGesture() = true
        override fun getMethod() = verb
        override fun getRequestHeaders() = emptyMap<String, String>()
    }

    @Test fun localMissesWrongPortsAndPostRequestsNeverFallBackToNetwork() = withPage { fixture ->
        val cases = mapOf(
            "https://mui.kernelsu.org/missing.html" to 404,
            "https://mui.kernelsu.org:444/index.html" to 403,
            "http://mui.kernelsu.org/index.html" to 403,
            "https://user@mui.kernelsu.org/index.html" to 403,
        )
        for ((url, status) in cases) {
            assertEquals(status, fixture.client.shouldInterceptRequest(fixture.view, request(url))!!.statusCode)
        }
        assertEquals(403, fixture.client.shouldInterceptRequest(fixture.view,
            request("https://mui.kernelsu.org/index.html", verb = "POST"))!!.statusCode)
        assertTrue(fixture.remoteRequests.isEmpty())
    }

    @Test fun dataFileIntentAndSubframeNavigationsAreConsumed() = withPage { fixture ->
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            for (url in listOf("data:text/html,test", "file:///etc/hosts", "intent://example", "javascript:alert(1)")) {
                assertTrue(fixture.client.shouldOverrideUrlLoading(fixture.view, request(url)))
            }
            assertTrue(fixture.client.shouldOverrideUrlLoading(fixture.view,
                request("https://outside.invalid/frame", mainFrame = false)))
            assertFalse(fixture.client.shouldOverrideUrlLoading(fixture.view,
                request("https://mui.kernelsu.org/index.html#route")))
        }
        assertTrue(fixture.externalLinks.isEmpty())
    }

    @Test fun rendererExitCallbackDisposesItsViewAndNotifiesTheOwner() = withPage { fixture ->
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            val detail = object : RenderProcessGoneDetail() {
                override fun didCrash() = true
                override fun rendererPriorityAtExit() = WebView.RENDERER_PRIORITY_IMPORTANT
            }
            assertNotNull(fixture.view.parent)
            assertTrue(fixture.client.onRenderProcessGone(fixture.view, detail))
            assertNull(fixture.view.parent)
            assertTrue(fixture.rendererGone)
        }
    }
}
