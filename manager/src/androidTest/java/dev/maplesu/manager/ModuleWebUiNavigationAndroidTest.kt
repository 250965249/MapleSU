package dev.maplesu.manager

import android.content.Intent
import android.view.View
import android.view.ViewGroup
import android.webkit.WebView
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.R
import com.maplesu.core.ui.webui.ModuleWebUIActivity
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

@RunWith(AndroidJUnit4::class)
class ModuleWebUiNavigationAndroidTest {
    @get:Rule val compose = createEmptyComposeRule()

    private fun findWebView(view: View): WebView? = when (view) {
        is WebView -> view
        is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull {
            findWebView(view.getChildAt(it))
        }
        else -> null
    }

    @Test fun firstLoadRejectsRedirectToAnotherPortAndCanRetry() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val loopback = InetAddress.getByName("127.0.0.1")
        val redirect = AtomicBoolean(true)
        val servedEntry = CountDownLatch(1)
        ServerSocket(0, 0, loopback).use { otherOrigin ->
            ServerSocket(0, 0, loopback).use { origin ->
                val worker = thread(isDaemon = true, name = "webui-navigation-fixture") {
                    while (!origin.isClosed) {
                        val socket = try {
                            origin.accept()
                        } catch (error: SocketException) {
                            if (origin.isClosed) break
                            throw error
                        }
                        try {
                            socket.use {
                                it.soTimeout = 2000
                                val request = it.getInputStream().bufferedReader(Charsets.US_ASCII)
                                val entry = request.readLine()?.startsWith("GET /index.html ") == true
                                while (!request.readLine().isNullOrEmpty()) { /* Drain headers. */ }
                                val response = when {
                                    !entry -> "404 Not Found\r\n"
                                    redirect.get() -> "302 Found\r\nLocation: http://127.0.0.1:${otherOrigin.localPort}/\r\n"
                                    else -> "200 OK\r\nContent-Type: text/html\r\n"
                                }
                                val body = if (response.startsWith("200")) "<html><title>Ready</title></html>" else ""
                                it.getOutputStream().write(
                                    ("HTTP/1.1 $response" + "Content-Length: ${body.length}\r\n" +
                                        "Cache-Control: no-store\r\nConnection: close\r\n\r\n$body").toByteArray(Charsets.US_ASCII)
                                )
                                if (body.isNotEmpty()) servedEntry.countDown()
                            }
                        } catch (_: SocketTimeoutException) {
                            // WebView may abandon a speculative connection without sending a request.
                        }
                    }
                }
                try {
                    val intent = Intent(context, ModuleWebUIActivity::class.java)
                        .putExtra(ModuleWebUIActivity.EXTRA_URL, "http://127.0.0.1:${origin.localPort}/index.html")
                        .putExtra(ModuleWebUIActivity.EXTRA_MODULE_ID, "webui_navigation_fixture")
                    ActivityScenario.launch<ModuleWebUIActivity>(intent).use {
                        val entryUrl = intent.getStringExtra(ModuleWebUIActivity.EXTRA_URL)!!
                        val blocked = context.getString(R.string.module_webui_external_blocked)
                        val retry = context.getString(R.string.module_webui_retry)
                        val loading = context.getString(R.string.webui_loading)
                        compose.waitUntil(10_000) {
                            compose.onAllNodesWithText(blocked).fetchSemanticsNodes().isNotEmpty()
                        }
                        compose.onNodeWithText(blocked).assertIsDisplayed()
                        assertTrue(compose.onAllNodesWithText(loading).fetchSemanticsNodes().isEmpty())

                        redirect.set(false)
                        compose.onNodeWithText(retry).performClick()
                        assertTrue("Retry did not request the original entry", servedEntry.await(10, TimeUnit.SECONDS))
                        val renderedTitle = AtomicReference<String?>()
                        it.onActivity { activity ->
                            findWebView(activity.window.decorView)!!.evaluateJavascript("document.title") {
                                renderedTitle.set(it)
                            }
                        }
                        compose.waitUntil(10_000) {
                            renderedTitle.get() == "\"Ready\""
                        }
                        it.onActivity { activity ->
                            assertTrue(findWebView(activity.window.decorView)!!.url == entryUrl)
                        }
                        compose.waitUntil(10_000) {
                            compose.onAllNodesWithText(loading).fetchSemanticsNodes().isEmpty()
                        }
                        assertTrue(compose.onAllNodesWithText(retry).fetchSemanticsNodes().isEmpty())
                        assertTrue(compose.onAllNodesWithText(blocked).fetchSemanticsNodes().isEmpty())
                    }
                } finally {
                    origin.close()
                    worker.join(3000)
                    assertFalse("Fixture server did not stop", worker.isAlive)
                }
            }
        }
    }
}
