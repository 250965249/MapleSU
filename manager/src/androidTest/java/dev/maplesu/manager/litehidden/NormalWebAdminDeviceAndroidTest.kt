package dev.maplesu.manager.litehidden

import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.util.WebAdminCli
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** Exercises the same entry used by Settings, without enabling stealth or removing the app. */
class NormalWebAdminDeviceAndroidTest {
    @Test(timeout = 180_000)
    fun settingsStartsMapleWebUiWithWorkingAuthorization() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySettingsWebAdmin") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val deadline = android.os.SystemClock.elapsedRealtime() + 60_000
            while (ModeRuntime.active == null && android.os.SystemClock.elapsedRealtime() < deadline) {
                android.os.SystemClock.sleep(100)
            }
            assertEquals(WorkMode.KSU, ModeRuntime.active)
            // Opening an already enabled setting must migrate the legacy listener too.
            val url = WebAdminCli.url().trimEnd('/') + "/"
            File(context.filesDir, "normal-settings-webui-url").writeText(url)
            fun read(path: String): String {
                val connection = URL(url + path).openConnection() as HttpURLConnection
                connection.connectTimeout = 10_000
                connection.readTimeout = 20_000
                return try {
                    assertEquals("HTTP $path", 200, connection.responseCode)
                    connection.inputStream.bufferedReader().use { reader -> reader.readText() }
                } finally { connection.disconnect() }
            }
            assertTrue(read("").contains("<title>MapleSU"))
            val catalog = JSONObject(read("api/superuser"))
            assertEquals("ksu", catalog.getString("backend"))
            assertEquals("uid", catalog.getString("scope"))
            assertTrue(catalog.getJSONArray("apps").length() > 0)
            assertEquals(0, com.maplesu.core.Natives.stealthState())
            assertTrue("Settings stop failed", WebAdminCli.setEnabled(false))
            assertTrue("Settings restart failed", WebAdminCli.setEnabled(true))
            assertEquals(url, WebAdminCli.url().trimEnd('/') + "/")
            assertTrue(JSONObject(read("api/superuser")).getBoolean("ok"))
        }
    }
}
