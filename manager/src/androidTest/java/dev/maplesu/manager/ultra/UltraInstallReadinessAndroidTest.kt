package dev.maplesu.manager.ultra

import android.util.Log
import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge
import org.json.JSONObject
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Read-only SDK observations: no key provisioning, install, root commands or partition writes. */
class UltraInstallReadinessAndroidTest {
    @Test fun captureEnvironmentAndKernelChannel() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyInstallReadiness") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val key = context.getSharedPreferences("maplesu-ultra", Context.MODE_PRIVATE).getString("rootKey", null)
        assertNotNull("Existing credential is required", key)
        val state = JSONObject(NativeBridge.getEnvironmentState(key))
        val channel = JSONObject(NativeBridge.testBasics(key, "Channel"))
        val version = JSONObject(NativeBridge.getInstalledEnvironmentVersion(key))
        // Only structured verdicts are recorded; SDK diagnostic text can contain the credential.
        val result = JSONObject().put("environment", state.optJSONObject("data")?.optString("state"))
            .put("environmentError", state.optString("sdkError"))
            .put("channelOk", channel.optBoolean("ok")).put("channelError", channel.optString("sdkError"))
            .put("versionOk", version.optBoolean("ok")).put("versionError", version.optString("sdkError"))
        Log.i("MapleSUInstallReadiness", result.toString())
    }
}
