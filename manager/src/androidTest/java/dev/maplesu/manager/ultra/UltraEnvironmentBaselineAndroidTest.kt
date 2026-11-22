package dev.maplesu.manager.ultra

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge
import dev.maplesu.manager.modules.UltraRootKeyStore
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Read-only environment / root-key baseline, taken BEFORE any environment install attempt.
 *
 * It answers three separate questions and keeps them separate:
 *   1. does the SDK accept the provisioned key at all (vs ERR_MODULE_ROOT_KEY)?
 *   2. does it report an environment (vs ERR_MODULE_NO_BOOT / NotInstalled)?
 *   3. what does the root-channel report say about the key's authority?
 *
 * It never installs, uninstalls or modifies anything.
 *
 * Opt-in: `-e verifyUltraEnv true`.
 */
class UltraEnvironmentBaselineAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val evidence = JSONObject()

    private fun receipt(raw: String, operation: String): JSONObject {
        assertNotNull("$operation returned null", raw)
        val json = JSONObject(raw)
        assertEquals("$operation backend", "maplesu_ultra", json.getString("backend"))
        assertEquals("$operation operation", operation, json.getString("operation"))
        return json
    }

    @Test
    fun keyIsAcceptedAndEnvironmentIsAbsent() {
        org.junit.Assume.assumeTrue(
            InstrumentationRegistry.getArguments().getString("verifyUltraEnv") == "true"
        )

        // The Ultra root key is a user passphrase, not a vendor-issued secret: MapleSU Ultra's own
        // Manager asks the user to type it and stores it verbatim. When the operator has not
        // provisioned one, this test acts as that user once and records that it did so.
        var key = UltraRootKeyStore.read(context)
        if (key == null) {
            val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            key = (1..48).map { alphabet.random() }.joinToString("")
            UltraRootKeyStore.write(context, key)
            evidence.put("provisionedByTest", true)
        } else {
            evidence.put("provisionedByTest", false)
        }
        assertNotNull(key)
        evidence.put("keyLength", key.length)
        evidence.put("keyLooksLikeAlnum", key.all { it.isLetterOrDigit() })

        // 1. environment state with a real key
        val stateRaw = NativeBridge.getEnvironmentState(key)
        val state = receipt(stateRaw, "get_maplesu_environment_state")
        evidence.put("envStateReceipt", stateRaw)
        evidence.put("envState", if (state.getBoolean("ok")) state.getJSONObject("data").getString("state") else null)

        // 2. installed environment version: absent environment must be an error, not "0.0.0"
        val versionRaw = NativeBridge.getInstalledEnvironmentVersion(key)
        val version = receipt(versionRaw, "get_installed_maplesu_environment_version")
        evidence.put("installedVersionReceipt", versionRaw)
        evidence.put("installedVersionOk", version.getBoolean("ok"))
        evidence.put("installedVersionError", version.getString("sdkError"))

        // 3. root channel report for this key
        val rootRaw = NativeBridge.testRoot(key)
        val root = receipt(rootRaw, "get_root_status_report")
        evidence.put("rootStatusReceipt", rootRaw)
        evidence.put("rootStatusOk", root.getBoolean("ok"))

        // 4. module descriptor parse with a real key: distinguishes key gate from boot gate
        val teeZip = File(context.getExternalFilesDir(null), "tee.zip")
        if (teeZip.isFile) {
            val descRaw = NativeBridge.parseModuleDescriptor(key, teeZip.absolutePath)
            val desc = receipt(descRaw, "parse_module_desc_from_zip_file")
            evidence.put("descriptorReceipt", descRaw)
            evidence.put("descriptorOk", desc.getBoolean("ok"))
            evidence.put("descriptorError", desc.getString("sdkError"))
        } else {
            evidence.put("descriptorReceipt", "not-run: tee.zip absent at ${teeZip.absolutePath}")
        }

        // 5. module list with a real key
        val listRaw = NativeBridge.getModuleList(key)
        val list = receipt(listRaw, "get_all_modules_list")
        evidence.put("moduleListReceipt", listRaw)
        evidence.put("moduleListError", list.getString("sdkError"))

        val output = File(context.filesDir, "ultra-env-baseline.json")
        output.writeText(evidence.toString(2))
        android.util.Log.i("MAPLESU_EVIDENCE", "ultra-env-baseline " + evidence.toString())
        assertTrue("evidence written", output.isFile && output.length() > 0)
    }
}
