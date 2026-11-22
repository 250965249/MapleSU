package dev.maplesu.manager.ultra

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Static recognition of a MapleSU module archive by the product pipeline itself.
 *
 * No Ultra environment, no root key, no native host: this only answers "would MapleSU route
 * this archive to the Ultra backend, and does its descriptor match what the archive claims".
 *
 * Parameters (all optional, defaults target the packaged TEESimulator-RS build):
 *   -e verifyUltraArtifact true
 *   -e ultraArtifact   tee.zip                       file name under the app's external files dir
 *   -e ultraExpectedId teesimulator601skpro202607210000
 *   -e ultraExpectedEntry libmodule_TEESimulatorRS.so
 */
class UltraModuleArtifactAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test
    fun packagedArchiveIsRecognisedAsMaplesu() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("verifyUltraArtifact") == "true")
        val artifact = arguments.getString("ultraArtifact") ?: "tee.zip"
        val expectedId = arguments.getString("ultraExpectedId") ?: "teesimulator601skpro202607210000"
        val expectedEntry = arguments.getString("ultraExpectedEntry") ?: "libmodule_TEESimulatorRS.so"

        val zip = File(context.getExternalFilesDir(null), artifact)
        assertTrue("push the archive to ${zip.absolutePath}", zip.isFile)

        val report = ModuleArchiveInspector.inspect(zip)
        val evidence = JSONObject()
            .put("archive", zip.absolutePath)
            .put("bytes", zip.length())
            .put("type", report.type.name)
            .put("id", report.id)
            .put("nativeEntry", report.nativeEntry)
            .put("versionCode", report.versionCode)
            .put("sha256", report.sha256)
            .put("features", report.features.map { it.name })
            .put("properties", JSONObject(report.properties as Map<*, *>))

        val output = File(context.filesDir, "ultra-artifact-$artifact.json")
        output.writeText(evidence.toString(2))
        android.util.Log.i("MAPLESU_EVIDENCE", "ultra-artifact $artifact " + evidence.toString())

        assertEquals(ModuleType.MAPLESU, report.type)
        assertEquals(expectedEntry, report.nativeEntry)
        assertEquals(expectedId, report.id)
    }
}
