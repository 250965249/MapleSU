package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * Temporary diagnostic fixture. Runs the exact production management path and reports the
 * real stage and error instead of a bare empty result, so the current root-executor start
 * failure can be attributed before any code change.
 */
class DiagManagementPathAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun emit(key: String, value: String) = instrumentation.sendStatus(2,
        Bundle().apply { putString("diag_$key", value) })

    @Test(timeout = 120_000) fun reportManagementStartStage() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val stages = ArrayList<String>()

        // Stage 1: internal credential shell (already proven by MapleSuExecutorAndroidTest).
        val internalShell = runCatching {
            MapleSuRuntime.openShell(context).use { shell ->
                "isRoot=${shell.isRoot},alive=${shell.isAlive}," +
                    "uid=" + shell.newJob().add("/system/bin/id -u").to(ArrayList(), ArrayList())
                        .exec().out.joinToString("")
            }
        }
        stages += "stage1_internal_key_shell=" + internalShell.fold({ it }, { "FAILED: $it" })
        emit("stage1", stages.last())

        // Stage 2: directory prepare, which must publish the Root endpoint.
        val prepared = runCatching { NativeSuDaemon.management(context) }
        stages += "stage2_management_endpoint=" + prepared.fold(
            { "ok" }, { "${it::class.java.simpleName}: ${it.message}" })
        emit("stage2", stages.last())

        // Stage 3: management status through the published endpoint.
        val status = prepared.mapCatching { it.status() }
        stages += "stage3_status=" + status.fold({ it.toString() }, { "FAILED: $it" })
        emit("stage3", stages.last())

        // Stage 4: a real management shell through the execution owner.
        val shellResult = runCatching {
            RootManagement.openShell(context).use { shell ->
                val out = shell.newJob().add("test \"\$(id -u)\" = 0 && echo MANAGEMENT_ROOT_OK")
                    .to(ArrayList(), ArrayList()).exec()
                "alive=${shell.isAlive},isRoot=${shell.isRoot},success=${out.isSuccess}," +
                    "out=${out.out},err=${out.err}"
            }
        }
        stages += "stage4_management_openShell=" + shellResult.fold({ it }, { "${it::class.java.simpleName}: ${it.message}" })
        emit("stage4", stages.last())

        // Stage 5: the exact production command shape the store fixture uses.
        val exact = runCatching {
            RootManagement.openShell(context).use { shell ->
                val out = shell.newJob().add("set -eu\nid -u\nstat -c '%u:%a' /data/adb/maplesu 2>&1 || echo STAT_FAILED")
                    .to(ArrayList(), ArrayList()).exec()
                "success=${out.isSuccess},out=${out.out},err=${out.err}"
            }
        }
        stages += "stage5_exact=" + exact.fold({ it }, { "${it::class.java.simpleName}: ${it.message}" })
        emit("stage5", stages.last())

        stages.forEach { emit("stage", it) }
        // This fixture reports, it does not gate: keep it green so the report is always delivered.
        assertTrue(true)
        instrumentation.sendStatus(2, Bundle().apply { putString("diag_all", stages.joinToString("\n")) })
        Unit.also { TimeUnit.MILLISECONDS.sleep(50) }
    }
}
