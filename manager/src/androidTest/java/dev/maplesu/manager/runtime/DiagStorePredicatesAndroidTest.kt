package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Temporary diagnostic: evaluate every store-fixture predicate separately, reporting real state. */
class DiagStorePredicatesAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test(timeout = 120_000) fun reportEachStorePredicate() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val uid = context.applicationInfo.uid
        val root = "/data/adb/maplesu/authorization/$uid"
        val legacy = "${context.noBackupFilesDir.absolutePath}/authorizations.bin"
        val report = ArrayList<String>()
        RootManagement.openShell(context).use { shell ->
            for ((name, command) in listOf(
                "p1_uid" to "id -u",
                "p2_root_mode" to "stat -c '%u:%a' '$root' 2>&1 || echo MISSING",
                "p3_store_mode" to "stat -c '%u:%a' '$root/authorizations.bin' 2>&1 || echo MISSING",
                "p4_marker_mode" to "stat -c '%u:%a' '$root/import-complete' 2>&1 || echo MISSING",
                "p5_legacy_sha" to "sha256sum '$legacy' 2>&1 || echo MISSING",
                "p6_store_sha" to "sha256sum '$root/authorizations.bin' 2>&1 || echo MISSING",
                "p7_marker_uid_line" to "sed -n '2p' '$root/import-complete' 2>&1 || echo MISSING",
                "p8_named_listeners" to "grep -E '@(maplesu-su-v2|maplesu-[0-9a-f-]{36})$' /proc/net/unix || echo NO_MATCH",
                "p9_full_listing" to "stat -c '%u:%g:%a:%n' '$root' '$root/authorizations.bin' '$root/import-complete' 2>&1",
                "p10_legacy_dir" to "ls -la '${context.noBackupFilesDir.absolutePath}' 2>&1 | head -6",
                "p11_whoami" to "id"
            )) {
                val out = shell.newJob().add(command).to(ArrayList(), ArrayList()).exec()
                val text = "ok=${out.isSuccess} out=${out.out} err=${out.err}"
                report += "$name :: $text"
                instrumentation.sendStatus(2, Bundle().apply { putString("diag_$name", text) })
            }
        }
        instrumentation.sendStatus(2, Bundle().apply { putString("diag_store_all", report.joinToString("\n")) })
        assertTrue(true)
    }
}
