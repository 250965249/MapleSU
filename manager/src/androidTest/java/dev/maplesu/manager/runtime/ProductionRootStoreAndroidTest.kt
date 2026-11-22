package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Run before authorization mutations: prove the real one-time import retained its exact bytes. */
class ProductionRootStoreAndroidTest {
    @Test(timeout = 60_000) fun initialImportRetainsBytesAndPrivateOwnership() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyProductionRootOwner") == "true")
        val context = instrumentation.targetContext
        NativeSuDaemon.ensure(context)
        val uid = context.applicationInfo.uid
        val root = "/data/adb/maplesu/authorization/$uid"
        val legacy = "${context.noBackupFilesDir.absolutePath}/authorizations.bin"
        val result = RootManagement.openShell(context).use { shell ->
            shell.newJob().add("""
                set -eu
                test "${'$'}(id -u)" = 0
                test "${'$'}(stat -c '%u:%a' '$root')" = '0:700'
                test "${'$'}(stat -c '%u:%a' '$root/authorizations.bin')" = '0:600'
                test "${'$'}(stat -c '%u:%a' '$root/import-complete')" = '0:600'
                test "${'$'}(sha256sum '$legacy' | cut -d ' ' -f 1)" = "${'$'}(sha256sum '$root/authorizations.bin' | cut -d ' ' -f 1)"
                test "${'$'}(sed -n '2p' '$root/import-complete')" = '$uid'
                if grep -Eq '@(maplesu-su-v2|maplesu-[0-9a-f-]{36})${'$'}' /proc/net/unix; then exit 92; fi
                stat -c '%u:%g:%a:%n' '$root' '$root/authorizations.bin' '$root/import-complete'
                sha256sum '$legacy' '$root/authorizations.bin'
                cat '$root/import-complete'
                printf 'NAMED_SESSION_LISTENERS:absent\n'
            """.trimIndent()).to(ArrayList<String>(), ArrayList<String>()).exec()
        }
        instrumentation.sendStatus(2, Bundle().apply {
            putString("productionRootStore", result.out.joinToString("\n"))
            putString("productionRootStoreErrors", result.err.joinToString("\n"))
        })
        assertTrue(result.err.joinToString("\n"), result.isSuccess)
        assertTrue(result.out.contains("NAMED_SESSION_LISTENERS:absent"))
    }
}
