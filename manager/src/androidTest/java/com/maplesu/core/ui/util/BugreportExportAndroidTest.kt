package com.maplesu.core.ui.util

import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.zip.GZIPInputStream

/** Opt-in production collection and ContentResolver export; no privileged channel is required. */
class BugreportExportAndroidTest {
    @Test fun savedReportIsReadableAndContainsAppDiagnostics() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyLogExport") == "true")
        val arguments = InstrumentationRegistry.getArguments()
        val verifyPolicy = arguments.getString("verifyPolicyDiagnostics") == "true"
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val destination = File.createTempFile("bugreport-export-test-", ".tar.gz", context.cacheDir)
        try {
            saveBugreport(context, Uri.fromFile(destination))
            assertTrue("Export left an empty document", destination.length() > 0)
            val contents = mutableMapOf<String, String>()
            GZIPInputStream(destination.inputStream()).use { gzip ->
                TarArchiveInputStream(gzip).use { tar ->
                    while (true) {
                        val entry = tar.nextEntry ?: break
                        if (entry.name in setOf("basic.txt", "collection.txt", "ultra-module-policy.txt", "ultra-authorization.txt")) {
                            contents[entry.name] = tar.readBytes().toString(Charsets.UTF_8)
                        }
                    }
                }
            }
            assertTrue("Missing device information", contents["basic.txt"].orEmpty().contains("MODEL:"))
            assertTrue("Missing collection result", contents["collection.txt"].orEmpty().contains("Root shell available:"))
            if (verifyPolicy) {
                val policy = contents["ultra-module-policy.txt"].orEmpty()
                assertTrue("Missing policy diagnostics", policy.contains("module_policy_diagnostics:"))
                assertTrue("Missing policy failure", policy.contains("MODULE_POLICY_LOADER_HOOK_CONFLICT"))
                assertTrue("Missing kernel identity", policy.contains("buildId=") && policy.contains("pageSize="))
                assertTrue("Missing boot identity", policy.contains("current_boot=") && policy.contains("boot="))
                assertTrue("Report was truncated", policy.contains("module_policy_diagnostics_end"))
                assertTrue("Old SDK collected report", contents["ultra-authorization.txt"].orEmpty()
                    .contains("maplesu-ultra-5.2.0-policy-r20-20261108"))
            }
        } finally {
            destination.delete()
        }
    }
}
