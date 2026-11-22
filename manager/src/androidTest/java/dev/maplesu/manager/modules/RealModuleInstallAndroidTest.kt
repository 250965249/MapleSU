package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ModuleArchiveInspector
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.json.JSONArray
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/**
 * Installs the three fixed target packages from the compatibility contract and
 * records what MapleSU actually does with each one.
 *
 * The ZIP inputs use fixed local file names; their inspected SHA-256 values are
 * recorded in the output. This test never downloads or substitutes packages. A package
 * that fails inspection or installation is recorded and fails the test after
 * all packages have been attempted. The receipts cover installation only;
 * boot activation and module behavior require their own acceptance checks.
 *
 * Opt-in, because it writes below /data/adb and runs real Root work:
 * `-e verifyMapleSuBoot true`
 */
class RealModuleInstallAndroidTest {

    @Test(timeout = 180_000) fun fixedTargetPackagesInstallResults() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val backend = LiteScriptModuleBackend(context)
        val catalog = ModuleCatalog(File(context.filesDir, "module-catalog"))
        val revisionRoot = File(context.filesDir, "module-runtime/revisions")

        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        fun root(command: String): List<String> = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
            assertTrue(result.err.joinToString("\n"), result.isSuccess)
            result.out
        }
        fun revisionKey(report: ModuleArchiveInspector.Report): String =
            MessageDigest.getInstance("SHA-256")
                .digest("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
                .joinToString("") { "%02x".format(it.toInt() and 255) }

        val summary = mutableListOf<String>()
        val failures = mutableListOf<String>()
        for (name in PACKAGES) {
            val archive = File(INPUT_DIR, name)
            if (!archive.isFile) {
                println("MAPLESU_MODULE_EVIDENCE package=$name result=INPUT_MISSING path=${archive.absolutePath}")
                summary += "$name=INPUT_MISSING"
                failures += "$name=INPUT_MISSING"
                continue
            }
            val out = mutableListOf<String>()
            val err = mutableListOf<String>()
            var report: ModuleArchiveInspector.Report? = null
            var key: String? = null
            try {
                report = try {
                    ModuleArchiveInspector.inspect(archive)
                } catch (failure: ModuleArchiveInspector.Failure) {
                    println("MAPLESU_MODULE_EVIDENCE package=$name result=INSPECT_REJECTED code=${failure.code}")
                    summary += "$name=INSPECT_REJECTED:${failure.code}"
                    failures += "$name=INSPECT_REJECTED:${failure.code}"
                    continue
                }
                println("MAPLESU_MODULE_EVIDENCE package=$name type=${report.type} id=${report.id} " +
                    "versionCode=${report.versionCode} sha256=${report.sha256} " +
                    "features=${report.features.joinToString(",")} nativeEntry=${report.nativeEntry} " +
                    "entries=${report.entryCount} skipMount=${report.skipMount}")
                key = revisionKey(report)
                val revision = File(revisionRoot, key)
                val installed = backend.install(archive, report, out::add, err::add)
                println("MAPLESU_MODULE_EVIDENCE package=$name result=INSTALL_RETURNED code=${installed.code} " +
                    "needsReboot=${installed.needsReboot} revisionExists=${revision.exists()} " +
                    "rootCommitted=${installed.rootCommitted} commitUnknown=${installed.commitUnknown} " +
                    "archiveError=${installed.archiveError}")
                if (installed.code != 0 || !installed.rootCommitted || installed.commitUnknown || installed.archiveError != null) {
                    failures += "$name=INSTALL_FAILED:${installed.code}:committed=${installed.rootCommitted}:" +
                        "unknown=${installed.commitUnknown}:archive=${installed.archiveError}"
                }
                if (out.isNotEmpty()) println("MAPLESU_MODULE_EVIDENCE package=$name stdout=${quote(out.joinToString(" | "))}")
                if (err.isNotEmpty()) println("MAPLESU_MODULE_EVIDENCE package=$name stderr=${quote(err.joinToString(" | "))}")
                val listed = runCatching {
                    JSONArray(backend.listJson()).let { array ->
                        (0 until array.length()).map { array.getJSONObject(it) }
                            .firstOrNull { it.getString("id") == report.id }
                    }
                }.getOrNull()
                println("MAPLESU_MODULE_EVIDENCE package=$name listed=" +
                    (listed?.toString() ?: "absent"))
                if (listed == null) failures += "$name=NOT_LISTED"
                summary += "$name=code:${installed.code}"
            } finally {
                // Restore: remove only this package's revision and catalog entry.
                runCatching {
                    val id = report?.id ?: return@runCatching
                    val revision = key?.let { File(revisionRoot, it) }
                    if (revision != null && revision.exists()) {
                        runCatching { root("rm -rf -- ${quote(revision.absolutePath)}") }
                    }
                    runCatching {
                        catalog.get(report.type, id)
                            ?.takeIf { it.report.sha256 == report.sha256 }
                            ?.let { catalog.uninstall(report.type, id) }
                    }
                }
            }
        }
        println("MAPLESU_MODULE_EVIDENCE summary=${summary.joinToString(";")}")
        assertTrue("Module installation failures: ${failures.joinToString(";")}", failures.isEmpty())
    }

    private companion object {
        const val INPUT_DIR = "/data/local/tmp/maple-module-input"
        val PACKAGES = listOf(
            "zygisk-next-1.5.2.zip",
            "lsposed-2.1.1.zip",
            "teesimulator-rs-6.0.1-307.zip",
        )
    }
}
