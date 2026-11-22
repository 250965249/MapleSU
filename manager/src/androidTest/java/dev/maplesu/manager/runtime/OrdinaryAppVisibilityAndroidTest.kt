package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Ordinary-app-domain observability probe.
 *
 * <p>An instrumentation process runs with the target application's real UID and real
 * SELinux domain, so this is the closest thing to "what an installed app can see" that
 * does not require a separate probe APK. Every measurement is emitted as a
 * `MAPLESU_VISIBILITY` line so the result is quotable evidence instead of an assertion
 * that hides its own inputs.
 *
 * <p>It records what is observable, not a claim of invisibility: a zero-match run only
 * covers the checks performed here, on this device, in this domain.
 */
class OrdinaryAppVisibilityAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun report(label: String, value: String) {
        android.util.Log.i("MapleSU", "MAPLESU_VISIBILITY $label=$value")
    }

    private fun probe(label: String, path: String, read: Boolean = false): String = runCatching {
        val file = File(path)
        if (!file.exists()) return@runCatching "ABSENT"
        val stat = android.system.Os.lstat(path)
        val mode = Integer.toOctalString(stat.st_mode and 0xFFF)
        val kind = when {
            (stat.st_mode and 0xF000) == 0xA000 -> "symlink->" + runCatching { file.canonicalPath }.getOrElse { "?" }
            (stat.st_mode and 0xF000) == 0x4000 -> "dir"
            (stat.st_mode and 0xF000) == 0x8000 -> "file"
            (stat.st_mode and 0xF000) == 0x1000 -> "fifo"
            else -> "other"
        }
        val content = if (read && kind == "file") {
            runCatching { file.readText().take(120).replace("\n", "\\n") }.getOrElse { "READ_FAILED:" + (it.message ?: it.javaClass.simpleName) }
        } else "not-read"
        "$kind mode=$mode size=${stat.st_size} content=$content"
    }.getOrElse { "ERR:" + (it.message ?: it.javaClass.simpleName) }

    private fun label(path: String): String = runCatching {
        android.system.Os.getxattr(path, "security.selinux").toString(Charsets.UTF_8).trim('\u0000')
    }.getOrElse { "UNREADABLE:" + (it.message ?: it.javaClass.simpleName) }

    @Test fun recordsWhatAnOrdinaryAppCanObserve() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val clientPath = RuntimeDeployment.clientPath(context)
        val directory = File(clientPath).parentFile!!
        report("uid", Process.myUid().toString())
        report("domain", runCatching { File("/proc/self/attr/current").readText().trim() }.getOrElse { "?" })

        // 1. Published entry, its derived directory, and the former /dev location.
        report("path.client", probe("path.client", clientPath))
        report("path.directory", probe("path.directory", directory.path))
        report("path.legacyDev", probe("path.legacyDev", "/dev/maplesu"))
        for (name in listOf("manager.uid", "manager.apk", "manager.lib")) {
            report("path.legacyMetadata.$name", probe("path.legacyMetadata.$name", "/dev/maplesu/$name"))
        }

        // 2. Mount table: only framework per-app data mounts may mention the package.
        val publicationMounts = File("/proc/self/mountinfo").readLines().filter {
            it.contains(" $clientPath ") || it.contains(" maplesu-su ")
        }
        report("mounts.publication", publicationMounts.size.toString())
        publicationMounts.take(3).forEach { report("mounts.line", it) }
        val productMounts = File("/proc/self/mountinfo").readLines().count {
            it.contains("maplesu", ignoreCase = true) && !it.contains("/data/data/") &&
                !it.contains("/data/user_de/") && !it.contains("/data/user/") && !it.contains("/misc/profiles/")
        }
        report("mounts.productNamed", productMounts.toString())

        // 3. Process visibility. /proc/<pid>/cmdline of another UID is the practical
        //    question: if it is readable, a product-derived argv is a fingerprint.
        val pidEntries = File("/proc").listFiles()?.filter { it.name.all(Char::isDigit) } ?: emptyList()
        var readableForeign = 0
        var productNamed = 0
        val samples = StringBuilder()
        for (entry in pidEntries) {
            val cmdline = runCatching { File("${entry.path}/cmdline").readBytes() }.getOrNull() ?: continue
            if (cmdline.isEmpty()) continue
            val text = String(cmdline, Charsets.UTF_8).replace('\u0000', ' ').trim()
            if (text.isEmpty()) continue
            if (text.contains("maplesu", ignoreCase = true)) {
                productNamed++
                if (samples.length < 240) samples.append("[").append(entry.name).append("]").append(text.take(80)).append(" | ")
            }
            val owner = runCatching {
                File("/proc/${entry.name}/status").readLines()
                    .firstOrNull { it.startsWith("Uid:") }?.split(Regex("\\s+"))?.getOrNull(1)
            }.getOrNull()
            if (owner != null && owner != Process.myUid().toString()) readableForeign++
        }
        report("proc.readableForeignCmdlines", readableForeign.toString())
        report("proc.productNamedCmdlines", productNamed.toString())
        report("proc.productNamedSamples", samples.toString().ifEmpty { "NONE" })

        // 4. Named unix sockets registered by the product.
        val unix = runCatching { File("/proc/net/unix").readLines() }.getOrElse { emptyList() }
        report("unix.productNamed", unix.count { it.contains("maplesu", ignoreCase = true) }.toString())

        // 5. Component discoverability of the discovery entry.
        val component = ComponentName(context.packageName, NativeSuBrokerService::class.java.name)
        val resolved = runCatching {
            context.packageManager.queryIntentServices(Intent(NativeSuBrokerService.PEEK_ACTION), 0)
                .map { it.serviceInfo.name }
        }.getOrElse { listOf("QUERY_FAILED:" + (it.message ?: it.javaClass.simpleName)) }
        report("component.brokerQuery", resolved.toString())
        report("component.brokerClass", component.className)

        // 6. Product-named properties and the process environment.
        val props = runCatching { File("/proc/self/environ").readBytes() }.getOrNull()
        report("env.selfHasProductName",
            (props != null && String(props, Charsets.UTF_8).contains("maplesu", ignoreCase = true)).toString())
        val propertyMatches = runCatching {
            val process = ProcessBuilder("/system/bin/getprop").redirectErrorStream(true).start()
            process.inputStream.bufferedReader().readText().lines()
                .filter { it.contains("maplesu", ignoreCase = true) }
        }.getOrElse { listOf("GETPROP_FAILED:" + (it.message ?: it.javaClass.simpleName)) }
        report("props.productNamed", propertyMatches.toString())

        // 7. Credential isolation (K01). Every path that could carry the main key or
        //    recoverable authentication material must be unreadable from another UID;
        //    this process shares the Manager UID, so it records its own encrypted record
        //    and the Root-private authorization table only.
        val credentialPath = File(context.noBackupFilesDir, "maplesu-credential.bin").absolutePath
        report("key.keystoreRecord", probe("key.keystoreRecord", credentialPath, read = true))
        report("key.authorizationTable",
            probe("key.authorizationTable", "/data/adb/maplesu/authorization/10481/authorizations.bin", read = true))
        report("key.authorizationDir", probe("key.authorizationDir", "/data/adb/maplesu"))
        report("key.clientImageReadable", probe("key.clientImageReadable", clientPath))
        report("key.runtimeImageReadable", probe("key.runtimeImageReadable",
            File(context.applicationInfo.nativeLibraryDir, "libmaplesu_runtime.so").absolutePath))

        // 8. Backing files of the client inside the APK directory.
        report("apk.dir", probe("apk.dir", context.applicationInfo.nativeLibraryDir))
        report("apk.libSu", probe("apk.libSu",
            File(context.applicationInfo.nativeLibraryDir, "libmaplesu_su.so").absolutePath))

        // 9. SELinux labels as this domain can read them. A label that differs from the
        //    surrounding directory is itself an observable point.
        for (path in listOf("/dev", "/data", "/data/app", directory.path, clientPath)) {
            report("label.${path.replace('/', '_')}", label(path))
        }

        // 10. Enumeration. `/data` must not be listable by an ordinary app, which is what
        //     makes the derived directory name unguessable; the published directory
        //     itself is traversable (it has to be) and contains only the client entry.
        report("data.listable",
            runCatching { File("/data").list()?.joinToString(",") ?: "NOT_LISTABLE" }
                .getOrElse { "NOT_LISTABLE:" + (it.message ?: it.javaClass.simpleName) }.toString())
        report("published.entries",
            runCatching { directory.list()?.joinToString(",") ?: "NULL" }
                .getOrElse { "ERR:" + (it.message ?: it.javaClass.simpleName) }.toString())

        // Hard contract assertions for this batch: nothing product-named under /dev, no
        // publication mount, /data not listable.
        assertFalse("the former /dev publication must be gone", File("/dev/maplesu").exists())
        assertTrue("publication must create no mount: $publicationMounts", publicationMounts.isEmpty())
        assertNull("an ordinary app must not be able to list /data", File("/data").list())
    }
}
