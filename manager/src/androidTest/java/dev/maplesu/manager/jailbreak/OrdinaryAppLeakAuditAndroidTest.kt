package dev.maplesu.manager.jailbreak

import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The vantage point the product must stay invisible from: an ordinary app with no
 * Root grant (this test package, a different uid than the Manager).
 *
 * Checked here:
 *  - no mount entry names this product (no overlay/bind leftovers),
 *  - no readable process cmdline names its Root executor,
 *  - its device-protected files are not readable from this uid,
 *  - the SELinux state is not left permissive,
 *  - the patched system library carries none of our bytes (heuristic: the product
 *    name does not appear in a page cache the whole system shares).
 */
class OrdinaryAppLeakAuditAndroidTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val manager = "dev.maplesu.manager"

    @Test fun noMountLeak() {
        val mounts = runCatching { File("/proc/self/mounts").readLines() }.getOrDefault(emptyList())
        /*
         * Every app has its own f2fs mounts for its data and profile directories; those
         * are not a leak. What must never appear is a mount this product created:
         * overlay, tmpfs, bind or any path outside the standard per-package set.
         */
        val standard = listOf("/data/user_de/0/dev.maplesu.manager", "/data/data/dev.maplesu.manager",
            "/data/misc/profiles/cur/0/dev.maplesu.manager", "/data/misc/profiles/ref/dev.maplesu.manager")
        val suspicious = mounts.filter { line ->
            val target = line.split(' ').getOrNull(1).orEmpty()
            val named = line.contains("maplesu") || line.contains("dfroot") || line.contains(dev.maplesu.manager.compat.StoredInputs.ENVIRONMENT_NAME_PATTERN)
            named && (target !in standard || line.contains(" overlay ") || line.contains(" tmpfs ")
                || line.contains("bind"))
        }
        assertTrue("mount table leaks the product: $suspicious", suspicious.isEmpty())
    }

    @Test fun noReadableExecutorProcess() {
        val visible = ArrayList<String>()
        val proc = File("/proc")
        proc.list()?.filter { it.all { character -> character.isDigit() } }?.forEach { pid ->
            val cmdline = File(proc, "$pid/cmdline")
            val text = runCatching { cmdline.readBytes().toString(Charsets.UTF_8) }.getOrNull() ?: return@forEach
            if (text.contains("$manager:root:")) visible.add("$pid:$text")
        }
        assertTrue("an ordinary app can read the Root executor cmdline: $visible", visible.isEmpty())
    }

    @Test fun attemptFilesAreNotWorldAccessible() {
        /*
         * NOTE: androidTest runs inside the target app's own process/uid, so canRead()
         * here proves nothing about an ordinary app. What is verifiable from anywhere
         * is the mode: attempt files must not be world readable and the directory must
         * not be world readable either. The uid vantage needs a separate probe APK.
         */
        val dataDir = File("/data/user_de/0/$manager")
        val worldReadable = dataDir.listFiles()?.filter { file ->
            val path = file.absolutePath
            val mode = runCatching {
                android.system.Os.stat(path).st_mode
            }.getOrDefault(0)
            (mode and 0x4) != 0
        } ?: emptyList()
        assertTrue("attempt files are world readable: $worldReadable", worldReadable.isEmpty())
    }

    @Test fun selinuxStaysEnforcingIfVisible() {
        val state = runCatching { File("/sys/fs/selinux/enforce").readText().trim() }.getOrNull()
        // An ordinary app usually cannot read selinuxfs at all (that is a pass);
        // when it can, the value must be enforcing.
        if (state != null) assertTrue("SELinux left permissive: $state", state == "1")
    }

    @Test fun systemLibraryCarriesNoProductBytes() {
        val library = File("/system/lib64/libc++.so")
        assertTrue("the system library is not readable from an ordinary app", library.canRead())
        val bytes = runCatching { library.readBytes() }.getOrNull()
        assertTrue("cannot read the system library", bytes != null)
        val needle = manager.toByteArray(Charsets.UTF_8)
        var found = -1
        outer@ for (index in 0..(bytes!!.size - needle.size)) {
            for (offset in needle.indices) {
                if (bytes[index + offset] != needle[offset]) continue@outer
            }
            found = index
            break
        }
        assertFalse("the shared page cache of libc++.so contains this product's name at $found",
            found >= 0)
        // Recorded for the report even when clean.
        println("leak-audit: libc++.so bytes=${bytes.size} sdk=${Build.VERSION.SDK_INT} needle=$found")
    }
}
