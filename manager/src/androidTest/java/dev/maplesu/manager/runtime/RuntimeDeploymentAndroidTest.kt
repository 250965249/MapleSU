package dev.maplesu.manager.runtime

import android.system.Os
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Publication contract.
 *
 * <p>The entry lives at `/data/<derived>/su` - under a directory an ordinary app can
 * traverse but not list, named by a derived token rather than by the product - and is
 * a symbolic link to the installed library. The former `/dev/maplesu` tree must be
 * gone, no metadata file may exist, and no mount may be created.
 */
class RuntimeDeploymentAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun publicationPublishesResolvableLinkWithoutMetadata() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        RuntimeDeployment.start(context)
        val clientPath = RuntimeDeployment.clientPath(context)
        val source = Os.stat(File(context.applicationInfo.nativeLibraryDir, "libmaplesu_su.so").path)
        val deadline = android.os.SystemClock.elapsedRealtime() + 20_000
        while (runCatching { Os.stat(clientPath) }.getOrNull()?.st_ino != source.st_ino &&
            android.os.SystemClock.elapsedRealtime() < deadline) Thread.sleep(50)
        val published = Os.stat(clientPath)
        assertEquals(source.st_dev, published.st_dev)
        assertEquals(source.st_ino, published.st_ino)
        // A link, not a mount: lstat must show a symlink resolving to the library.
        assertTrue(OsConstants_S_ISLNK(Os.lstat(clientPath).st_mode))
        assertEquals(File(context.applicationInfo.nativeLibraryDir, "libmaplesu_su.so").path,
            File(clientPath).canonicalPath)
        // The directory is root-owned and traversable, and carries a pre-existing type.
        val directory = File(clientPath).parentFile!!
        val stat = Os.stat(directory.path)
        assertEquals(0, stat.st_uid)
        assertEquals(0, stat.st_gid)
        assertEquals(0x1ED /* 0755 */, stat.st_mode and 0xFFF)
        assertEquals("u:object_r:system_file:s0",
            Os.getxattr(directory.path, "security.selinux").toString(Charsets.UTF_8).trim('\u0000'))
        // Nothing product-named may remain under /dev, and no metadata file exists.
        assertFalse("the former /dev publication must be gone", File("/dev/maplesu").exists())
        for (name in listOf("manager.uid", "manager.apk", "manager.lib")) {
            assertFalse("/dev/maplesu/$name must not exist", File("/dev/maplesu/$name").exists())
        }
        // An ordinary app can traverse /data but must not be able to enumerate it,
        // which is what makes the derived name unguessable.
        assertNull("an ordinary app must not be able to list /data", File("/data").list())
    }

    @Test fun repeatedPublicationCreatesNoMountAndKeepsStandardPathUnpublished() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val source = Os.stat(File(context.applicationInfo.nativeLibraryDir, "libmaplesu_su.so").path)
        val clientPath = RuntimeDeployment.clientPath(context)
        repeat(2) {
            val result = RuntimeDeployment.deploy(context)
            assertEquals(clientPath, result.clientPath)
            // The standard path stays unpublished by design; the state is explicit.
            assertNull(result.standardPath)
            assertEquals("SU_STANDARD_PATH_NOT_PUBLISHED", result.error)
            val published = Os.stat(clientPath)
            assertEquals(source.st_dev, published.st_dev)
            assertEquals(source.st_ino, published.st_ino)
        }
        // Android mounts every app's own data directory; those are not ours. What must
        // not appear is a mount at the published entry or an overlay from an earlier
        // revision.
        val publication = File("/proc/self/mountinfo").readLines().filter { line ->
            line.contains(" $clientPath ") || line.contains(" maplesu-su ")
        }
        assertTrue("publication must create no mount, found: $publication", publication.isEmpty())
        assertFalse(File("/dev/maplesu").exists())
    }

    private fun OsConstants_S_ISLNK(mode: Int): Boolean = (mode and 0xF000) == 0xA000
}
