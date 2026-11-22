package dev.maplesu.manager.jailbreak

import android.net.LocalSocket
import android.net.LocalSocketAddress
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.DataInputStream
import java.io.File
import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test
import org.junit.runner.RunWith

/** No provider execution, kernel changes or root permission are needed by these probes. */
@RunWith(AndroidJUnit4::class)
class DirtyfragUltraTransportAndroidTest {
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun nativeFilesystemConnectorReachesTheAppListener() {
        val attempt = UUID.randomUUID().toString()
        val socket = HookAttestServer.socketFile(context, attempt)
        assertTrue(HookAttestServer.ensureListening(context, attempt, DirtyfragAttempt.readBootId(), 2000))
        assertTrue("filesystem listener must publish a pathname", socket.exists())
        LocalSocket(LocalSocket.SOCKET_STREAM).use { client ->
            client.soTimeout = 1500
            client.connect(LocalSocketAddress(socket.path, LocalSocketAddress.Namespace.FILESYSTEM))
            val hello = ByteArray(6)
            DataInputStream(client.inputStream).readFully(hello)
            assertEquals("hello\n", hello.toString(Charsets.UTF_8))
        }
        // The test's app-uid connector is intentionally not accepted as root evidence.
        assertEquals(null, HookAttestServer.read(context, attempt, DirtyfragAttempt.readBootId()))
    }

    @Test fun productHookStagesOnAReleaseWithNoLegacyIrSpec() {
        val inventory = IrImages.inventory(context)
        assumeFalse("bring-up builds intentionally use the legacy canary loader", inventory.isRootCanary)
        assertTrue("product must package the hook carrier", inventory.rootModule != null)
        val release = "6.6.999-android15-8-hook-staging-probe"
        assertFalse(IrImages.supports(context, release))
        val directory = File(context.cacheDir, "hook-staging-probe-" + UUID.randomUUID())
        assertTrue(directory.mkdirs())
        try {
            File(directory, IrImages.SPEC_FILE).writeText("stale per-release offsets")
            File(directory, IrImages.MARKER_FILE).writeText("")
            IrImages.stageForHook(context, directory, release)
            assertFalse(File(directory, IrImages.SPEC_FILE).exists())
            assertFalse(File(directory, IrImages.MARKER_FILE).exists())
            val staged = IrImages.stageHookModule(context, directory)
            assertTrue("packaged hook must keep the route available", staged != null)
            inventory.l3Module?.let { module ->
                assertEquals(module.bytes, File(directory, IrImages.STAGE2_FILE).length())
            }
        } finally {
            directory.deleteRecursively()
        }
    }
}
