package dev.maplesu.consumer

import android.content.Context
import android.content.pm.PackageManager
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.client.CooperativeSuClient
import dev.maplesu.client.CooperativeSuException
import dev.maplesu.client.SuRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/**
 * End-to-end proof that an ordinary third-party app (its own applicationId and
 * therefore its own Linux UID, no credential, no native SDK) can bind the public
 * MapleSU entry and drive a real Root session.
 *
 * Every assertion below observes a result produced by the Root side. There is no
 * fixture, no mocked transport, and no expected-output shortcut: the shell bytes
 * and the exit status come from the actual child process on the device.
 *
 * Run with `-e expectGranted true` once this app is authorized in MapleSU, or
 * with `-e expectGranted false` while it is not authorized.
 */
@RunWith(AndroidJUnit4::class)
class CooperativeSuClientTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val targetContext: Context get() = instrumentation.targetContext
    private val expectGranted: String =
        InstrumentationRegistry.getArguments().getString("expectGranted") ?: "true"
    private val granted: Boolean = expectGranted == "true"

    private var client: CooperativeSuClient? = null

    @Before
    fun connectClient() {
        client = connect()
        println("MAPLESU_EVIDENCE consumerUid=${android.os.Process.myUid()} " +
            "managerPackage=${client!!.service.asBinder().isBinderAlive}")
    }

    @After
    fun closeClient() {
        runCatching { client?.close() }
        client = null
    }

    // --- Authorization ------------------------------------------------------

    /**
     * Only meaningful while this app has no grant. The Root side may surface its
     * rejection as SecurityException across Binder, so both forms are accepted,
     * but the observed code/type is always included in a failure message.
     */
    @Test
    fun unauthorizedRequestIsRejected() {
        assumeTrue("requires -e expectGranted false", !granted)
        val request = SuRequest("/system/bin/id", listOf("id", "-u"))
        val session = try {
            client!!.start(request)
        } catch (failure: Throwable) {
            val code = (failure as? CooperativeSuException)?.code
            val observed = buildString {
                append(failure.javaClass.name)
                if (code != null) append(" code=").append(code)
                append(" message=").append(failure.message)
            }
            assertTrue(
                "expected AUTH_NOT_GRANTED from the Root side; observed $observed",
                observed.contains("AUTH_NOT_GRANTED"),
            )
            assertTrue(
                "unexpected rejection type; observed $observed",
                failure is CooperativeSuException || failure is SecurityException,
            )
            println("MAPLESU_EVIDENCE unauthorized rejection observed: $observed")
            return
        }
        session.close()
        fail("Root side started a session for an app that was never granted")
    }

    // --- Real command execution --------------------------------------------

    @Test
    fun runsRealCommandAsRoot() {
        assumeTrue("requires -e expectGranted true", granted)
        client!!.start(SuRequest("/system/bin/id", listOf("id", "-u"))).use { session ->
            val out = readAll(session.stdout)
            val err = readAll(session.stderr)
            val exit = session.awaitExit(10_000)
            assertNotNull("id -u did not finish; stderr=${quote(err)}", exit)
            assertEquals("exit status; stdout=${quote(out)} stderr=${quote(err)}", 0, exit)
            assertEquals("stdout; stderr=${quote(err)}", "0", out.trim())
            assertEquals("reported exitCode", 0, session.exitCode)
            println("MAPLESU_EVIDENCE id -u stdout=${quote(out.trim())} stderr=${quote(err.trim())} exit=$exit")
        }
    }

    @Test
    fun exitCodeIsPreserved() {
        assumeTrue("requires -e expectGranted true", granted)
        client!!.start(
            SuRequest("/system/bin/sh", listOf("sh", "-c", "exit 37")),
        ).use { session ->
            val exit = session.awaitExit(10_000)
            assertNotNull("exit 37 did not finish", exit)
            assertEquals("exit status from the real child", 37, exit)
            assertEquals("reported exitCode", 37, session.exitCode)
            println("MAPLESU_EVIDENCE sh -c 'exit 37' observed exit=$exit")
        }
    }

    @Test
    fun threeStreamsAreIndependent() {
        assumeTrue("requires -e expectGranted true", granted)
        client!!.start(
            SuRequest("/system/bin/sh", listOf("sh", "-c", "echo out; echo err >&2; exit 5")),
        ).use { session ->
            val out = readAll(session.stdout)
            val err = readAll(session.stderr)
            assertTrue("stdout must contain 'out'; stdout=${quote(out)}", out.contains("out"))
            assertFalse("stdout must not contain stderr text; stdout=${quote(out)}", out.contains("err"))
            assertTrue("stderr must contain 'err'; stderr=${quote(err)}", err.contains("err"))
            assertFalse("stderr must not contain stdout text; stderr=${quote(err)}", err.contains("out"))
            val exit = session.awaitExit(10_000)
            assertNotNull("sh did not finish", exit)
            assertEquals("exit status; stdout=${quote(out)} stderr=${quote(err)}", 5, exit)
            println("MAPLESU_EVIDENCE streams stdout=${quote(out.trim())} stderr=${quote(err.trim())} exit=$exit")
        }
    }

    @Test
    fun sigintTerminatesRunningTask() {
        assumeTrue("requires -e expectGranted true", granted)
        client!!.start(
            SuRequest("/system/bin/sh", listOf("sh", "-c", "sleep 30")),
        ).use { session ->
            // A null here is direct evidence that the real child is still running.
            assertNull("sleep exited before SIGINT could be sent", session.awaitExit(500))
            session.signal(OsConstants.SIGINT)
            val exit = session.awaitExit(10_000)
            assertNotNull("SIGINT did not terminate the task within 10 s", exit)
            assertEquals("expected 130 (128 + SIGINT), observed $exit", 130, exit)
            println("MAPLESU_EVIDENCE SIGINT observed exit=$exit")
        }
    }

    @Test
    fun ptyResizeIsAccepted() {
        assumeTrue("requires -e expectGranted true", granted)
        // terminals = 7: stdin, stdout and stderr all share the PTY. The Root side
        // then replaces all three child descriptors with the pty slave, so output
        // is only readable from the returned master - not from session.stdout.
        client!!.start(
            SuRequest("/system/bin/sh", listOf("sh", "-c", "tty; exit 0"), terminals = 7),
        ).use { session ->
            val terminal = session.openTerminal()
            assertNotNull("openTerminal returned null although a PTY was requested", terminal)
            // Must not throw: the Root side validates the window against this session.
            session.resize(24, 80)
            session.resize(40, 120)
            val out = readTerminal(terminal!!)
            assertTrue("PTY device path missing; terminal=${quote(out)}", out.contains("/dev/pts/"))
            val exit = session.awaitExit(10_000)
            assertNotNull("tty did not finish; terminal=${quote(out)}", exit)
            assertEquals("exit status; terminal=${quote(out)}", 0, exit)
            println("MAPLESU_EVIDENCE pty terminal=${quote(out.trim())} resize=24x80,40x120 exit=$exit")
        }
    }

    @Test
    fun awaitExitReportsUnfinished() {
        assumeTrue("requires -e expectGranted true", granted)
        val session = client!!.start(SuRequest("/system/bin/sh", listOf("sh", "-c", "sleep 3")))
        assertNull("awaitExit reported an exit for a task that is still running", session.awaitExit(50))
        session.cancel()
        session.close()
    }

    @Test
    fun sessionQuotaRecovers() {
        assumeTrue("requires -e expectGranted true", granted)
        // Twice the Root side's limit of four concurrent sessions: after each
        // natural exit and close the slot has to be available again.
        repeat(8) { index ->
            client!!.start(SuRequest("/system/bin/id", listOf("id", "-u"))).use { session ->
                val out = readAll(session.stdout)
                val exit = session.awaitExit(10_000)
                assertNotNull("iteration $index did not finish; stdout=${quote(out)}", exit)
                assertEquals("iteration $index exit status; stdout=${quote(out)}", 0, exit)
                assertEquals("iteration $index stdout", "0", out.trim())
            }
        }
        println("MAPLESU_EVIDENCE quota recovered across 8 sequential sessions")
    }

    @Test
    fun closedSessionRejectsFurtherCalls() {
        assumeTrue("requires -e expectGranted true", granted)
        val session = client!!.start(SuRequest("/system/bin/id", listOf("id", "-u")))
        session.close()
        val failure = try {
            session.awaitExit(0)
            null
        } catch (thrown: Throwable) {
            thrown
        }
        if (failure == null) {
            fail("a closed session accepted a further awaitExit call")
        }
        val code = (failure as? CooperativeSuException)?.code
        val observed = "${failure!!.javaClass.name} code=$code message=${failure.message}"
        assertNotNull("closed-session rejection carries no CooperativeSuException code; observed $observed", code)
        assertTrue(
            "expected a CLOSED-style code from the client; observed $observed",
            code!!.contains("CLOSED", ignoreCase = true),
        )
        println("MAPLESU_EVIDENCE closed session rejection: $observed")
    }

    // --- Helpers ------------------------------------------------------------

    /**
     * Binds the public Manager entry and verifies it against this app's signer.
     *
     * Signer policy: the cooperative client verifies the *Manager* against the
     * set passed here. A real third-party integrator must pin MapleSU's release
     * certificate instead. Passing this consumer's own signer digests is valid
     * only because this repository signs the Manager and this consumer with the
     * same (debug) key, so the expected and observed signer sets coincide.
     */
    private fun connect(): CooperativeSuClient {
        val digests = ownSignerDigests(targetContext)
        return try {
            CooperativeSuClient(targetContext, expectedSignerSha256 = digests).connect()
        } catch (failure: CooperativeSuException) {
            if (failure.code == "SU_EXECUTOR_NOT_READY" ||
                failure.message?.contains("SU_EXECUTOR_NOT_READY") == true
            ) {
                fail(
                    "MapleSU executor is not running: open the MapleSU Manager app once " +
                        "(unlocked) before running this test",
                )
            }
            throw failure
        } catch (failure: Exception) {
            if (failure.message?.contains("SU_EXECUTOR_NOT_READY") == true) {
                fail(
                    "MapleSU executor is not running: open the MapleSU Manager app once " +
                        "(unlocked) before running this test",
                )
            }
            throw failure
        }
    }

    private fun ownSignerDigests(context: Context): Set<String> {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES,
        )
        val signers = info.signingInfo?.apkContentsSigners ?: emptyArray()
        return signers.mapTo(LinkedHashSet()) { signature -> sha256Hex(signature.toByteArray()) }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    /** Bounded to 256 KiB, UTF-8, exactly as the Root-side reader is bounded. */
    private fun readAll(stream: InputStream): String {
        val bytes = ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        var total = 0
        while (total < MAX_BYTES) {
            val read = stream.read(chunk, 0, minOf(chunk.size, MAX_BYTES - total))
            if (read < 0) break
            bytes.write(chunk, 0, read)
            total += read
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    /**
     * Reads a PTY master until the stream ends.
     *
     * A pty master reports EIO, not a clean EOF, once the last slave descriptor is
     * gone; that is the normal end of the stream, so the partial bytes are kept.
     */
    private fun readTerminal(descriptor: ParcelFileDescriptor): String {
        val bytes = ByteArrayOutputStream()
        ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { stream ->
            val chunk = ByteArray(8192)
            try {
                while (bytes.size() < MAX_BYTES) {
                    val read = stream.read(chunk)
                    if (read < 0) break
                    bytes.write(chunk, 0, read)
                }
            } catch (_: IOException) {
                // EIO after the slave closes: normal end of a pty master.
            }
        }
        return String(bytes.toByteArray(), Charsets.UTF_8)
    }

    private fun quote(value: String): String = "\"" + value.replace("\n", "\\n") + "\""

    private companion object {
        const val MAX_BYTES = 256 * 1024
    }
}
