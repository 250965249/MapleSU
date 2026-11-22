package dev.maplesu.consumer

import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.view.ViewGroup
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import dev.maplesu.client.CooperativeSuClient
import dev.maplesu.client.CooperativeSuException
import dev.maplesu.client.SuRequest
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.Executors

/**
 * Manual demonstration surface for the cooperative (no-Key) Root entry.
 *
 * Every button performs a real bind and a real Binder request against the
 * installed Manager and appends only the observed result. Nothing here
 * fabricates output: the command buttons report the actual bytes and exit
 * status that the Root side produced.
 *
 * This app holds no credential, links no native SDK, and requests no permission.
 */
class MainActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var logView: TextView
    @Volatile private var client: CooperativeSuClient? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(buildContent())
        append(getString(R.string.log_ready))
        append("applicationId=$packageName uid=${Process.myUid()}")
        append("signerSha256=${ownSignerDigests().joinToString()}")
    }

    override fun onDestroy() {
        runCatching { client?.close() }
        client = null
        worker.shutdownNow()
        super.onDestroy()
    }

    // --- UI -----------------------------------------------------------------

    private fun buildContent(): ViewGroup {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
        }
        logView = TextView(this).apply {
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
            setPadding(0, 0, 0, dp(8))
        }
        root.addView(ScrollView(this).apply {
            addView(logView, FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f)
        })
        val actions: List<Pair<Int, () -> Unit>> = listOf(
            R.string.action_connect to ::connect,
            R.string.action_id to ::runId,
            R.string.action_exit to ::runExit,
            R.string.action_pty to ::runPty,
        )
        for ((label, action) in actions) {
            root.addView(Button(this).apply {
                text = getString(label)
                isAllCaps = false
                setOnClickListener { run(label, action) }
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        return root
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    private fun run(label: Int, action: () -> Unit) {
        // Everything that can block on Binder or on a root child stays off the UI thread.
        worker.execute {
            val started = System.currentTimeMillis()
            try {
                action()
            } catch (error: Throwable) {
                append("${getString(label)} failed: ${describe(error)}")
            } finally {
                append("${getString(label)} finished in ${System.currentTimeMillis() - started} ms")
            }
        }
    }

    private fun append(line: String) {
        main.post {
            if (!::logView.isInitialized) return@post
            logView.append(if ((logView.text?.length ?: 0) == 0) line else "\n$line")
        }
    }

    private fun describe(error: Throwable): String {
        val code = (error as? CooperativeSuException)?.code
        val suffix = if (code == null) "" else " code=$code"
        return "${error.javaClass.simpleName}$suffix: ${error.message}"
    }

    // --- Real actions -------------------------------------------------------

    private fun connect() {
        client?.let { previous -> runCatching { previous.close() } }
        client = null
        val fresh = CooperativeSuClient(
            applicationContext,
            expectedSignerSha256 = ownSignerDigests(),
        ).connect()
        client = fresh
        append("connected: service=${fresh.service.asBinder()}")
    }

    private fun runId() {
        // Real /system/bin/id: the value is whatever the Root side actually runs.
        requireClient().start(SuRequest("/system/bin/id", listOf("id", "-u"))).use { session ->
            val out = readBounded(session.stdout)
            val err = readBounded(session.stderr)
            val exit = session.awaitExit(10_000)
            append("id -u stdout=${quote(out)} stderr=${quote(err)} exit=$exit exitCode=${session.exitCode}")
        }
    }

    private fun runExit() {
        requireClient().start(
            SuRequest("/system/bin/sh", listOf("sh", "-c", "exit 37")),
        ).use { session ->
            append("exit 37 -> awaitExit=${session.awaitExit(10_000)} exitCode=${session.exitCode}")
        }
    }

    private fun runPty() {
        // terminals=7 puts stdin, stdout and stderr on the same PTY, so the Root side
        // replaces all three child descriptors with the pty slave: output is only
        // readable from the returned master, not from session.stdout.
        val request = SuRequest(
            "/system/bin/sh",
            listOf("sh", "-c", "tty; sleep 1; exit 0"),
            terminals = 7,
        )
        requireClient().start(request).use { session ->
            val terminal = session.openTerminal()
            append("openTerminal=${terminal?.fd ?: "null"}")
            if (terminal == null) return@use
            session.resize(24, 80)
            session.resize(40, 120)
            append("resize 24x80 then 40x120 accepted")
            val out = readTerminal(terminal)
            append("pty output=${quote(out)} exit=${session.awaitExit(10_000)}")
        }
    }

    private fun requireClient(): CooperativeSuClient =
        client ?: throw IllegalStateException("Connect first")

    // --- Observation helpers ------------------------------------------------

    /** Bounded to 256 KiB so a noisy root child cannot exhaust this process. */
    private fun readBounded(stream: InputStream): String {
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

    private fun quote(value: String): String = "\"" + value.replace("\n", "\\n") + "\""

    /**
     * Reads a PTY master until the stream ends.
     *
     * A pty master reports EIO once the last slave descriptor is gone; that is the
     * normal end of the stream, so the bytes read so far are kept.
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

    /**
     * SHA-256 digests of every signer of *this* package.
     *
     * Signer policy: the cooperative client verifies the Manager against this
     * set. A real third-party integrator must pin MapleSU's release certificate
     * here instead of its own. Reusing this app's own signer set is valid only
     * because this repository signs both the Manager and this consumer with one
     * key (the debug key), so the expected and observed signer sets coincide.
     */
    private fun ownSignerDigests(): Set<String> {
        val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val signers = info.signingInfo?.apkContentsSigners ?: emptyArray()
        return signers.mapTo(LinkedHashSet()) { signature -> sha256Hex(signature.toByteArray()) }
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val MAX_BYTES = 256 * 1024
    }
}
