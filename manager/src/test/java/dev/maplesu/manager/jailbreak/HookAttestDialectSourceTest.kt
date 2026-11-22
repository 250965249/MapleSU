package dev.maplesu.manager.jailbreak

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * M2 static gate (report `maplesu-ultra-attestation-stability-2026-10-31.md` §5): one
 * socket path, one dialect, one listener.
 *
 * <p>The path `maplesu-hook-&lt;attempt&gt;.sock` used to be spoken in two incompatible
 * dialects. [HookAttestServer] listens, writes `hello` and reads the worker's JSON
 * (`bootstrap.c`'s reverse connect, DEV-174); the old forward branch in `HookWorker`
 * instead connected to the same name and wrote `hello &lt;nonce&gt;`. The only listener
 * that could ever be at that path was the App's own, so the forward dial always failed -
 * and its fallback unlinked the live 300 s listener (R2). The tests below read the
 * sources and refuse a second dialect or a second binder coming back:
 *
 *  - `HookWorker.kt` may not contain the forward dialect at all (no `hello ` literal, no
 *    client socket, no second parser);
 *  - exactly one file may bind an AF_UNIX listener, and it is [HookAttestServer];
 *  - the claim may not bind: it arms/reuses the singleton and polls the record;
 *  - the dialect the App speaks must be the one `bootstrap.c` implements.
 */
class HookAttestDialectSourceTest {

    private val managerDir: File = sequenceOf(
        File("."), File("manager"), File("../manager"),
    ).map { it.absoluteFile.normalize() }
        .firstOrNull { File(it, "src/main/java").isDirectory }
        ?: error("cannot locate the manager module from " + File(".").absolutePath)

    private val repoRoot = managerDir.parentFile
    private val server = File(managerDir,
        "src/main/java/dev/maplesu/manager/jailbreak/HookAttestServer.kt")
    private val worker = File(managerDir,
        "src/main/java/dev/maplesu/manager/jailbreak/HookWorker.kt")
    private val bootstrap = File(repoRoot,
        "jailbreak-providers/dirtyfrag/adapter/bootstrap.c")
    private val ghostlockHandover = File(managerDir,
        "src/main/java/dev/maplesu/manager/jailbreak/GhostlockHandover.kt")

    private fun text(file: File): String = file.readText(Charsets.UTF_8)

    @Test
    fun `ghostlock listener covers staging and the whole prepare budget`() {
        val body = text(ghostlockHandover).replace(Regex("\\s+"), " ")
        assertTrue("the listener starts before the native wait and must cover the whole prepare",
            body.contains("HookAttestServer.listen(context, request.attemptId, boot, " +
                "hookPrepareBudgetMillis(request).toInt())"))
    }

    /** Every Kotlin/Java source the App compiles, including the provider source dir. */
    private fun appSources(): List<File> {
        val roots = buildList {
            add(File(managerDir, "src/main"))
            File(repoRoot, "jailbreak-providers/android/src/main/java")
                .takeIf { it.isDirectory }?.let { add(it) }
        }
        return roots.flatMap { root ->
            root.walkTopDown()
                .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
                .filterNot { it.path.contains("${File.separator}test${File.separator}") }
                .filterNot { it.path.contains("androidTest") }
                .toList()
        }.distinctBy { it.absolutePath }
    }

    @Test
    fun `the claim has no forward dialect left`() {
        val body = text(worker)
        for (banned in listOf(
            "\"hello ",              // the forward hello <nonce> the worker never answered
            "LocalSocket",           // any AF_UNIX client socket at all
            "peerCredentials",       // client-side ucred: the wrong direction for this proof
            "parseReply",            // the second JSON dialect's parser
        )) {
            assertFalse("HookWorker.kt still carries the retired forward dialect: " + banned,
                body.contains(banned))
        }
        // The one remaining move is the bounded wait on this process's listener.
        assertTrue("the claim must go through HookAttestServer.handshake",
            body.contains("HookAttestServer.handshake(context, attemptId, bootId, timeoutMillis)"))
        assertTrue("the claim reads the recorded answer first",
            body.contains("HookAttestServer.read(context, attemptId, bootId)"))
    }

    @Test
    fun `no Kotlin or Java source speaks the hello nonce dialect`() {
        val offenders = appSources().filter { text(it).contains("\"hello ") }
        assertTrue("only the listener may produce the hello line, found a second producer: " +
            offenders.joinToString { it.absolutePath }, offenders.isEmpty())
    }

    @Test
    fun `the hook attestation socket has exactly one binder`() {
        // The lease transport has its own AF_UNIX listener (`RootShellLease`); the rule
        // this test enforces is about the hook attestation socket only.
        val binders = appSources().filter {
            val body = text(it)
            body.contains("LocalServerSocket(") && body.contains("maplesu-hook-")
        }
        assertEquals("one listener, one file: " + binders.joinToString { it.absolutePath },
            listOf(server.absolutePath), binders.map { it.absolutePath })
        assertEquals("the attestation listener is created in exactly one place",
            1, Regex(Regex.escape("LocalServerSocket(")).findAll(text(server)).count())
    }

    @Test
    fun `the claim reuses the singleton listener instead of binding again`() {
        val body = text(server)
        assertTrue("the listener is a process-wide singleton",
            body.contains("@Volatile private var listener: Listener?"))
        assertEquals("only ensureListening may bind",
            1, Regex(Regex.escape("val created = bind(")).findAll(body).count())
        assertTrue("handshake must go through ensureListening, not bind itself",
            body.contains(
                "runCatching { ensureListening(context, attemptId, bootId, timeoutMillis) }"))
        assertTrue("the claim polls the record file",
            body.contains("private fun awaitRecord("))
        // M1: the accept is bounded, and the bound closes the descriptor.
        assertTrue("accept must be bounded", body.contains("boundedAccept("))
        assertTrue("the timeout path must close the listener so the thread cannot outlive it",
            body.substringAfter("onTimeout = {").substringBefore("}").contains("target.server.close()") &&
                body.substringAfter("onTimeout = {").substringBefore("},").contains("target.binding.close()"))
    }

    @Test
    fun `only an owned listener may be unlinked`() {
        val body = text(server)
        val handshake = body.substringAfter("fun handshake(").substringBefore("fun listen(")
        assertFalse("a claim must not unlink anything, found: " + handshake.take(160),
            handshake.contains("delete"))
        val stop = body.substringAfter("private fun stop(target: Listener)")
        assertTrue("stop() must unlink only while this process still owns the listener",
            stop.contains("if (owned)"))
        assertTrue("a stale file is only removed when no listener of ours holds the name",
            body.contains("if (socket.exists() && !socket.delete())"))
    }

    @Test
    fun `the App dialect is the one bootstrap c implements`() {
        val c = text(bootstrap)
        // Reverse connect: the App writes the hello, the worker answers with this JSON.
        assertTrue("bootstrap.c lost the reverse-connect reply the App reads",
            c.contains("\\\"boot\\\":\\\"%s\\\"") &&
                c.contains("\\\"attempt\\\":\\\"%s\\\"") &&
                c.contains("\\\"enforcing\\\":%d"))
        assertTrue("the worker must still read the App's hello line",
            c.contains("strncmp(hello, \"hello \", 6)"))
        val app = text(server)
        assertEquals("the App's record must use the worker's field names",
            true, app.contains("body.optString(\"attempt\")") &&
                app.contains("body.optString(\"boot\")") &&
                app.contains("body.optInt(\"enforcing\""))
        // And the hello it sends is the one the worker's read is waiting for.
        assertTrue("the App must write the hello the reverse path reads",
            app.contains("private val HELLO = byteArrayOf(104, 101, 108, 108, 111, 10)"))
    }

    @Test
    fun `every attestation names where its evidence came from`() {
        val body = text(server)
        assertTrue("the socket record must say ucred",
            body.contains(".put(\"source\", HookWorker.SOURCE_UCRED)"))
        assertTrue("the socket attestation must be built as ucred",
            body.contains("source = HookWorker.SOURCE_UCRED"))
        assertTrue("the daemon record must say daemon-record",
            body.contains("source = HookWorker.SOURCE_DAEMON_RECORD"))
    }
}
