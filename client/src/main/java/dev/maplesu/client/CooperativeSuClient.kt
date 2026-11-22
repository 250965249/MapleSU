package dev.maplesu.client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.Binder
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import dev.maplesu.manager.runtime.INativeSuDiscovery
import dev.maplesu.manager.runtime.INativeSuService
import dev.maplesu.manager.runtime.INativeSuSession
import java.security.MessageDigest
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Which installed package and component provide the cooperative Root entry.
 *
 * <p>Defaults match MapleSU. An integrator normally leaves them alone; they exist
 * so the values are explicit rather than scattered string literals.
 */
data class ManagerTarget(
    val packageName: String = "dev.maplesu.manager",
    val serviceClass: String = "dev.maplesu.manager.runtime.NativeSuBrokerService",
    val action: String = "dev.maplesu.manager.action.NATIVE_SU_PEEK",
)

/**
 * Client for MapleSU's cooperative (no-credential) Root entry.
 *
 * <p>What this does: an explicit public [Context.bindService] against the exported
 * broker. A caller-checked discovery transaction returns the Root side's original
 * restricted [INativeSuService] binder; this library never sees a credential.
 *
 * <p>What this deliberately does not do: no hidden API, no reflection, no
 * `ActivityManager.peekService`, no native library, no permission. The integrating
 * app keeps its own uid; only the Root side's authorized child runs as root.
 *
 * <p>Threading: [connect] blocks while it binds and retries, so it must not run on
 * the main thread. Session calls are synchronous Binder calls and are safe from any
 * background thread.
 *
 * <p>The broker's binding is independent of Root readiness. Only an admitted caller
 * receives an endpoint. A missing endpoint is retried within the caller's deadline;
 * discovery never starts elevation or prepares an executor.
 */
class CooperativeSuClient(
    context: Context,
    private val target: ManagerTarget = ManagerTarget(),
    expectedSignerSha256: Set<String>,
) : AutoCloseable {

    private val application: Context = context.applicationContext
    private val expectedSigners: Set<String> = expectedSignerSha256.mapTo(LinkedHashSet()) { it.lowercase() }
    private val lock = Any()

    @Volatile private var bound: Bound? = null
    @Volatile private var closed = false

    private class Bound(val endpoint: INativeSuService, val connection: ServiceConnection)

    init {
        if (expectedSigners.isEmpty()) {
            throw CooperativeSuException(
                "SU_SIGNER_POLICY_EMPTY",
                "pass the SHA-256 digests of the certificates you accept for ${target.packageName}",
            )
        }
    }

    /**
     * Binds the entry, verifying the Manager's installation and signature first.
     *
     * Idempotent: a second call on a connected client returns the same instance.
     */
    @Synchronized
    fun connect(timeoutMillis: Long = DEFAULT_CONNECT_TIMEOUT_MILLIS): CooperativeSuClient {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "SU_CONNECT_ON_MAIN_THREAD: connect() blocks while it binds; call it from a worker thread"
        }
        if (closed) throw CooperativeSuException("SU_CLIENT_CLOSED")
        if (bound != null) return this
        verifyManagerInstallation()
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        var last: CooperativeSuException? = null
        while (SystemClock.elapsedRealtime() < deadline) {
            try {
                bound = bindOnce(deadline)
                return this
            } catch (failure: CooperativeSuException) {
                last = failure
                if (failure.code != "SU_EXECUTOR_NOT_READY" && failure.code != "SU_BINDING_DIED") throw failure
                // Discovery returns no endpoint until policy and executor are ready.
                // Retry within the deadline; this connection never starts elevation.
                SystemClock.sleep(RETRY_DELAY_MILLIS)
            }
        }
        throw last ?: CooperativeSuException("SU_CONNECT_TIMEOUT", "no binding within ${timeoutMillis}ms")
    }

    /** The verified restricted endpoint. */
    val service: INativeSuService
        get() {
            val current = bound ?: throw CooperativeSuException("SU_NOT_CONNECTED")
            if (!current.endpoint.asBinder().isBinderAlive) throw CooperativeSuException("SU_EXECUTOR_DIED")
            return current.endpoint
        }

    /**
     * Starts one session.
     *
     * Three pipe pairs carry stdio out of band; the request frame carries only
     * execution data. When [SuRequest.terminals] is non-zero the Root side replaces
     * the selected child descriptors with a PTY and returns its master through
     * [SuSession.openTerminal] — reading `stdout` in that case yields nothing.
     */
    fun start(request: SuRequest): SuSession {
        val endpoint = service
        val frame = request.encode()
        val stdin = ParcelFileDescriptor.createPipe()
        val stdout = ParcelFileDescriptor.createPipe()
        val stderr = ParcelFileDescriptor.createPipe()
        var remote: INativeSuSession? = null
        try {
            val owner = Binder()
            remote = try {
                // Root reads stdin from the first end and writes stdout/stderr into
                // the second ends; this process keeps the opposite ends.
                endpoint.start(frame, stdin[0], stdout[1], stderr[1], owner)
            } catch (failure: Throwable) {
                throw CooperativeSuException.normalize(failure, "SU_SESSION_START_FAILED")
            }
            val session = SuSession(
                stdin = ParcelFileDescriptor.AutoCloseOutputStream(stdin[1]),
                stdout = ParcelFileDescriptor.AutoCloseInputStream(stdout[0]),
                stderr = ParcelFileDescriptor.AutoCloseInputStream(stderr[0]),
                remote = remote,
            )
            // The Root side duplicated these into its own process during start().
            runCatching { stdin[0].close() }
            runCatching { stdout[1].close() }
            runCatching { stderr[1].close() }
            return session
        } catch (failure: Throwable) {
            // No path may leak a descriptor: close all six ends on every failure.
            listOf(stdin[0], stdin[1], stdout[0], stdout[1], stderr[0], stderr[1])
                .forEach { runCatching { it.close() } }
            runCatching { remote?.close() }
            throw if (failure is CooperativeSuException) failure
            else CooperativeSuException.normalize(failure, "SU_SESSION_START_FAILED")
        }
    }

    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            val current = bound
            bound = null
            if (current != null) runCatching { application.unbindService(current.connection) }
        }
    }

    // --- Binding ------------------------------------------------------------

    private fun bindOnce(deadline: Long): Bound {
        val settled = CompletableFuture<IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                settled.complete(service)
            }

            override fun onServiceDisconnected(name: ComponentName) {
                if (!settled.isDone) {
                    settled.completeExceptionally(CooperativeSuException("SU_SERVICE_DISCONNECTED"))
                }
            }

            override fun onNullBinding(name: ComponentName) {
                settled.completeExceptionally(CooperativeSuException("SU_EXECUTOR_NOT_READY"))
            }

            override fun onBindingDied(name: ComponentName) {
                if (!settled.isDone) settled.completeExceptionally(CooperativeSuException("SU_BINDING_DIED"))
            }
        }
        val intent = Intent(target.action)
            .setComponent(ComponentName(target.packageName, target.serviceClass))
        if (!application.bindService(intent, connection, Context.BIND_AUTO_CREATE)) {
            runCatching { application.unbindService(connection) }
            throw CooperativeSuException("SU_BIND_REJECTED")
        }
        try {
            val remaining = (deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1L)
            val binder = settled.get(remaining, TimeUnit.MILLISECONDS)
            if (!binder.isBinderAlive) throw CooperativeSuException("SU_BINDER_DEAD")
            val endpoint = INativeSuDiscovery.Stub.asInterface(binder).endpoint
                ?: throw CooperativeSuException("SU_EXECUTOR_NOT_READY")
            if (!endpoint.isBinderAlive) throw CooperativeSuException("SU_BINDER_DEAD")
            return Bound(INativeSuService.Stub.asInterface(endpoint), connection)
        } catch (failure: TimeoutException) {
            runCatching { application.unbindService(connection) }
            throw CooperativeSuException("SU_CONNECT_TIMEOUT")
        } catch (failure: ExecutionException) {
            runCatching { application.unbindService(connection) }
            throw CooperativeSuException.normalize(failure.cause ?: failure, "SU_CONNECT_FAILED")
        } catch (failure: Throwable) {
            runCatching { application.unbindService(connection) }
            throw CooperativeSuException.normalize(failure, "SU_CONNECT_FAILED")
        }
    }

    // --- Manager verification ----------------------------------------------

    /**
     * Verifies that the target package is installed, signed by an accepted
     * certificate, and that its reported uid is the real installation.
     *
     * <p>The binder arrives from AMS, which resolves a component to the package that
     * declares it, so verifying the package also pins the executing uid. The uid is
     * still confirmed through the package manager rather than assumed.
     */
    private fun verifyManagerInstallation(): Int {
        val manager = application.packageManager
        val info = try {
            manager.getPackageInfo(target.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } catch (_: PackageManager.NameNotFoundException) {
            throw CooperativeSuException("SU_MANAGER_NOT_INSTALLED", target.packageName)
        }
        val signers = info.signingInfo?.apkContentsSigners
        if (signers.isNullOrEmpty()) throw CooperativeSuException("SU_MANAGER_SIGNERS_UNAVAILABLE")
        val observed = signers.mapTo(LinkedHashSet()) { sha256Hex(it.toByteArray()) }
        if (!expectedSigners.containsAll(observed)) {
            throw CooperativeSuException("SU_MANAGER_SIGNATURE_MISMATCH", "observed=$observed")
        }
        val uid = manager.getPackageUid(target.packageName, 0)
        val owners = manager.getPackagesForUid(uid)
        if (owners == null || target.packageName !in owners) {
            throw CooperativeSuException("SU_MANAGER_UID_MISMATCH", "uid=$uid owners=${owners?.joinToString()}")
        }
        return uid
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val DEFAULT_CONNECT_TIMEOUT_MILLIS = 10_000L
        const val RETRY_DELAY_MILLIS = 250L
    }
}
