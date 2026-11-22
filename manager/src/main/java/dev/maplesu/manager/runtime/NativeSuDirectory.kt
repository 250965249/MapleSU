package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.UserManager
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ipc.RootService
import dev.maplesu.manager.jailbreak.JailbreakLeaseStore
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.jailbreak.JailbreakRequest
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/**
 * One process-local ordinary libsu connection is retained independently of the
 * Manager UI.
 *
 * R03 (review 2026-10-26): a retained endpoint used to be returned to any caller
 * that asked for one, so an endpoint left over from normal mode or from an
 * earlier attempt could answer for a new attempt and hide its failure. The
 * connection now carries the origin it was created for, and an endpoint is only
 * reused for exactly that origin; anything else is unbound first and rebuilt from
 * the transport the caller actually asked for.
 */
internal object NativeSuDirectory {
    private val worker = Executors.newSingleThreadExecutor { task ->
        Thread(task, "maplesu-root-directory").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var retained: Binding? = null
    /** The one restricted su interface this process publishes for jailbreak mode. */
    @Volatile private var suInterface: JailbreakSuEndpoint? = null

    private fun jailbreakSu(context: Context): JailbreakSuEndpoint =
        suInterface ?: JailbreakSuEndpoint(context).also { suInterface = it }

    private class Binding(val origin: String) {
        val ready = CompletableFuture<IBinder>()
        @Volatile var endpoint: IBinder? = null
        @Volatile var established = false
        @Volatile var launchFailure: Exception? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                if (retained !== this@Binding) return
                endpoint = service
                established = true
                ready.complete(service)
            }
            override fun onServiceDisconnected(name: ComponentName) { endpoint = null }
            override fun onNullBinding(name: ComponentName) {
                ready.completeExceptionally(IllegalStateException("SU_DIRECTORY_NULL_BINDING"))
            }
            override fun onBindingDied(name: ComponentName) {
                endpoint = null
                ready.completeExceptionally(IllegalStateException("SU_DIRECTORY_BINDING_DIED"))
            }
        }
    }

    fun prepare(context: Context, request: JailbreakRequest? = null): IBinder = worker.submit<IBinder> {
        val manager = resolveEndpoint(context, request)
        /*
         * Publish what this call resolved. The previous code compared against a
         * field nothing ever assigned, so every prepare - normal mode included -
         * failed with SU_DIRECTORY_MANAGER_MISMATCH; that is why the jailbreak
         * executor answered but the attempt still reported SU_EXECUTOR_UNAVAILABLE.
         */
        NativeSuDirectoryProvider.publishManager(manager)
        if (request != null) {
            /*
             * E2: jailbreak mode has no Root-side Android service, so the restricted su
             * interface has to be published from this process (the one that owns the
             * lease). Without it the broker had nothing to hand out and every third-party
             * bind answered SU_EXECUTOR_NOT_READY.
             */
            NativeSuDirectoryProvider.publishRestrictedSu(jailbreakSu(context).asBinder())
            StageMark.mark(context, "directory:su:jailbreak")
        } else {
            /*
             * Normal mode publishes its own Root-side endpoint. A request-less call must
             * not clear a live jailbreak publication: that call is exactly how the
             * Manager reuses the current executor, and clearing here would make the
             * restricted su entry disappear while the attempt is still serving it.
             */
            val live = JailbreakStatus.read(context)
            if (live?.claimsCurrentBoot(dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId()) != true) {
                NativeSuDirectoryProvider.clearRestrictedSu()
            }
        }
        /*
         * Broker binding is discovery only (it hands third parties the endpoint we just
         * published, never this binder), so a failure here must not fail the attempt:
         * it is recorded and re-armed by the next publish.
         */
        val broker = runCatching { NativeSuBrokerService.publish(context) }
        StageMark.mark(context, "directory:published:" +
            (broker.exceptionOrNull()?.message ?: "ok"))
        manager
    }.get(if (request != null) 120 else 35, TimeUnit.SECONDS)

    /**
     * The launcher shell is the only difference between the two modes. A jailbreak
     * request consumes the authenticated provider lease of *this* attempt; it never
     * falls back to the normal-mode credential path, and normal mode never picks
     * up a lease.
     */
    private fun trustedShell(context: Context, request: JailbreakRequest?): Shell {
        if (request != null) {
            StageMark.mark(context, "directory:claim")
            StageMark.mark(context, "directory:lease-probe:" + JailbreakLeaseStore.probeTransport())
            val claimed = JailbreakLeaseStore.claimForDaemon(context, request.attemptId)
            StageMark.mark(context, "directory:claim:" + (claimed != null))
            return claimed ?: throw IllegalStateException("SU_DIRECTORY_JAILBREAK_LEASE_MISSING")
        }
        return MapleSuRuntime.openShell(context)
    }

    private fun resolveEndpoint(context: Context, request: JailbreakRequest?): IBinder {
        StageMark.mark(context, "directory:resolve:" + (request?.origin ?: "normal"))
        if (request == null) {
            /*
             * DEV-7: a live jailbreak attempt owns the product. A request-less
             * prepare must not open a normal-mode executor behind it - that both
             * masks the attempt and publishes a capability the user did not
             * choose. Reuse the attempt's endpoint, or refuse explicitly.
             */
            val live = JailbreakStatus.read(context)
            // read() preserves history; an old boot must not block normal environment recovery.
            if (live?.claimsCurrentBoot(dev.maplesu.manager.jailbreak.DirtyfragAttempt.readBootId()) == true) {
                /*
                 * Reuse this attempt's **management** binder. It is a separate object
                 * from the restricted su endpoint published for third parties, so a
                 * request-less prepare must not hand back the su interface: that is the
                 * "Binder invocation to an incorrect interface" failure (DEV-28).
                 */
                NativeSuDirectoryProvider.manager?.takeIf { it.isBinderAlive }?.let { published ->
                    StageMark.mark(context, "directory:reuse:jailbreak")
                    return published
                }
                StageMark.mark(context, "directory:refuse:jailbreak-active")
                throw IllegalStateException("SU_DIRECTORY_JAILBREAK_ACTIVE:" + live.stage)
            }
        }
        check(context.getSystemService(UserManager::class.java)?.isUserUnlocked == true) { "SU_DIRECTORY_USER_LOCKED" }
        val origin = request?.origin ?: "normal"
        retained?.let { previous ->
            val alive = previous.endpoint?.takeIf { it.isBinderAlive }
            if (alive != null && previous.origin == origin) return alive
            if (alive != null && previous.origin != origin) {
                // A live endpoint of another mode or another attempt must not
                // answer here, and it must not be reported as this attempt's
                // executor either: unbind before building the requested one.
                unbind(previous)
                retained = null
            } else if (!previous.established && previous.origin == origin) {
                previous.launchFailure?.let { throw IllegalStateException("SU_DIRECTORY_PRIOR_LAUNCH_FAILED", it) }
                return previous.ready.get(20, TimeUnit.SECONDS)
            } else {
                // This connection actually existed and died, or belongs to another
                // origin. Do not accumulate libsu connection records.
                unbind(previous)
                retained = null
            }
        }
        if (request != null) {
            /*
             * Jailbreak launcher: the lease is driven directly (DEV-10/DEV-11).
             * libsu's task layer is never used here, so this path cannot be
             * broken by it, and the executor's binder arrives over the lease's
             * stderr descriptor instead of a Service connection.
             */
            val binding = Binding(origin)
            retained = binding
            StageMark.mark(context, "directory:launch")
            val service = JailbreakLeaseLauncher.launch(context)
            val state = service.status()
            val rootUid = state.getInt("rootUid", -1)
            val rootPid = state.getInt("rootPid", -1)
            val protocol = state.getInt("protocol", -1)
            StageMark.mark(context, "directory:launch:uid=" + rootUid + " pid=" + rootPid +
                " protocol=" + protocol)
            check(rootUid == 0 && rootPid > 1 && protocol == 1) { "SU_DIRECTORY_EXECUTOR_IDENTITY" }
            // The executor exists and answered: the consumer keeps it.
            JailbreakLeaseStore.confirmHandover()
            return service.asBinder()
        }
        val binding = Binding(origin)
        retained = binding
        var stage = if (request != null) "jailbreak_lease_shell" else "internal_key_shell"
        try {
            trustedShell(context, request).use { shell ->
                check(shell.isRoot && shell.isAlive) { "SU_DIRECTORY_KEY_SHELL_NOT_ROOT" }
                /*
                 * Prove the leased shell transport before relying on it: libsu
                 * builds a Shell over the lease's process, and a shell that
                 * reports root but never answers a command turns every later
                 * stage into a silent 20 s timeout.
                 */
                stage = "launcher_probe"
                /*
                 * Prove the leased shell transport with the only primitive this
                 * libsu build exposes: a task that writes one command into the
                 * shell's stdin. The drain threads above capture the echo, so a
                 * working channel leaves a line in launcher-output.
                 */
                val probe = CompletableFuture<String>()
                try {
                    shell.submitTask(object : Shell.Task {
                        override fun run(stdin: java.io.OutputStream, stdout: java.io.InputStream,
                                         stderr: java.io.InputStream) {
                            try {
                                stdin.write("echo maplesu-ultrabe-done\n".toByteArray())
                                stdin.flush()
                                probe.complete("submitted")
                            } catch (error: Throwable) {
                                probe.completeExceptionally(error)
                            }
                        }
                        override fun shellDied() {
                            probe.completeExceptionally(IllegalStateException("SU_DIRECTORY_PROBE_SHELL_DIED"))
                        }
                    })
                    StageMark.mark(context, "directory:probe:" +
                        (runCatching { probe.get(5, TimeUnit.SECONDS) }.getOrElse {
                            "failed:" + (it.message ?: it.javaClass.simpleName)
                        }))
                } catch (error: Throwable) {
                    StageMark.mark(context, "directory:probe:threw:" +
                        (error.message ?: error.javaClass.simpleName))
                }
                stage = "libsu_bind"
                val pending = CompletableFuture<Shell.Task?>()
                main.post {
                    try {
                        // No CATEGORY_DAEMON_MODE: no ServiceManager registration/discovery dependency.
                        pending.complete(RootService.bindOrTask(Intent(context, NativeSuDaemonService::class.java),
                            context.mainExecutor, binding.connection))
                    } catch (error: Throwable) {
                        // Errors (NoClassDefFoundError from the libsu service, for
                        // example) must not escape a main-thread post: that kills
                        // the provider process instead of failing this attempt.
                        StageMark.mark(context, "directory:bind:threw:" +
                            (error.message ?: error.javaClass.simpleName))
                        pending.completeExceptionally(error)
                    }
                }
                val launch = pending.get(5, TimeUnit.SECONDS)
                StageMark.mark(context, "directory:bind:" + (launch != null))
                launch?.let { task ->
                    stage = "libsu_launch_task"
                    val submitted = CompletableFuture<Unit>()
                    shell.submitTask(object : Shell.Task {
                        override fun run(stdin: java.io.OutputStream, stdout: java.io.InputStream, stderr: java.io.InputStream) {
                            // DEV-9: the launch task never reads the shell streams, so a
                            // failing app_process was silent (and a full pipe would block
                            // it). Tee both into a bounded file before handing them over.
                            val drain = { stream: java.io.InputStream, tag: String -> Thread {
                                runCatching {
                                    val buffer = ByteArray(4096)
                                    while (true) {
                                        val read = stream.read(buffer)
                                        if (read <= 0) break
                                        StageMark.output(context, tag + ":" + String(buffer, 0, read))
                                    }
                                    StageMark.mark(context, "directory:" + tag + ":eof")
                                }
                            }.apply { isDaemon = true; start() } }
                            drain(stdout, "launcher-out")
                            drain(stderr, "launcher-err")
                            try { task.run(stdin, stdout, stderr); submitted.complete(Unit) }
                            catch (error: Exception) { submitted.completeExceptionally(error) }
                        }
                        override fun shellDied() {
                            submitted.completeExceptionally(IllegalStateException("SU_DIRECTORY_LAUNCH_SHELL_DIED"))
                        }
                    })
                    submitted.get(10, TimeUnit.SECONDS)
                }
                stage = "libsu_bind_callback"
                // Keep the authenticated launcher shell until the Root endpoint has actually arrived.
                val endpoint = binding.ready.get(20, TimeUnit.SECONDS)
                check(endpoint.isBinderAlive) { "SU_DIRECTORY_ROOT_BINDER_DEAD" }
                // S04: the executor now owns the capability. Tell the privileged
                // side before this launcher shell is closed, so the consumer keeps
                // the detached executor instead of reaping it as a cancelled run.
                if (request != null) JailbreakLeaseStore.confirmHandover()
                return endpoint
            }
        } catch (error: Exception) {
            if ((stage == "internal_key_shell" || stage == "jailbreak_lease_shell") && retained === binding)
                retained = null
            val failed = IllegalStateException("SU_DIRECTORY_$stage", error)
            binding.launchFailure = failed
            throw failed
        }
    }

    private fun unbind(previous: Binding) {
        if (!previous.established) return
        val removed = CompletableFuture<Unit>()
        main.post {
            try { RootService.unbind(previous.connection); removed.complete(Unit) }
            catch (error: Exception) { removed.completeExceptionally(error) }
        }
        runCatching { removed.get(5, TimeUnit.SECONDS) }
    }
}
