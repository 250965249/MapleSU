package dev.maplesu.manager.runtime

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Parcel
import android.os.UserManager
import android.util.Log
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ipc.RootService
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Debug discovery only. The receiver transfers the original Root endpoint, never proxies calls. */
class BinderAdmissionBrokerReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) return
        val callback = try { intent.extras?.getBinder("callback") } catch (error: Exception) {
            Log.w(TAG, "Discovery callback parcel invalid", error)
            null
        } ?: return
        val pending = goAsync()
        BinderAdmissionBroker.enqueue(context.applicationContext, callback) { pending.finish() }
    }

    companion object {
        const val ACTION = "dev.maplesu.manager.debug.BINDER_ADMISSION_DISCOVER"
        const val CALLBACK_DESCRIPTOR = "dev.maplesu.manager.binderAdmissionDiscovery"
        internal const val TAG = "MapleSUBinderAdmission"
    }
}

/** One process-local ordinary libsu connection is retained independently of the Manager UI. */
internal object BinderAdmissionBroker {
    private val worker = Executors.newSingleThreadExecutor { task ->
        Thread(task, "binder-admission-broker").apply { isDaemon = true }
    }
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var retained: Binding? = null

    private class Binding {
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
                ready.completeExceptionally(IllegalStateException("BINDER_ADMISSION_NULL_BINDING"))
            }
            override fun onBindingDied(name: ComponentName) {
                endpoint = null
                ready.completeExceptionally(IllegalStateException("BINDER_ADMISSION_BINDING_DIED"))
            }
        }
    }

    fun enqueue(context: Context, callback: IBinder, publish: ((IBinder) -> Unit)? = null, finished: () -> Unit) {
        try {
            worker.execute {
                try {
                    var endpoint: IBinder? = null
                    var failure: String? = null
                    try {
                        endpoint = resolveEndpoint(context)
                        publish?.invoke(endpoint)
                    }
                    catch (error: Exception) {
                        failure = "${error.javaClass.simpleName}: ${error.message}"
                        Log.w(BinderAdmissionBrokerReceiver.TAG, "Discovery failed: $failure", error)
                    }
                    val response = Parcel.obtain()
                    try {
                        response.writeInterfaceToken(BinderAdmissionBrokerReceiver.CALLBACK_DESCRIPTOR)
                        response.writeStrongBinder(endpoint)
                        response.writeString(failure)
                        if (!callback.transact(IBinder.FIRST_CALL_TRANSACTION, response, null, IBinder.FLAG_ONEWAY)) {
                            Log.w(BinderAdmissionBrokerReceiver.TAG, "Discovery callback transaction not handled")
                        }
                    } finally { response.recycle() }
                } catch (error: Exception) {
                    Log.w(BinderAdmissionBrokerReceiver.TAG, "Discovery callback failed", error)
                } finally { finished() }
            }
        } catch (error: Exception) {
            try { Log.w(BinderAdmissionBrokerReceiver.TAG, "Discovery worker rejected request", error) }
            finally { finished() }
        }
    }

    private fun resolveEndpoint(context: Context): IBinder {
        check(context.getSystemService(UserManager::class.java)?.isUserUnlocked == true) { "BINDER_ADMISSION_USER_LOCKED" }
        retained?.let { previous ->
            previous.endpoint?.takeIf { it.isBinderAlive }?.let { return it }
            if (!previous.established) {
                previous.launchFailure?.let { throw IllegalStateException("BINDER_ADMISSION_PRIOR_LAUNCH_FAILED", it) }
                return previous.ready.get(20, TimeUnit.SECONDS)
            }
            // This connection actually existed and died. Do not accumulate libsu connection records.
            val removed = CompletableFuture<Unit>()
            main.post {
                try { RootService.unbind(previous.connection); removed.complete(Unit) }
                catch (error: Exception) { removed.completeExceptionally(error) }
            }
            removed.get(5, TimeUnit.SECONDS)
        }
        val binding = Binding()
        retained = binding
        var stage = "internal_key_shell"
        try {
            MapleSuRuntime.openShell(context).use { shell ->
                check(shell.isRoot && shell.isAlive) { "BINDER_ADMISSION_KEY_SHELL_NOT_ROOT" }
                stage = "libsu_bind"
                val pending = CompletableFuture<Shell.Task?>()
                main.post {
                    try {
                        // No CATEGORY_DAEMON_MODE: no ServiceManager registration/discovery dependency.
                        pending.complete(RootService.bindOrTask(Intent(context, BinderAdmissionRootService::class.java),
                            context.mainExecutor, binding.connection))
                    } catch (error: Exception) { pending.completeExceptionally(error) }
                }
                pending.get(5, TimeUnit.SECONDS)?.let { task ->
                    stage = "libsu_launch_task"
                    val submitted = CompletableFuture<Unit>()
                    shell.submitTask(object : Shell.Task {
                        override fun run(stdin: java.io.OutputStream, stdout: java.io.InputStream, stderr: java.io.InputStream) {
                            try { task.run(stdin, stdout, stderr); submitted.complete(Unit) }
                            catch (error: Exception) { submitted.completeExceptionally(error) }
                        }
                        override fun shellDied() {
                            submitted.completeExceptionally(IllegalStateException("BINDER_ADMISSION_LAUNCH_SHELL_DIED"))
                        }
                    })
                    submitted.get(10, TimeUnit.SECONDS)
                }
                stage = "libsu_bind_callback"
                // Keep the authenticated launcher shell until the Root endpoint has actually arrived.
                return binding.ready.get(20, TimeUnit.SECONDS).also {
                    check(it.isBinderAlive) { "BINDER_ADMISSION_ROOT_BINDER_DEAD" }
                }
            }
        } catch (error: Exception) {
            val failed = IllegalStateException("BINDER_ADMISSION_$stage", error)
            binding.launchFailure = failed
            throw failed
        }
    }
}
