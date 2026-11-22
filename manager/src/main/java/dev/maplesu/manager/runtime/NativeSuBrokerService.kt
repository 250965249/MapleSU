package dev.maplesu.manager.runtime

import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Stable public discovery; only admitted callers receive the original restricted Binder. */
class NativeSuBrokerService : Service() {
    private val discovery = object : INativeSuDiscovery.Stub() {
        override fun getEndpoint(): IBinder? {
            val caller = Binder.getCallingUid()
            val identity = Binder.clearCallingIdentity()
            return try {
                discoverNativeSuEndpoint(caller, applicationInfo.uid,
                    eligible = { NativeSuAdmission.eligible(caller) },
                    authorized = { NativeSuAdmission.authorized(this@NativeSuBrokerService, caller) },
                    endpoint = { NativeSuDirectoryProvider.endpoint?.takeIf { it.isBinderAlive } })
            } finally { Binder.restoreCallingIdentity(identity) }
        }
    }

    override fun onBind(intent: Intent?): IBinder? =
        if (intent?.action == PEEK_ACTION) discovery else null

    companion object {
        const val PEEK_ACTION = "dev.maplesu.manager.action.NATIVE_SU_PEEK"
        private var connection: ServiceConnection? = null
        private var root: IBinder? = null
        private var death: IBinder.DeathRecipient? = null
        private var publication: CompletableFuture<Unit>? = null
        private val main = Handler(Looper.getMainLooper())

        internal fun isReady(): Boolean = root?.isBinderAlive == true && brokerPublicationReady(publication)

        /**
         * Binds the broker so AMS holds a `ServiceRecord` for it - `peekService` only
         * answers for an already-connected service.
         *
         * The public object stays the same when the Root endpoint changes. Discovery
         * authenticates each caller, then returns the original restricted interface;
         * execution is never proxied under the Manager UID.
         */
        internal fun initialize(context: Context) {
            val app = context.applicationContext
            main.post { runCatching { bindDiscovery(app) } }
        }

        internal fun publish(context: Context) {
            dev.maplesu.manager.runtime.authorization.SuperuserControl.snapshot(context)
            val done = CompletableFuture<Unit>()
            main.post {
                try {
                    val published = NativeSuDirectoryProvider.endpoint
                        ?: throw IllegalStateException("SU_DIRECTORY_NOT_PUBLISHED")
                    val binding = bindDiscovery(context)
                    if (root != published) {
                        clearRoot()
                        root = published
                        val recipient = IBinder.DeathRecipient {
                            main.post { if (root == published) clearRoot() }
                        }
                        death = recipient
                        published.linkToDeath(recipient, 0)
                    }
                    binding.whenComplete { _, error ->
                        if (error == null) done.complete(Unit) else done.completeExceptionally(error)
                    }
                } catch (error: Exception) { done.completeExceptionally(error) }
            }
            done.get(8, TimeUnit.SECONDS)
        }

        /** Main-thread only. Root death never removes this public binding. */
        private fun bindDiscovery(context: Context): CompletableFuture<Unit> {
            publication?.takeIf { !it.isCompletedExceptionally && !it.isCancelled }?.let { return it }
            connection?.let { context.unbindService(it) }
            connection = null
            val done = CompletableFuture<Unit>()
            publication = done
            val binding = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, service: IBinder) {
                    if (service.interfaceDescriptor == INativeSuDiscovery.DESCRIPTOR) done.complete(Unit)
                    else done.completeExceptionally(IllegalStateException("SU_PUBLICATION_MISMATCH"))
                }
                override fun onServiceDisconnected(name: ComponentName) {
                    done.completeExceptionally(IllegalStateException("SU_PUBLICATION_DISCONNECTED"))
                    publication = null
                    clearRoot()
                }
                override fun onNullBinding(name: ComponentName) {
                    done.completeExceptionally(IllegalStateException("SU_PUBLICATION_NULL"))
                }
                override fun onBindingDied(name: ComponentName) {
                    done.completeExceptionally(IllegalStateException("SU_PUBLICATION_DIED"))
                    publication = null
                    clearRoot()
                    initialize(context)
                }
            }
            if (!context.bindService(Intent(PEEK_ACTION).setClass(context, NativeSuBrokerService::class.java),
                    binding, Context.BIND_AUTO_CREATE)) {
                done.completeExceptionally(IllegalStateException("SU_PUBLICATION_REJECTED"))
            } else connection = binding
            return done
        }

        private fun clearRoot() {
            death?.let { recipient -> root?.let { runCatching { it.unlinkToDeath(recipient, 0) } } }
            death = null
            root = null
        }

    }
}

/** A cached binder alone does not prove that AMS acknowledged its publication. */
internal fun brokerPublicationReady(completion: CompletableFuture<Unit>?): Boolean =
    completion?.isDone == true && !completion.isCompletedExceptionally && !completion.isCancelled
