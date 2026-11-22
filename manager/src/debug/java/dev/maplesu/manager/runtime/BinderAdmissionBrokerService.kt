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
import android.os.Parcel
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Debug admission only: compare started and bound service discovery with the receiver. */
class BinderAdmissionBrokerService : Service() {
    private var publicationConnection: ServiceConnection? = null
    private var publishedRoot: IBinder? = null
    private var publicationDeath: IBinder.DeathRecipient? = null
    private val discovery = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION || reply == null) return false
            val caller = getCallingUid()
            val peer = packageManager.getApplicationInfo("$packageName.test", 0).uid
            if (caller != applicationInfo.uid && caller != peer) throw SecurityException("BINDER_ADMISSION_CALLER")
            data.enforceInterface(BinderAdmissionBrokerReceiver.CALLBACK_DESCRIPTOR)
            val callback = requireNotNull(data.readStrongBinder())
            require(data.dataAvail() == 0) { "BINDER_ADMISSION_TRAILING_DATA" }
            // Only transfer the original Root endpoint; later Root calls retain the client's UID.
            BinderAdmissionBroker.enqueue(applicationContext, callback) { }
            reply.writeNoException()
            return true
        }
    }

    override fun onBind(intent: Intent?): IBinder? = when (intent?.action) {
        BinderAdmissionBrokerReceiver.ACTION -> discovery
        PEEK_ACTION -> BinderAdmissionDirectoryProvider.endpoint
        else -> null
    }

    private fun publishRoot(root: IBinder) {
        val ready = CompletableFuture<Unit>()
        Handler(Looper.getMainLooper()).post {
            try {
                if (publishedRoot == root && root.isBinderAlive) {
                    ready.complete(Unit)
                    return@post
                }
                clearPublication()
                check(BinderAdmissionDirectoryProvider.endpoint == root) { "BINDER_ADMISSION_DIRECTORY_NOT_PUBLISHED" }
                val connection = object : ServiceConnection {
                    override fun onServiceConnected(name: ComponentName, service: IBinder) {
                        if (service == root) ready.complete(Unit)
                        else ready.completeExceptionally(IllegalStateException("BINDER_ADMISSION_PUBLISHED_BINDER_MISMATCH"))
                    }
                    override fun onServiceDisconnected(name: ComponentName) = Unit
                    override fun onNullBinding(name: ComponentName) {
                        ready.completeExceptionally(IllegalStateException("BINDER_ADMISSION_PUBLICATION_NULL"))
                    }
                }
                // This real broker ApplicationThread owns the binding, independently of the UI.
                // AMS stores the original Root Binder; fresh clients never transact with this broker.
                check(applicationContext.bindService(Intent(PEEK_ACTION).setClass(this, javaClass),
                    connection, Context.BIND_AUTO_CREATE)) { "BINDER_ADMISSION_PUBLICATION_REJECTED" }
                publicationConnection = connection
                publishedRoot = root
                val death = IBinder.DeathRecipient {
                    Handler(Looper.getMainLooper()).post { if (publishedRoot == root) clearPublication() }
                }
                publicationDeath = death
                root.linkToDeath(death, 0)
            } catch (error: Exception) { ready.completeExceptionally(error) }
        }
        ready.get(8, TimeUnit.SECONDS)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val callback = if (intent?.action == BinderAdmissionBrokerReceiver.ACTION || intent?.action == PEEK_ACTION) {
            intent.extras?.getBinder("callback")
        } else null
        if (callback == null) stopSelfResult(startId)
        else if (intent?.action == PEEK_ACTION) {
            BinderAdmissionBroker.enqueue(applicationContext, callback, publish = ::publishRoot) { stopSelfResult(startId) }
        } else BinderAdmissionBroker.enqueue(applicationContext, callback) { stopSelfResult(startId) }
        return START_NOT_STICKY
    }

    private fun clearPublication() {
        publicationDeath?.let { death -> publishedRoot?.let { runCatching { it.unlinkToDeath(death, 0) } } }
        publicationDeath = null
        publishedRoot = null
        publicationConnection?.let { applicationContext.unbindService(it) }
        publicationConnection = null
    }

    override fun onDestroy() {
        clearPublication()
        super.onDestroy()
    }

    companion object {
        const val PEEK_ACTION = "dev.maplesu.manager.debug.BINDER_ADMISSION_PEEK"
    }
}
