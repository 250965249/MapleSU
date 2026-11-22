package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Minimal Binder client. The caller keeps this connection alive for the lifetime of its tasks. */
class RootRequestClient private constructor(
    private val context: Context,
    private val connection: ServiceConnection,
    private val service: IRootRequestService,
) : Closeable {
    private val owner = Binder()
    private val tasks = ArrayList<Session>()

    fun start(argv: List<String>): Session = Session(service.start(argv.toTypedArray(), owner))
        .also { tasks.add(it) }

    override fun close() {
        tasks.forEach { runCatching { it.close() } }
        context.unbindService(connection)
    }

    class Session internal constructor(private val task: IRootTask) : Closeable {
        val stdin: ParcelFileDescriptor
        val stdout: ParcelFileDescriptor
        val stderr: ParcelFileDescriptor

        init {
            val opened = ArrayList<ParcelFileDescriptor>()
            try {
                stdin = task.openStdin().also { opened.add(it) }
                stdout = task.openStdout().also { opened.add(it) }
                stderr = task.openStderr().also { opened.add(it) }
            } catch (error: Exception) {
                runCatching { task.close() }
                opened.forEach { runCatching { it.close() } }
                throw error
            }
        }

        fun awaitExit(timeoutMillis: Int = 30_000): Bundle = task.awaitExit(timeoutMillis)
        fun cancel() = task.cancel()

        override fun close() {
            try { task.close() } finally {
                listOf(stdin, stdout, stderr).forEach { runCatching { it.close() } }
            }
        }
    }

    companion object {
        /** Include a package-visibility <queries><package .../></queries> entry in a third-party client. */
        fun connect(context: Context, managerPackage: String = "dev.maplesu.manager"): RootRequestClient {
            check(Looper.myLooper() != Looper.getMainLooper()) { "MAPLESU_BACKGROUND_THREAD_REQUIRED" }
            val application = context.applicationContext
            val connected = CompletableFuture<IBinder>()
            val connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, service: IBinder) { connected.complete(service) }
                override fun onServiceDisconnected(name: ComponentName) {
                    connected.completeExceptionally(IllegalStateException("MAPLESU_SERVICE_DISCONNECTED"))
                }
                override fun onNullBinding(name: ComponentName) {
                    connected.completeExceptionally(IllegalStateException("MAPLESU_SERVICE_BINDING_REJECTED"))
                }
            }
            val intent = Intent().setComponent(ComponentName(managerPackage, RootRequestService::class.java.name))
            check(application.bindService(intent, Context.BIND_AUTO_CREATE, application.mainExecutor, connection)) {
                "MAPLESU_SERVICE_UNAVAILABLE"
            }
            try {
                return RootRequestClient(application, connection,
                    IRootRequestService.Stub.asInterface(connected.get(10, TimeUnit.SECONDS)))
            } catch (error: Exception) {
                application.unbindService(connection)
                throw error
            }
        }
    }
}
