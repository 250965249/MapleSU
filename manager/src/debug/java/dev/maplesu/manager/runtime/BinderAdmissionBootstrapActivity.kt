package dev.maplesu.manager.runtime

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.Parcel
import android.os.Process
import android.util.Log
import android.widget.TextView
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ipc.RootService
import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Debug-only trusted startup without MainActivity's unrelated libsu connections. */
class BinderAdmissionBootstrapActivity : Activity() {
    private val completed = AtomicBoolean(false)
    private var competingConnection: ServiceConnection? = null
    private val callback = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION || getCallingUid() != Process.myUid()) return false
            if (!completed.compareAndSet(false, true)) return true
            try {
                data.enforceInterface(BinderAdmissionBrokerReceiver.CALLBACK_DESCRIPTOR)
                val root = requireNotNull(data.readStrongBinder()) { "Root endpoint missing" }
                check(data.readString() == null && data.dataAvail() == 0) { "Broker bootstrap failed" }
                val query = Parcel.obtain()
                val response = Parcel.obtain()
                try {
                    query.writeInterfaceToken(BinderAdmissionRootService.DESCRIPTOR)
                    check(root.transact(FIRST_CALL_TRANSACTION, query, response, 0))
                    response.readException()
                    val identity = requireNotNull(response.readTypedObject(Bundle.CREATOR))
                    check(identity.getInt("rootUid", -1) == 0 && identity.getInt("callingUid", -1) == Process.myUid())
                    val observed = JSONObject()
                    identity.keySet().forEach { observed.put(it, identity.get(it)) }
                    Log.i(BinderAdmissionBrokerReceiver.TAG, "BROKER_PREPARED $observed")
                    if (intent.getBooleanExtra("stopRoot", false)) {
                        val stop = Parcel.obtain()
                        val stopped = Parcel.obtain()
                        try {
                            stop.writeInterfaceToken(BinderAdmissionRootService.DESCRIPTOR)
                            check(root.transact(FIRST_CALL_TRANSACTION + 4, stop, stopped, 0))
                            stopped.readException()
                            Log.i(BinderAdmissionBrokerReceiver.TAG, "ROOT_STOP_ACCEPTED $observed")
                        } finally { stop.recycle(); stopped.recycle() }
                    }
                } finally { query.recycle(); response.recycle() }
            } catch (error: Exception) {
                Log.w(BinderAdmissionBrokerReceiver.TAG, "BROKER_PREPARATION_FAILED", error)
            }
            return true
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply { text = "MapleSU Binder admission preparation" })
        if (intent.getBooleanExtra("competingOrdinary", false)) prepareCompetingRoot()
        else startBroker()
    }

    private fun prepareCompetingRoot() {
        val connected = CompletableFuture<android.os.IBinder>()
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: android.os.IBinder) { connected.complete(service) }
            override fun onServiceDisconnected(name: ComponentName) = Unit
            override fun onNullBinding(name: ComponentName) { connected.completeExceptionally(IllegalStateException("COMPETING_NULL_BINDING")) }
        }
        competingConnection = connection
        val task = RootService.bindOrTask(Intent(this, BinderAdmissionCompetingRootService::class.java), mainExecutor, connection)
        Thread({
            try {
                MapleSuRuntime.openShell(applicationContext).use { shell ->
                    task?.let { pending ->
                        val submitted = CompletableFuture<Unit>()
                        shell.submitTask(object : Shell.Task {
                            override fun run(stdin: java.io.OutputStream, stdout: java.io.InputStream, stderr: java.io.InputStream) {
                                try { pending.run(stdin, stdout, stderr); submitted.complete(Unit) }
                                catch (error: Exception) { submitted.completeExceptionally(error) }
                            }
                            override fun shellDied() { submitted.completeExceptionally(IllegalStateException("COMPETING_LAUNCH_SHELL_DIED")) }
                        })
                        submitted.get(10, TimeUnit.SECONDS)
                    }
                    val root = connected.get(20, TimeUnit.SECONDS)
                    val request = Parcel.obtain()
                    val response = Parcel.obtain()
                    try {
                        request.writeInterfaceToken(BinderAdmissionCompetingRootService.DESCRIPTOR)
                        check(root.transact(Binder.FIRST_CALL_TRANSACTION, request, response, 0))
                        response.readException()
                        val identity = requireNotNull(response.readTypedObject(Bundle.CREATOR))
                        check(identity.getInt("rootUid", -1) == 0 && identity.getInt("callingUid", -1) == Process.myUid())
                        Log.i(BinderAdmissionBrokerReceiver.TAG, "COMPETING_ROOT_READY ${JSONObject().apply {
                            identity.keySet().forEach { put(it, identity.get(it)) }
                        }}")
                    } finally { request.recycle(); response.recycle() }
                    runOnUiThread { startBroker() }
                }
            } catch (error: Exception) { Log.w(BinderAdmissionBrokerReceiver.TAG, "COMPETING_ROOT_FAILED", error) }
        }, "binder-admission-competing-root").start()
    }

    private fun startBroker() {
        // A visible trusted Activity can start this ordinary Service. No broadcast timeout,
        // foreground service, notification, global service name or third-party Key transfer.
        val action = if (intent.getBooleanExtra("peekPublication", false)) BinderAdmissionBrokerService.PEEK_ACTION
            else BinderAdmissionBrokerReceiver.ACTION
        checkNotNull(startService(Intent(action)
            .setComponent(ComponentName(this, BinderAdmissionBrokerService::class.java))
            .putExtras(Bundle().apply { putBinder("callback", callback) })))
    }

    override fun onDestroy() {
        competingConnection?.let { RootService.unbind(it) }
        super.onDestroy()
    }
}
