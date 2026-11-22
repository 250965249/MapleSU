package dev.maplesu.manager.runtime

import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.ParcelFileDescriptor
import android.os.Process
import com.topjohnwu.superuser.ipc.RootService

/** Debug transport and fixed-session fixture only; no production grants or policy loading. */
class BinderAdmissionRootService : RootService() {
    private var managerUid = -1
    private var peerUid = -1
    private lateinit var sessions: BinderAdmissionSessions
    private lateinit var directoryLease: BinderAdmissionDirectoryLease

    private val endpoint = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code !in FIRST_CALL_TRANSACTION..FIRST_CALL_TRANSACTION + 4 || reply == null) {
                return super.onTransact(code, data, reply, flags)
            }
            val caller = getCallingUid()
            if (caller != managerUid && caller != peerUid) throw SecurityException("BINDER_ADMISSION_CALLER")
            data.enforceInterface(DESCRIPTOR)
            val identity = clearCallingIdentity()
            try {
                if (code == FIRST_CALL_TRANSACTION + 4) {
                    check(caller == managerUid && data.dataAvail() == 0) { "BINDER_ADMISSION_STOP_MANAGER_ONLY" }
                    reply.writeNoException()
                    android.os.Handler(mainLooper).postDelayed({ stopSelf() }, 200)
                    return true
                }
                if (code == FIRST_CALL_TRANSACTION + 2) {
                    val descriptors = ArrayList<ParcelFileDescriptor>(3)
                    try {
                        val caseId = data.readInt()
                        repeat(3) { descriptors.add(requireNotNull(data.readTypedObject(ParcelFileDescriptor.CREATOR))) }
                        val owner = requireNotNull(data.readStrongBinder())
                        require(data.dataAvail() == 0) { "BINDER_ADMISSION_TRAILING_DATA" }
                        val session = sessions.start(caller, caseId, descriptors, owner)
                        reply.writeNoException()
                        reply.writeTypedObject(Bundle().apply {
                            putInt("callingUid", caller); putInt("rootUid", Process.myUid())
                            putInt("rootPid", Process.myPid()); putInt("caseId", caseId)
                        }, 0)
                        reply.writeStrongBinder(session.asBinder())
                    } finally { descriptors.forEach { runCatching { it.close() } } }
                    return true
                }
                if (code == FIRST_CALL_TRANSACTION + 3) {
                    require(data.dataAvail() == 0) { "BINDER_ADMISSION_TRAILING_DATA" }
                    reply.writeNoException()
                    reply.writeTypedObject(sessions.stats(caller), 0)
                    return true
                }
                val result = Bundle().apply {
                    putInt("rootUid", Process.myUid())
                    putInt("rootPid", Process.myPid())
                    putInt("callingUid", caller)
                    putString("rootContext", java.io.File("/proc/self/attr/current").readText().trimEnd('\u0000', '\n'))
                    putInt("directoryPid", directoryLease.directory.getInt("directoryPid"))
                }
                if (code == FIRST_CALL_TRANSACTION) {
                    try {
                        val registered = Class.forName("android.os.ServiceManager")
                            .getDeclaredMethod("checkService", String::class.java)
                            .invoke(null, "libsu-$packageName") as IBinder?
                        result.putBoolean("registryPresent", registered != null)
                        result.putBoolean("registryLocal", registered is Binder)
                        result.putString("registryDescriptor", registered?.interfaceDescriptor)
                    } catch (error: Exception) {
                        result.putString("registryFailure", error.toString())
                    }
                } else {
                    val descriptors = ArrayList<ParcelFileDescriptor>(3)
                    var stage = "receive_fd"
                    try {
                        repeat(3) { descriptors.add(requireNotNull(data.readTypedObject(ParcelFileDescriptor.CREATOR))) }
                        require(data.dataAvail() == 0) { "BINDER_ADMISSION_TRAILING_DATA" }
                        stage = "stdin_read"
                        val expected = INPUT.toByteArray(Charsets.UTF_8)
                        val received = ByteArray(expected.size)
                        ParcelFileDescriptor.AutoCloseInputStream(descriptors[0]).use { input ->
                            java.io.DataInputStream(input).readFully(received)
                        }
                        check(received.contentEquals(expected)) { "BINDER_ADMISSION_INPUT_MISMATCH" }
                        stage = "stdout_write"
                        ParcelFileDescriptor.AutoCloseOutputStream(descriptors[1]).use { it.write(received) }
                        stage = "stderr_write"
                        ParcelFileDescriptor.AutoCloseOutputStream(descriptors[2]).use { it.write(ERROR.toByteArray(Charsets.UTF_8)) }
                        result.putInt("exitCode", 37)
                        result.putBoolean("stdio", true)
                        stage = "complete"
                    } catch (error: Exception) {
                        result.putString("failure", error.toString())
                    } finally {
                        descriptors.forEach { runCatching { it.close() } }
                        result.putString("stage", stage)
                    }
                }
                reply.writeNoException()
                reply.writeTypedObject(result, 0)
            } finally { restoreCallingIdentity(identity) }
            return true
        }
    }

    override fun onCreate() {
        super.onCreate()
        check(Process.myUid() == 0) { "BINDER_ADMISSION_ROOT_REQUIRED" }
        managerUid = packageManager.getApplicationInfo(packageName, 0).uid
        peerUid = packageManager.getApplicationInfo("$packageName.test", 0).uid
        sessions = BinderAdmissionSessions(this)
        directoryLease = BinderAdmissionDirectoryLease(this, endpoint)
    }

    override fun onBind(intent: Intent): IBinder = endpoint

    override fun onDestroy() {
        sessions.close()
        directoryLease.close()
        super.onDestroy()
    }

    companion object {
        const val DESCRIPTOR = "dev.maplesu.manager.binderAdmissionRoot"
        const val INPUT = "maplesu-binder-admission\n"
        const val ERROR = "maplesu-binder-stderr\n"
    }
}
