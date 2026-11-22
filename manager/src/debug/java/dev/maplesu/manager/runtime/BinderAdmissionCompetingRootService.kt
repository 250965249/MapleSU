package dev.maplesu.manager.runtime

import android.content.Intent
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import com.topjohnwu.superuser.ipc.RootService

/** A real unrelated ordinary libsu binding in the UI process, for owner isolation regression. */
class BinderAdmissionCompetingRootService : RootService() {
    override fun onBind(intent: Intent): IBinder = object : Binder() {
        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            if (code != FIRST_CALL_TRANSACTION || reply == null) return false
            check(getCallingUid() == applicationInfo.uid) { "BINDER_ADMISSION_COMPETING_MANAGER_ONLY" }
            data.enforceInterface(DESCRIPTOR)
            require(data.dataAvail() == 0)
            reply.writeNoException()
            reply.writeTypedObject(Bundle().apply {
                putInt("rootPid", Process.myPid()); putInt("rootUid", Process.myUid())
                putInt("callingUid", getCallingUid())
            }, 0)
            return true
        }
    }

    companion object { const val DESCRIPTOR = "dev.maplesu.manager.binderAdmissionCompetingRoot" }
}
