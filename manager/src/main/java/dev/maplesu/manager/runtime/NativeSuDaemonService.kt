package dev.maplesu.manager.runtime

import android.content.Intent
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import com.topjohnwu.superuser.ipc.RootService
import dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities
import dev.maplesu.manager.runtime.authorization.RootAuthorizationStore
import java.io.File

/** Ordinary libsu execution owner. The directory, not the UI, retains its connection. */
class NativeSuDaemonService : RootService() {
    private lateinit var sessions: NativeSuBinder
    private lateinit var tasks: RootManagementTasks
    private lateinit var lease: NativeSuDirectoryLease
    private lateinit var management: IRootManagementService.Stub

    override fun onCreate() {
        super.onCreate()
        check(Process.myUid() == 0) { "SU_EXECUTOR_ROOT_REQUIRED" }
        val verifier = ManagerCallerVerifier(this)
        val policy = RootAuthorizationStore.open(applicationInfo.uid,
            File(noBackupFilesDir, "authorizations.bin").toPath(), AndroidApplicationIdentities(this))
        sessions = NativeSuBinder(this, policy)
        tasks = RootManagementTasks(this, verifier)
        management = object : IRootManagementService.Stub() {
            override fun status(): Bundle = verifier.withCallingManager {
                Bundle().apply {
                    putInt("rootUid", Process.myUid())
                    putInt("rootPid", Process.myPid())
                    putInt("managerUid", applicationInfo.uid)
                    putInt("protocol", 1)
                    putInt("activeSessions", sessions.activeCount())
                }
            }
            override fun isEnabled(): Boolean = verifier.withCallingManager { policy.isEnabled }
            override fun setEnabled(enabled: Boolean) = verifier.withCallingManager { policy.setEnabled(enabled) }
            override fun hasGrant(uid: Int): Boolean = verifier.withCallingManager { policy.hasCurrentGrant(uid) }
            override fun grant(uid: Int) = verifier.withCallingManager { policy.grant(uid) }
            override fun revoke(uid: Int) = verifier.withCallingManager { policy.revoke(uid) }
            override fun grantCount(): Int = verifier.withCallingManager { policy.currentGrantCount() }
            override fun start(argv: Array<out String>?, owner: IBinder?, globalMnt: Boolean): IRootTask = tasks.start(argv, owner, globalMnt)
        }
        lease = NativeSuDirectoryLease(this, sessions, management)
    }

    override fun onBind(intent: Intent): IBinder = management

    override fun onDestroy() {
        if (::lease.isInitialized) runCatching { lease.close() }
        if (::sessions.isInitialized) sessions.close()
        if (::tasks.isInitialized) tasks.close()
        super.onDestroy()
    }
}
