package dev.maplesu.manager.runtime

import android.content.Intent
import android.os.IBinder
import com.topjohnwu.superuser.ipc.RootService

/** Bound only while SDK-backed interactive shells are in use. */
class SdkRootShellService : RootService() {
    private lateinit var tasks: RootManagementTasks

    override fun onCreate() {
        super.onCreate()
        tasks = RootManagementTasks(this, ManagerCallerVerifier(this))
    }

    override fun onBind(intent: Intent): IBinder = object : IRootShellService.Stub() {
        override fun start(argv: Array<out String>?, owner: IBinder?, globalMnt: Boolean): IRootTask =
            tasks.start(argv, owner, globalMnt)

        override fun startModule(argv: Array<out String>?, owner: IBinder?, environment: Array<out String>?): IRootTask =
            tasks.startModule(argv, owner, environment)
    }

    override fun onDestroy() {
        if (::tasks.isInitialized) tasks.close()
        super.onDestroy()
    }
}
