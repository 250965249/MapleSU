package dev.maplesu.manager.runtime

import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.test.platform.app.InstrumentationRegistry
import com.topjohnwu.superuser.ipc.RootService
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Executor

class RootServiceStartupAndroidTest {
    @Test fun cancelledLaunchCanBeRetriedAndOtherWaitersKeepTheirLaunch() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            val type = Class.forName("com.topjohnwu.superuser.internal.RootServiceManager")
            val singleton = type.getDeclaredField("mInstance").apply { isAccessible = true }
            val original = singleton.get(null)
            val fixture = type.getDeclaredConstructor().apply { isAccessible = true }.newInstance()
            singleton.set(null, fixture)
            val intent = Intent(instrumentation.targetContext, SdkRootShellService::class.java)
            fun connection() = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName, binder: IBinder) = Unit
                override fun onServiceDisconnected(name: ComponentName) = Unit
            }
            val first = connection()
            val second = connection()
            val executor = Executor { it.run() }
            try {
                assertNotNull(RootService.bindOrTask(intent, executor, first))
                assertNull(RootService.bindOrTask(intent, executor, second))
                RootService.unbind(first)
                assertNull("Another waiter still owns the launch", RootService.bindOrTask(intent, executor, first))
                RootService.unbind(first)
                RootService.unbind(second)
                assertNotNull("Last cancellation must release the startup lane", RootService.bindOrTask(intent, executor, first))
            } finally {
                RootService.unbind(first)
                RootService.unbind(second)
                singleton.set(null, original)
            }
        }
    }
}
