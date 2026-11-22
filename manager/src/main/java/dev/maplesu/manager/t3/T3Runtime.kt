package dev.maplesu.manager.t3

import android.content.Context
import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.launch

/** Process-owned network session; only visible manager Activities keep its heartbeat running. */
internal class T3Runtime private constructor(context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    @Volatile private var coreSnapshot = ""
    private val client = T3AccountClient(
        transport = T3SdkTransport(),
        store = T3AndroidAccountStore(context),
        identityProvider = { T3DeviceIdentity.resolve(context) },
        coreProvider = { coreSnapshot },
    )
    private val controller = T3ForegroundController(scope, client)
    private val foregroundOwners = mutableSetOf<Any>()
    private val attachedOwners = mutableSetOf<Any>()
    private val countdown = T3DisableCountdown(SystemClock::elapsedRealtime)
    private val mutableSecondsRemaining = MutableStateFlow<Int?>(null)
    val secondsRemaining = mutableSecondsRemaining.asStateFlow()
    val notice = controller.notice

    init {
        scope.launch {
            controller.disabledMessage.filterNotNull().collect {
                countdown.confirm()
                controller.stop()
                do {
                    val seconds = countdown.remainingSeconds()!!
                    mutableSecondsRemaining.value = seconds
                    if (seconds == 0) break
                    delay(100L)
                } while (true)
            }
        }
    }

    fun foreground(owner: Any) {
        foregroundOwners.add(owner)
        if (secondsRemaining.value == null) controller.start()
    }

    fun attach(owner: Any) {
        attachedOwners.add(owner)
    }

    fun destroy(owner: Any, finishing: Boolean) {
        background(owner)
        attachedOwners.remove(owner)
        // A fresh launch can revalidate after the server re-enables the program.
        // Normal backgrounding and configuration changes keep the same deadline.
        if (finishing && attachedOwners.isEmpty() && secondsRemaining.value == 0) {
            scope.cancel()
            synchronized(Companion) {
                if (instance === this) instance = null
            }
        }
    }

    fun background(owner: Any) {
        foregroundOwners.remove(owner)
        if (foregroundOwners.isEmpty()) controller.stop()
    }

    fun updateCoreSnapshot(working: Boolean, kernelVersion: String, model: String) {
        coreSnapshot = if (working && kernelVersion.isNotBlank()) "$kernelVersion $model".trim() else ""
    }

    companion object {
        private var instance: T3Runtime? = null

        @Synchronized
        fun get(context: Context): T3Runtime = instance ?: T3Runtime(context.applicationContext).also {
            instance = it
        }
    }
}
