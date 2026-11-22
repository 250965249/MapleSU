package dev.maplesu.manager.runtime

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Retired discovery broadcast; no application-process execution owner is created. */
class NativeSuBootstrapReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = Unit
    companion object { const val ACTION = "dev.maplesu.manager.action.NATIVE_SU_BIND" }
}
