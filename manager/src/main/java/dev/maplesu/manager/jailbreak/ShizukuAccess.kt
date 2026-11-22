package dev.maplesu.manager.jailbreak

import android.content.pm.PackageManager
import rikka.shizuku.Shizuku

/** UI permission and execution-process checks use the same observed state. */
internal object ShizukuAccess {
    data class State(val running: Boolean = false, val granted: Boolean = false) {
        val ready: Boolean get() = running && granted
    }

    fun state(): State = runCatching {
        val running = Shizuku.pingBinder()
        State(running, running && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED)
    }.getOrDefault(State())

    fun requestPermission() {
        if (state().running) Shizuku.requestPermission(93260)
    }

    fun requireReady() {
        val state = state()
        if (!state.running) throw java.io.IOException("SHIZUKU_NOT_RUNNING")
        if (!state.granted) throw java.io.IOException("SHIZUKU_PERMISSION_REQUIRED")
    }
}
