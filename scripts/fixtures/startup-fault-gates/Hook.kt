package dev.maplesu.manager.runtime

import android.content.Context

object HookRootExecutor {
    fun production(context: Context) = this
    fun available() = false
}
