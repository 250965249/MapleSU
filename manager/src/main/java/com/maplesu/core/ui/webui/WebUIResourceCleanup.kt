package com.maplesu.core.ui.webui

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlin.coroutines.EmptyCoroutineContext

/** Cleanup outlives the page and never waits for IO on the UI thread. */
internal fun cleanupWebUiResources(cleanup: () -> Unit) {
    Dispatchers.IO.dispatch(EmptyCoroutineContext, Runnable {
        runCatching(cleanup).onFailure { Log.w("WebUI", "Resource cleanup failed", it) }
    })
}
