package com.maplesu.core.ui.viewmodel

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Claim before launch so repeated refreshes never queue another mode wait or probe. */
internal class HomeRefreshSingleFlight {
    private val active = AtomicBoolean(false)

    fun launch(scope: CoroutineScope, block: suspend () -> Unit): Job? {
        if (!active.compareAndSet(false, true)) return null
        return scope.launch { block() }.also { job ->
            job.invokeOnCompletion { active.set(false) }
        }
    }
}
