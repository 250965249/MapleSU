package com.maplesu.core.ui.screen.module

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Cancellation alone does not prevent an already-completed request from publishing late. */
internal class ModuleRequestGeneration {
    private var generation = 0L

    @Synchronized
    fun next(): Long = ++generation

    @Synchronized
    fun isCurrent(request: Long): Boolean = request == generation
}

/** Only the facts used to build the visible list; unrelated UI changes do not discard work. */
internal class ModuleListInputs<T>(
    private val modules: List<T>,
    private val displayOrder: List<T>,
    private val searchText: String,
    private val sortEnabledFirst: Boolean,
    private val sortActionFirst: Boolean,
) {
    fun matches(current: ModuleListInputs<T>): Boolean =
        modules === current.modules && displayOrder === current.displayOrder &&
            searchText == current.searchText && sortEnabledFirst == current.sortEnabledFirst &&
            sortActionFirst == current.sortActionFirst
}

/** Per-module admission is synchronous, before a coroutine can suspend or UI can recompose. */
internal class PendingModuleOperations {
    private val execution = Mutex()
    @Volatile var ids: Set<String> = emptySet()
        private set

    @Synchronized
    fun begin(id: String): Boolean {
        if (id in ids) return false
        ids = ids + id
        return true
    }

    @Synchronized
    fun finish(id: String) {
        ids = ids - id
    }

    suspend fun <T> execute(action: suspend () -> T): T = execution.withLock { action() }
}
