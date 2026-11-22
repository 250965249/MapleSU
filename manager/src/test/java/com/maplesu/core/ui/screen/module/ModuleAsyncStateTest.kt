package com.maplesu.core.ui.screen.module

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleAsyncStateTest {
    @Test
    fun onlyTheLatestRefreshCanPublishOrEndLoading() {
        val requests = ModuleRequestGeneration()
        val first = requests.next()
        val second = requests.next()
        var refreshing = true
        if (requests.isCurrent(first)) refreshing = false
        assertTrue(refreshing)
        assertFalse(requests.isCurrent(first))
        assertTrue(requests.isCurrent(second))
        if (requests.isCurrent(second)) refreshing = false
        assertFalse(refreshing)
    }

    @Test
    fun onlyTheNewestProjectionCanPublishEvenIfInputsReturnToTheOldValues() {
        val requests = ModuleRequestGeneration()
        val oldQuery = requests.next()
        requests.next()
        val repeatedQuery = requests.next()
        assertFalse(requests.isCurrent(oldQuery))
        assertTrue(requests.isCurrent(repeatedQuery))
    }

    @Test
    fun changedModuleFactsOrOrderRejectAnOldProjection() {
        val modules = listOf("module")
        val order = listOf("module")
        val snapshot = ModuleListInputs(modules, order, "", false, false)
        assertTrue(snapshot.matches(ModuleListInputs(modules, order, "", false, false)))
        assertFalse(snapshot.matches(ModuleListInputs(modules.toMutableList(), order, "", false, false)))
        assertFalse(snapshot.matches(ModuleListInputs(modules, order.toMutableList(), "", false, false)))
    }

    @Test
    fun changedQueryOrEitherSortOptionRejectsAnOldProjection() {
        val modules = listOf("module")
        val snapshot = ModuleListInputs(modules, modules, "old", false, false)
        assertFalse(snapshot.matches(ModuleListInputs(modules, modules, "new", false, false)))
        assertFalse(snapshot.matches(ModuleListInputs(modules, modules, "old", true, false)))
        assertFalse(snapshot.matches(ModuleListInputs(modules, modules, "old", false, true)))
    }

    @Test
    fun duplicateActionsForOneModuleAreRejectedBeforeTheFirstSuspension() {
        val pending = PendingModuleOperations()
        assertTrue(pending.begin("one"))
        assertFalse(pending.begin("one"))
        assertEquals(setOf("one"), pending.ids)
        assertTrue(pending.begin("two"))
        assertEquals(setOf("one", "two"), pending.ids)
    }

    @Test
    fun successFailureOrCancellationReleaseOnlyTheCompletedModule() {
        val pending = PendingModuleOperations()
        pending.begin("one")
        pending.begin("two")
        pending.finish("one")
        assertEquals(setOf("two"), pending.ids)
        assertTrue(pending.begin("one"))
        pending.finish("one")
        pending.finish("two")
        assertTrue(pending.ids.isEmpty())
    }
}
