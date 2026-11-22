package com.maplesu.core.ui.webui

import android.app.Activity
import android.webkit.WebView
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Compiled only by the isolated JVM fixture runner; never shadows Android in normal tests. */
class WebUiSessionLifecycleJvmTest {
    private var shellOpens = 0

    private fun bridge(state: WebUIState) = WebViewInterface(state, {
        shellOpens++
        error("Session regression must not open a shell")
    })

    @Test fun retirementClosesRetainedIoBeforeQueuedUiCleanup() {
        val state = WebUIState()
        val activity = Activity()
        state.webView = WebView()
        try {
            assertTrue(state.bindModuleSession(activity, "maplesu:installed"))
            val bridge = bridge(state).also { state.javascriptBridge = it }
            val held = bridge.io()

            ModuleWebUiSessions.committed("maplesu:installed")

            assertFalse("UI cleanup ran before the fixture drained it", state.isDisposed)
            assertFalse("Retained IO survived retirement", held.canOpenStream())
            assertEquals("", bridge.exec("ignored"))
            assertEquals(0, shellOpens)
            activity.drain()
            assertTrue(state.isDisposed)
        } finally {
            state.dispose(activity)
        }
    }

    @Test fun retirementBeforeBridgeRegistrationRejectsLateCapabilities() {
        val state = WebUIState()
        val activity = Activity()
        state.webView = WebView()
        try {
            assertTrue(state.bindModuleSession(activity, "maplesu:late"))
            ModuleWebUiSessions.committed("maplesu:late")
            val bridge = bridge(state).also { state.javascriptBridge = it }

            assertFalse(bridge.io().canOpenStream())
            assertEquals("", bridge.exec("ignored"))
            assertEquals(0, shellOpens)
            activity.drain()
        } finally {
            state.dispose(activity)
        }
    }

    @Test fun queuedOldTokenCleanupDoesNotDestroyTheReboundPage() {
        val state = WebUIState()
        val activity = Activity()
        state.webView = WebView()
        try {
            assertTrue(state.bindModuleSession(activity, "maplesu:old"))
            val old = bridge(state).also { state.javascriptBridge = it }
            ModuleWebUiSessions.committed("maplesu:old")
            assertFalse(old.io().canOpenStream())

            assertTrue(state.bindModuleSession(activity, "maplesu:new"))
            val fresh = bridge(state).also { state.javascriptBridge = it }
            activity.drain()

            assertFalse(state.isDisposed)
            assertTrue(fresh.io().canOpenStream())
            assertEquals(0, shellOpens)
        } finally {
            state.dispose(activity)
        }
    }

    @Test fun queuedExitDropsTheRetiredPageBeforeUiCleanup() {
        val state = WebUIState()
        val activity = Activity()
        val view = WebView().also { state.webView = it }
        state.uiEvent = WebUIEvent.WebViewReady
        try {
            assertTrue(state.bindModuleSession(activity, "maplesu:queued-exit"))
            val bridge = bridge(state).also { state.javascriptBridge = it }

            bridge.exit()
            assertEquals(WebUIEvent.WebViewReady, state.uiEvent)
            assertEquals(1, view.queued.size)
            ModuleWebUiSessions.committed("maplesu:queued-exit")
            view.drain()

            assertEquals(WebUIEvent.WebViewReady, state.uiEvent)
            assertFalse(state.isDisposed)
            assertEquals(0, shellOpens)
            activity.drain()
            assertEquals(WebUIEvent.Close, state.uiEvent)
            assertTrue(state.isDisposed)
        } finally {
            state.dispose(activity)
        }
    }

    @Test fun unrelatedModuleCommitDoesNotRetireTheCurrentPage() {
        val state = WebUIState()
        val activity = Activity()
        state.webView = WebView()
        try {
            assertTrue(state.bindModuleSession(activity, "maplesu:separate"))
            val bridge = bridge(state).also { state.javascriptBridge = it }

            ModuleWebUiSessions.committed("maplesu:unrelated")

            assertTrue(bridge.io().canOpenStream())
            assertTrue(activity.queued.isEmpty())
            assertEquals(0, shellOpens)
        } finally {
            state.dispose(activity)
        }
    }
}
