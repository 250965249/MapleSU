package com.maplesu.core.theme

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModelStore
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.screen.settings.ThemeOperations
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.After
import org.junit.Before
import org.junit.Test

/** No SDK/bootstrap: exercise the same ordered preferences operations as the media screen. */
class ThemeOperationsDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private lateinit var operations: ThemeOperations
    private val store = ViewModelStore()

    @Before fun createOperations() {
        val context = instrumentation.targetContext
        assertTrue(context.packageName.endsWith(".themetest"))
        runBlocking { ThemeRepository(context).reset() }
        instrumentation.runOnMainSync {
            operations = ThemeOperations(SavedStateHandle())
            store.put("theme-operations", operations)
        }
        await { !operations.state.value.busy }
    }

    @After fun releaseOperations() { instrumentation.runOnMainSync { store.clear() } }

    @Test fun rapidTitleEditsStayInteractiveAndKeepTheLastSelection() {
        instrumentation.runOnMainSync {
            repeat(12) { index ->
                operations.edit(mapOf("isAdvancedTitleStyleEnabled" to (index % 2 == 0),
                    "titleCustomText" to "title-$index"))
                assertFalse("A title edit disabled every control", operations.state.value.busy)
            }
        }
        await { ThemeRuntime.document(instrumentation.targetContext).optString("titleCustomText") == "title-11" }
        assertFalse(ThemeRuntime.document(instrumentation.targetContext).optBoolean("isAdvancedTitleStyleEnabled"))
        assertNull(operations.state.value.error)
    }

    @Test fun resetWaitsForAcceptedEditsAndTheyDoNotReappearAfterwards() {
        instrumentation.runOnMainSync {
            repeat(12) { operations.edit(mapOf("titleCustomText" to "title-$it")) }
            operations.reset()
            assertTrue(operations.state.value.busy)
        }
        await { !operations.state.value.busy }
        assertFalse(ThemeRuntime.document(instrumentation.targetContext).has("titleCustomText"))
        assertNull(operations.state.value.error)
    }

    private fun await(condition: () -> Boolean) {
        val deadline = android.os.SystemClock.uptimeMillis() + 10_000
        while (!condition() && android.os.SystemClock.uptimeMillis() < deadline) {
            android.os.SystemClock.sleep(10)
        }
        assertTrue("Theme operation did not settle", condition())
    }
}
