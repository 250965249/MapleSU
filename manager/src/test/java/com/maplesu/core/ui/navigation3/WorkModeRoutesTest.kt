package com.maplesu.core.ui.navigation3

import android.os.Parcelable
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** 工作模式路由契约。 */
class WorkModeRoutesTest {

    @Test
    fun workModeDestinationsAreDeclared() {
        // 不用 kotlin-reflect（unit test 运行时不带 kotlin-reflect.jar）：读源码做结构断言。
        val file = File("src/main/java/com/maplesu/core/ui/navigation3/Routes.kt")
        assumeTrue(file.isFile)
        val text = file.readText()
        assertTrue(!text.contains("data object WorkMode : Route"))
        assertTrue(text.contains("data class ModeSwitch("))
        assertTrue(text.contains("val initialTarget: dev.maplesu.manager.workmode.WorkMode? = null"))
    }

    @Test
    fun workModeIsNotReachableFromExternalIntents() {
        val file = File("src/main/java/com/maplesu/core/ui/navigation3/IntentDispatcher.kt")
        assumeTrue(file.isFile)
        val text = file.readText()
        for (internalRoute in listOf("WorkMode", "ModeSwitch", "Recovery", "Diagnosis")) {
            assertTrue("$internalRoute must not accept an external intent", !text.contains(internalRoute))
        }
    }

    @Test
    fun destinationsAreParcelable() {
        assertTrue(Parcelable::class.java.isAssignableFrom(Route.Recovery::class.java))
        assertTrue(Parcelable::class.java.isAssignableFrom(Route.Diagnosis::class.java))
        assertTrue(Parcelable::class.java.isAssignableFrom(Route.ModeSwitch::class.java))
    }

    @Test
    fun modeSwitchCarriesExactlyOneSwitchId() {
        val route = Route.ModeSwitch("sw-1")
        assertEquals("sw-1", route.switchId)
        assertEquals(Route.ModeSwitch("sw-1"), Route.ModeSwitch("sw-1"))
        assertTrue(Route.ModeSwitch("sw-1") != Route.ModeSwitch("sw-2"))
    }

    @Test
    fun destinationsRoundTripThroughSerialization() {
        val json = Json { encodeDefaults = true }
        for (route in listOf<Route>(Route.Recovery("sw-1"), Route.Diagnosis("sw-1"))) {
            assertEquals(route, json.decodeFromString(Route.serializer(), json.encodeToString(Route.serializer(), route)))
        }

        val modeSwitch = json.decodeFromString(
            Route.serializer(),
            json.encodeToString(Route.serializer(), Route.ModeSwitch("sw-1")),
        )
        assertEquals(Route.ModeSwitch("sw-1"), modeSwitch)
    }
    @Test
    fun migrationTargetAndConfirmationSurviveSavedNavigation() {
        for (mode in dev.maplesu.manager.workmode.WorkMode.entries) {
            val route = Route.Migration("migration-42", mode, true)
            val encoded = Json.encodeToString(Route.Migration.serializer(), route)
            val restored = Json.decodeFromString(Route.Migration.serializer(), encoded)
            assertEquals(route, restored)
        }
    }

    @Test
    fun newSwitchTargetSurvivesNavigationAndOldSavedRoutesRemainReadable() {
        for (mode in dev.maplesu.manager.workmode.WorkMode.entries) {
            val route = Route.ModeSwitch("switch-request", mode)
            assertEquals(route, Json.decodeFromString(Route.ModeSwitch.serializer(),
                Json.encodeToString(Route.ModeSwitch.serializer(), route)))
        }
        assertEquals(Route.ModeSwitch("old-task"), Json.decodeFromString(
            Route.ModeSwitch.serializer(), """{"switchId":"old-task"}"""))
    }

}
