package dev.maplesu.manager.t3

import org.junit.Assert.*
import org.junit.Test

class T3DeviceIdentityTest {
    @Test fun widevineIsPreferredWithoutReadingAndroidId() {
        val identity = T3DeviceIdentity.derive({ byteArrayOf(1, 2, 3) }, { error("DRM wins") })
        assertTrue(identity!!.matches(Regex("[0-9a-f]{32}")))
        assertEquals(identity, T3DeviceIdentity.derive({ byteArrayOf(1, 2, 3) }, { "other-id" }))
    }

    @Test fun unavailableOrEmptyWidevineFallsBackToStableAndroidId() {
        val identity = T3DeviceIdentity.derive({ error("DRM unavailable") }, { "android-id" })
        assertNotNull(identity)
        assertEquals(identity, T3DeviceIdentity.derive({ ByteArray(0) }, { "android-id" }))
        assertEquals(identity, T3DeviceIdentity.derive({ ByteArray(16) }, { "android-id" }))
        assertNotEquals(identity, T3DeviceIdentity.derive({ null }, { "other-android-id" }))
    }

    @Test fun absentStableSignalsDoNotCreateRandomIdentity() {
        assertNull(T3DeviceIdentity.derive({ null }, { null }))
        assertNull(T3DeviceIdentity.derive({ null }, { "   " }))
        assertNull(T3DeviceIdentity.derive({ null }, { "0000000000000000" }))
        assertNull(T3DeviceIdentity.derive({ null }, { "9774d56d682e549c" }))
    }
}
