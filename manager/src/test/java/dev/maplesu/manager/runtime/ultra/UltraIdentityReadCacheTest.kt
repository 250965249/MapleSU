package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.*
import org.junit.Test

class UltraIdentityReadCacheTest {
    private fun identity(source: Source) = InstalledIdentity(
        "a".repeat(64), "/data/example/init", 100,
        "maplesu-ultra-build", "boot", source,
    )

    @Test fun fallbackIdentityIsReturnedButNextReadRetriesTheDevice() {
        for (source in listOf(Source.Persisted, Source.Unknown)) {
            val cache = UltraIdentityReadCache({ 0L }, 60_000L)
            val fallback = identity(source)
            val live = identity(Source.Readback)
            var calls = 0
            assertEquals(fallback, cache.read("key", "boot") { calls++; fallback })
            assertEquals(live, cache.read("key", "boot") { calls++; live })
            assertEquals(live, cache.read("key", "boot") { calls++; error("readback should be cached") })
            assertEquals(2, calls)
        }
    }

    @Test fun forcedReadFailureDiscardsThePreviousLiveObservation() {
        for (source in listOf(Source.Persisted, Source.Unknown)) {
            val cache = UltraIdentityReadCache({ 0L }, 60_000L)
            val live = identity(Source.Readback)
            val fallback = identity(source)
            var calls = 0
            cache.read("key", "boot") { calls++; live }
            assertEquals(fallback, cache.read("key", "boot", force = true) { calls++; fallback })
            assertEquals(live, cache.read("key", "boot") { calls++; live })
            assertEquals(3, calls)
        }
    }
}
