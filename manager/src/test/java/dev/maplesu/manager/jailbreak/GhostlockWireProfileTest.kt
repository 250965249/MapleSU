package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * S02 (review 2026-10-26): the product must hand the *typed wire v2 document* to
 * the native decoder, not the HOCON text. This test resolves one pinned profile
 * from the retained upstream asset tree, converts it with the vendored
 * profile-core and asserts the header `GhostlockWire` requires - and the negative
 * case where no profile exists for the release.
 */
class GhostlockWireProfileTest {
    private val assets = File("../jailbreak-providers/ghostlock/upstream/app/src/main/assets"
        + "/kernel_profiles")
    private val release = "6.6.89-android15-8-gf4dc45704e54-abogki446052083-4k"

    private fun documents(): Map<String, String> {
        val map = mutableMapOf<String, String>()
        assets.listFiles { file -> file.name.endsWith(".conf") }?.forEach {
            map[it.name] = it.readText()
        }
        return map
    }

    private fun resolver(only: List<String> = emptyList()): GhostlockProfiles {
        val documents = documents()
        val index = (if (only.isEmpty()) documents.keys.toList() else only).associate { name ->
            // The index maps release -> file; the file name minus .conf is the
            // release for the pinned set.
            name.removeSuffix(".conf") to name
        }
        val digests = documents.mapValues { (_, text) -> digest(text) }
        return GhostlockProfiles.fromIndex(index, digests,
            { path -> documents[path.removePrefix("ghostlock/")]?.toByteArray(Charsets.UTF_8) },
            "ghostlock")
    }

    private fun digest(text: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }

    @Test fun pinnedProfileResolvesToTheTypedWireDocument() {
        val profile = resolver(listOf("$release.conf")).resolve(release)
        val wire = GhostlockProfileCodec.toWire(profile, release)
        val header = ByteBuffer.wrap(wire).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals("magic", 0x0d000721, header.getInt())
        assertEquals("version", 2, header.getShort().toInt())
        header.position(6)
        header.getShort()
        header.getShort()
        val route = header.getShort().toInt()
        val length = header.getShort().toInt()
        assertTrue("route must be 1..3, was $route", route in 1..3)
        assertEquals("release length", release.length, length)
        val declared = String(wire, 16, length, Charsets.US_ASCII)
        assertEquals(release, declared)
        assertNotEquals("text and wire must differ", profile.document().size, wire.size)
        assertTrue("wire must carry sections", wire.size > 16 + release.length + 2)
    }

    @Test fun textIsNotAWireDocument() {
        val profile = resolver(listOf("$release.conf")).resolve(release)
        val error = runCatching {
            GhostlockWire(profile.document(), release, java.io.ByteArrayOutputStream())
        }.exceptionOrNull()
        assertEquals("GHOSTLOCK_PROFILE_COMPONENTS", error?.message)
    }

    @Test fun unknownReleaseHasNoProfile() {
        val error = runCatching { resolver(listOf("$release.conf")).resolve("6.6.89-not-in-set") }
            .exceptionOrNull()
        assertEquals("GHOSTLOCK_EXACT_PROFILE_MISSING:6.6.89-not-in-set", error?.message)
    }
}
