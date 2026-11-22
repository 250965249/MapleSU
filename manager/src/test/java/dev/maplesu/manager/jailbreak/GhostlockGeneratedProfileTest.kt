package dev.maplesu.manager.jailbreak

import com.ghostlock.app.data.NativeProfileDocument
import dev.maplesu.ghostlock.extract.ExtractInput
import dev.maplesu.ghostlock.extract.ExtractionOutcome
import dev.maplesu.ghostlock.extract.GhostlockExtractionPipeline
import dev.maplesu.ghostlock.extract.SyntheticKernel
import java.io.ByteArrayOutputStream
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The generated profile must be consumable by the *production* conversion the
 * executor uses (`GhostlockProfileCodec.toWire`) and by the provider's wire
 * check (`GhostlockWire`) - not only by the extractor's own validator.
 *
 * The fixture is a synthetic kernel image (real Image header, release banner,
 * BTF blob and kallsyms table), so this exercises the reference field mapping
 * end to end: HOCON document -> typed wire v2 -> native field values.
 */
class GhostlockGeneratedProfileTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test
    fun `generated profile is accepted by the production codec field for field`() {
        val fixture = SyntheticKernel.build()
        val boot = temporary.newFile("boot.img").apply { writeBytes(fixture.bootImage) }
        val outcome = GhostlockExtractionPipeline.parse(
            ExtractInput.BootImageFile(boot),
            workDir = temporary.newFolder("work"),
        )
        val profile = (outcome as ExtractionOutcome.Generated).profiles.single()
        assertTrue("invalid: ${profile.validation.invalidFields}", profile.complete)

        // The exact converter the executor calls before starting a provider.
        val wire = GhostlockProfileCodec.toWire(profile.document, profile.release)
        val document = NativeProfileDocument.fromBinary(wire)
        assertNotNull("the typed wire document must decode", document)
        document!!

        assertEquals(SyntheticKernel.RELEASE, document.release)
        assertEquals(6u, document.kernelMajor)
        assertEquals(0u, document.recommendShizuku)
        assertEquals(2u, document.routeKind) // RouteKind.SELECT_STACK
        assertEquals(0u, document.fallbackRoute) // "none"

        assertEquals(132u, document.taskStruct.prio)
        assertEquals(140u, document.taskStruct.normalPrio)
        assertEquals(2316u, document.taskStruct.piLock)
        assertEquals(2336u, document.taskStruct.piWaiters)
        assertEquals(2280u, document.taskStruct.seccomp)

        assertEquals(136u, document.cred.copySize)
        assertEquals(48u, document.cred.capsOffset)
        assertEquals(5u, document.cred.capsCount)
        assertEquals(1u, document.cred.usageValue)
        assertEquals(ULong.MAX_VALUE, document.cred.capsValue) // -1 in the profile

        assertEquals(4096uL, document.kernelOffset.initTask)
        assertEquals(8192uL, document.kernelOffset.initCred)
        assertEquals(12288uL, document.kernelOffset.rootTaskGroup)
        assertEquals(16384uL, document.kernelOffset.selinuxEnforcing)
        assertEquals(20480uL, document.kernelOffset.selinuxBlobSizes)
        assertEquals(24576uL, document.kernelOffset.securityHookHeads)
        assertEquals(40960uL, document.kernelOffset.emptyZeroPage)
        assertEquals(36880uL, document.kernelOffset.slideLoggers01) // loggers + 0x10

        // The provider's channel check: exact release, route 1..3, v2 header.
        GhostlockWire(wire, profile.release, ByteArrayOutputStream()).writeProfile()

        // The old JVM recipe is retained for fixtures, but its cached output
        // must request parsing with the reference implementation before use.
        val store = dev.maplesu.ghostlock.extract.GhostlockProfileStore.inMemory()
        assertTrue(store.save(store.entryFor(profile)))
        assertTrue(store.confirm(profile.release))
        val decision = dev.maplesu.ghostlock.extract.GhostlockProfileGate.decide(
            profile.release, packagedSupported = false, store = store)
        assertTrue(dev.maplesu.ghostlock.extract.GhostlockProfileGate.offersParser(decision))
    }
}
