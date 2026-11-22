package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelAssetSource
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.ultrakernel.UltraKernelReleaseFixtures
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import java.io.File
import java.nio.file.Files
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Test

class UltraInstallCredentialHandoffTest {
    private val specBytes get() = UltraKernelReleaseFixtures.k22Bytes()
    private val assets get() = UltraKernelReleaseFixtures.combinedAssets(UltraKernelReleaseFixtures.meta())

    @Test fun exactPrivateCandidateRestoresTheSelectedAssetKeyAsUnverified() = fixture { workspace ->
        receipt(workspace)
        var recovered: String? = null
        val outcome = recover(workspace) { recovered = it; true }
        assertEquals(UltraInstallCredentialHandoff.Outcome.Recovered, outcome)
        assertTrue(UltraKernelCredential.isValid(requireNotNull(recovered)))
        assertTrue(recovered == UltraKernelSpec.parse(specBytes.toString(Charsets.UTF_8)).key)
        // This seam deliberately offers no markPaired/storeVerifiedKey port.
    }

    @Test fun oldInvalidReceiptsDoNotHideTheVerifiedCandidateKey() = fixture { workspace ->
        repeat(32) { File(workspace, "candidate-old$it.json").writeText("broken historical receipt") }
        receipt(workspace)
        var recovered: String? = null
        assertEquals(UltraInstallCredentialHandoff.Outcome.Recovered,
            recover(workspace) { recovered = it; true })
        assertEquals(UltraKernelSpec.parse(specBytes.toString(Charsets.UTF_8)).key, recovered)
        assertEquals(33, workspace.listFiles { file -> file.extension == "json" }!!.size)
    }

    @Test fun changedCandidateBytesDoNotRestoreAKey() = fixture { workspace ->
        receipt(workspace)
        File(workspace, imageName).appendText("changed")
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace))
    }

    @Test fun specDigestMismatchDoesNotRestoreAKey() = fixture { workspace ->
        receipt(workspace, specSha = "0".repeat(64))
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace))
    }

    @Test fun packagedSpecDigestIsCheckedAgain() = fixture { workspace ->
        receipt(workspace)
        val source = assets
        val changed = object : UltraKernelAssetSource {
            override fun list(directory: String) = source.list(directory)
            override fun read(path: String) = source.read(path).let {
                if (path.endsWith(UltraKernelReleaseFixtures.K22_SPEC)) it + "\n".toByteArray() else it
            }
        }
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate,
            recover(workspace, source = changed))
    }

    @Test fun absentReceiptOrImageDoesNotRestoreAKey() = fixture { workspace ->
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace))
        receipt(workspace)
        File(workspace, imageName).delete()
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace))
    }

    @Test fun existingKeyAndSuspensionArePreservedWithoutReadingAssets() = fixture { workspace ->
        val unreadable = object : UltraKernelAssetSource {
            override fun list(directory: String): List<String> = error("unexpected asset access")
            override fun read(path: String): ByteArray = error("unexpected asset access")
        }
        assertEquals(UltraInstallCredentialHandoff.Outcome.KeyPresent,
            recover(workspace, key = "existing", source = unreadable))
        assertEquals(UltraInstallCredentialHandoff.Outcome.Suspended,
            recover(workspace, suspended = true, source = unreadable))
    }

    @Test fun normalOrMissingInstallTargetNeverRestoresAnUltraKey() = fixture { workspace ->
        receipt(workspace)
        assertEquals(UltraInstallCredentialHandoff.Outcome.NotUltraInstall, recover(workspace, target = "normal"))
        assertEquals(UltraInstallCredentialHandoff.Outcome.NotUltraInstall, recover(workspace, target = null))
    }

    @Test fun failedReadbackOrGeneratedPlanIsNotTreatedAsPackagedCredential() = fixture { workspace ->
        receipt(workspace, readback = false)
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace))
        receipt(workspace, generated = true)
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace))
    }

    @Test fun invalidPackagedCredentialDoesNotBecomeAPairingRecord() = fixture { workspace ->
        val text = specBytes.toString(Charsets.UTF_8).replace(Regex("(?m)^#key=.*$"), "#key=short")
        val bytes = text.toByteArray()
        val source = UltraKernelReleaseFixtures.combinedAssets(
            UltraKernelReleaseFixtures.meta(k22Sha = UltraKernelSpec.sha256(bytes)),
            specs = mapOf(UltraKernelReleaseFixtures.K22_SPEC to bytes,
                UltraKernelReleaseFixtures.K21_SPEC to UltraKernelReleaseFixtures.k21Bytes()))
        receipt(workspace, specSha = UltraKernelSpec.sha256(bytes))
        assertEquals(UltraInstallCredentialHandoff.Outcome.NoVerifiedCandidate, recover(workspace, source = source))
    }

    @Test fun storeRechecksExistingIdentityBeforeCommitting() = fixture { workspace ->
        receipt(workspace)
        assertEquals(UltraInstallCredentialHandoff.Outcome.KeyPresent, recover(workspace) { false })
    }

    @Test fun conflictingVerifiedReceiptsDoNotSelectEitherCredential() = fixture { workspace ->
        receipt(workspace)
        val original = UltraKernelReleaseFixtures.k21Bytes()
        val changed = original.toString(Charsets.UTF_8)
            .replace(Regex("(?m)^#key=.*$"), "#key=" + "B".repeat(48)).toByteArray()
        val source = UltraKernelReleaseFixtures.combinedAssets(
            UltraKernelReleaseFixtures.meta().replace(UltraKernelSpec.sha256(original), UltraKernelSpec.sha256(changed)),
            specs = mapOf(UltraKernelReleaseFixtures.K22_SPEC to specBytes,
                UltraKernelReleaseFixtures.K21_SPEC to changed))
        receipt(workspace, id = "k21", specSha = UltraKernelSpec.sha256(changed))
        assertEquals(UltraInstallCredentialHandoff.Outcome.AmbiguousCandidate, recover(workspace, source = source))
    }

    @Test fun productionHandoffCommitsPendingIdentityWithoutMarkingItVerified() {
        val store = File("src/main/java/dev/maplesu/manager/runtime/ultra/UltraKeyPairedStore.kt").readText()
            .substringAfter("internal fun storeInstallKeyIfAbsent(")
            .substringBefore("internal fun hasPendingInstallKey(")
        assertTrue(store.contains(".remove(KEY)"))
        assertTrue(store.contains(".remove(VERIFIED_KEY)"))
        assertFalse(store.contains(".putBoolean(KEY, true)"))
        val bootstrap = File("src/main/java/dev/maplesu/manager/workmode/boot/ModeBootstrap.kt").readText()
            .substringAfter("val preparation = preparationProbeRunner.run(8_000)")
            .substringBefore("if (preparation !is")
        val recovery = bootstrap.indexOf("UltraInstallCredentialRecovery.recover")
        assertTrue(bootstrap.indexOf("beforeDetection()") in 0 until recovery)
        assertTrue(bootstrap.indexOf("UltraEnvironmentProbe.currentSnapshot(it)") in 0 until recovery)
        assertTrue(bootstrap.indexOf("if (!currentUltraConfirmed)") in 0 until recovery)
    }

    private fun recover(workspace: File, target: String? = "ultra", key: String? = null,
        suspended: Boolean = false, source: UltraKernelAssetSource = assets,
        store: (String) -> Boolean = { error("unexpected key write") }) =
        UltraInstallCredentialHandoff(source).recover(workspace, target, key, suspended, store)

    private fun receipt(workspace: File, specSha: String = UltraKernelSpec.sha256(specBytes),
        readback: Boolean = true, generated: Boolean = false, id: String = "k22") {
        val image = File(workspace, "candidate-$id-${kernelSha.take(12)}.img")
            .also { it.writeText("private candidate fixture") }
        File(workspace, "candidate-$id.json").writeText(buildJsonObject {
            put("schemaVersion", 2)
            put("operation", "ULTRA_KERNEL_GENERATE")
            put("asset", id)
            put("assetKernelRelease", UltraKernelReleaseFixtures.RELEASE)
            put("specSha256", specSha)
            put("candidateBootSha256", UltraKernelSpec.sha256(image))
            put("patchedKernelSha256", kernelSha)
            put("candidateImageBytes", image.length())
            put("readbackVerified", readback)
            if (generated) put("planOrigin", "GENERATED")
        }.toString())
    }

    private inline fun fixture(block: (File) -> Unit) {
        val workspace = Files.createTempDirectory("install-credential-").toFile()
        try { block(workspace) } finally { workspace.deleteRecursively() }
    }

    private companion object {
        val kernelSha = "a".repeat(64)
        val imageName = "candidate-k22-${kernelSha.take(12)}.img"
    }
}
