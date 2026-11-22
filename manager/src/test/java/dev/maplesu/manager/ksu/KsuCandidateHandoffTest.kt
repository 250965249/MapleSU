package dev.maplesu.manager.ksu

import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Root output visibility is held until handoff; byte/form validation is the real producer. */
class KsuCandidateHandoffTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun rootPrivateCandidateIsHandedToAppBeforeItsBytesAreValidated() {
        val h = Harness()
        val result = h.producer.produceCandidate(h.source, KsuBootPatchOptions())
        assertTrue("expected root output handoff then production validation, got $result", result is KsuProduceResult.Produced)
        assertEquals(2, h.commands.size)
        assertTrue(h.commands.first().contains("boot-patch"))
        val handoff = h.commands.last()
        assertTrue(handoff.contains("/system/bin/chown 10404:10404"))
        assertTrue(handoff.contains("/system/bin/chmod 0600"))
        assertTrue(handoff.contains("/system/bin/restorecon"))
        assertTrue(handoff.contains("stat -c '%C'"))
        assertTrue(handoff.contains("\"\$C\""))
        assertFalse(handoff.contains(" -R "))
        assertFalse(Regex("(?:chown|chmod)[^\\n]*\\*").containsMatchIn(handoff))
        assertTrue(handoff.contains("! -L"))
        assertEquals(KsuInstallProducer.sha256(h.source), (result as KsuProduceResult.Produced).candidate.sourceSha256)
    }

    @Test fun handoffFailureIsSpecificAndNeverPromotesRootOnlyOutput() {
        val h = Harness(handoffCode = 74)
        val result = h.producer.produceCandidate(h.source, KsuBootPatchOptions()) as KsuProduceResult.Rejected
        assertEquals("PRODUCE_OUTPUT_HANDOFF_FAILED", result.code)
        assertTrue(result.detail.contains("code=74"))
        assertEquals(2, h.commands.size)
    }

    @Test fun ksudFailureRetainsExitAndMergedOutputWithoutHandoff() {
        val h = Harness(patchCode = 1)
        val result = h.producer.produceCandidate(h.source, KsuBootPatchOptions()) as KsuProduceResult.Rejected
        assertEquals("PRODUCE_KSud_FAILED", result.code)
        assertTrue(result.detail.contains("code=1"))
        assertTrue("RootExec merges native stderr into output", result.detail.contains("fixture-native-error"))
        assertEquals(1, h.commands.size)
    }

    @Test fun receivingAFileStillRequiresGenuineKsuCandidateForm() {
        val h = Harness(candidateBytes = KsuImageFixtures.stockImage())
        val result = h.producer.produceCandidate(h.source, KsuBootPatchOptions()) as KsuProduceResult.Rejected
        assertTrue(result.code.startsWith("PRODUCE_CANDIDATE_FORM_MISSING"))
        assertEquals(2, h.commands.size)
    }

    @Test fun completeCandidateFromFailedKsudIsStillRejectedBeforeHandoff() {
        val h = Harness(patchCode = 1, publishDuringPatch = true)
        val result = h.producer.produceCandidate(h.source, KsuBootPatchOptions()) as KsuProduceResult.Rejected
        assertEquals("PRODUCE_KSud_FAILED", result.code)
        assertEquals(1, h.commands.size)
    }

    @Test fun mismatchedSelinuxLabelNeverReturnsAProducedCandidate() {
        val h = Harness(handoffCode = 77)
        val result = h.producer.produceCandidate(h.source, KsuBootPatchOptions()) as KsuProduceResult.Rejected
        assertEquals("PRODUCE_OUTPUT_HANDOFF_FAILED", result.code)
        assertTrue(result.detail.contains("code=77"))
    }

    @Test fun productionCallersNeverReuseTheLegacyRootOwnedWorkspace() {
        var repository = File(System.getProperty("user.dir"))
        while (!File(repository, "manager/src/main/java").isDirectory) {
            repository = checkNotNull(repository.parentFile) { "repository root missing" }
        }
        val main = File(repository, "manager/src/main/java")
        val glue = File(main, "dev/maplesu/manager/ksu/KsuInstallGlue.kt").readText()
        val direct = File(main, "com/maplesu/core/ui/util/KsuCli.kt").readText()
        val switching = File(main, "dev/maplesu/manager/workmode/service/ModeSwitchRuntime.kt").readText()
        assertTrue(glue.contains("KsuCandidateWorkspaces.install(context.filesDir)"))
        assertTrue(direct.contains("KsuCandidateWorkspaces.install(ksuApp.filesDir)"))
        assertTrue(switching.contains("KsuCandidateWorkspaces.switch(input.workDir)"))
    }

    @Test fun upgradedInstallAndSwitchWorkspacesPreserveTheOldRootTree() {
        val root = temporary.newFolder()
        val legacy = File(root, "ksu/work").apply { mkdirs() }
        val oldCandidate = File(legacy, "root-owned-candidate.img").apply { writeText("legacy-preserve") }
        val oldSha = KsuInstallProducer.sha256(oldCandidate)
        val source = File(root, "source.img").apply { writeBytes(KsuImageFixtures.stockImage()) }
        val daemon = File(root, "libksud_ksu.so").apply { writeText("fixture") }
        for (work in listOf(KsuCandidateWorkspaces.install(root),
            KsuCandidateWorkspaces.switch(File(root, "switch-uuid")))) {
            assertFalse(work.toPath().startsWith(legacy.toPath()))
            val producer = KsuInstallProducer(daemon.path,
                KsuImageFixtures.FakeBootPatchRunner(KsuImageFixtures.ksuImage()), work,
                KsuCandidateCommitPort { _, _ -> error("candidate only") }, clock = { 1L })
            val result = producer.produceCandidate(source, KsuBootPatchOptions())
            assertTrue("fresh app-owned workspace must generate without touching legacy", result is KsuProduceResult.Produced)
            assertTrue((result as KsuProduceResult.Produced).candidate.candidate.toPath().startsWith(work.toPath()))
        }
        assertEquals(oldSha, KsuInstallProducer.sha256(oldCandidate))
        assertEquals(listOf(oldCandidate.name), legacy.listFiles()!!.map(File::getName))
    }

    private inner class Harness(
        patchCode: Int = 0,
        handoffCode: Int = 0,
        candidateBytes: ByteArray = KsuImageFixtures.ksuImage(),
        publishDuringPatch: Boolean = false,
    ) {
        private val root = temporary.newFolder()
        val source = File(root, "init_boot.img").apply { writeBytes(KsuImageFixtures.stockImage()) }
        private val daemon = File(root, "libksud_ksu.so").apply { writeText("fixture") }
        val commands = mutableListOf<String>()
        private var pending: File? = null
        val producer = KsuInstallProducer(daemon.path, KsuRootCommandRunner { command, _ ->
            commands += command
            if (command.contains("boot-patch")) {
                val tokens = KsuImageFixtures.splitCommandLine(command)
                val directory = File(tokens[tokens.indexOf("-o") + 1]).apply { mkdirs() }
                pending = File(directory, tokens[tokens.indexOf("--out-name") + 1])
                if (publishDuringPatch) checkNotNull(pending).writeBytes(candidateBytes)
                // The root-only artifact is deliberately not visible to the simulated app yet.
                KsuShellResult(patchCode, listOf(if (patchCode == 0) "patched" else "fixture-native-error"), emptyList())
            } else {
                if (handoffCode == 0) checkNotNull(pending).writeBytes(candidateBytes)
                KsuShellResult(handoffCode, emptyList(), emptyList())
            }
        }, File(root, "work"), KsuCandidateCommitPort { _, _ -> error("candidate-only; never commit") },
            clock = { 1L }, appUid = 10404)
    }
}
