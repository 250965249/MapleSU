package dev.maplesu.manager.workmode.service

import dev.maplesu.image.BootImageInspector
import dev.maplesu.image.BootImageRebuilder
import dev.maplesu.manager.installer.KsuKernelPreservation
import dev.maplesu.manager.ksu.KsuImageFixtures
import dev.maplesu.manager.ksu.KsuRootCommandRunner
import dev.maplesu.manager.ksu.KsuShellResult
import dev.maplesu.manager.ksu.KsuTimeouts
import dev.maplesu.manager.ultrakernel.*
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.CandidateResult
import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ModeSwitchSourceRecoveryTest {
    @get:Rule val temporary = TemporaryFolder()
    private val emptyAssets = UltraKernelMemoryAssets(emptyMap())
    private var sequence = 0
    private val logs = mutableListOf<String>()

    @Test fun normalOursInitBootRebuildsOnlyTheSuppliedCopyAndPreservesFullLength() {
        val input = image(KsuImageFixtures.ksuImage(true).copyOf(16384))
        val before = input.readBytes()
        val runner = Runner("ours", KsuImageFixtures.stockImage())
        val result = recover(WorkMode.KSU, "init_boot", input, runner, true)
        assertTrue(result.detail, result.ok)
        assertNotEquals(input.canonicalFile, result.image!!.canonicalFile)
        assertEquals(16384L, result.size)
        assertEquals(0L, BootImageInspector.inspect(result.image).kernelSize)
        assertArrayEquals(KsuImageFixtures.stockImage().copyOf(16384), result.image.readBytes())
        assertArrayEquals(before, input.readBytes())
        assertEquals(ModeSwitchHashes.sha256(result.image), result.sha256)
        assertEquals(2, runner.commands.size)
        assertEquals(listOf(KsuTimeouts.COMMAND_MS, KsuTimeouts.BOOT_RESTORE_MS), runner.timeouts)
        assertEquals(listOf("boot-info", "ramdisk-state", "--boot", input.absolutePath),
            runner.commands[0].drop(1))
        assertTrue(runner.commands[1].containsAll(listOf("boot-restore", "--file-only", "--boot", input.absolutePath)))
        assertTrue(runner.commands.flatten().none { it in listOf("--flash", "-f", "--backup", "--ota", "--restore") })
        assertTrue(logs.any { "argv=" in it && "code=0" in it && "stdout=restored" in it && "stderr=" in it })
    }

    @Test fun normalCompatibleBootPreservesTheKernelAndNeedsNoBackup() {
        val input = image(boot(KsuImageFixtures.ksuRamdisk()).copyOf(24576))
        val result = recover(WorkMode.KSU, "boot", input, Runner("compatible", boot(KsuImageFixtures.stockRamdisk())), true)
        assertTrue(result.detail, result.ok)
        assertEquals(input.length(), result.size)
        assertEquals(KsuKernelPreservation.Verdict.Ok,
            KsuKernelPreservation.check("boot", input, result.image!!))
        assertTrue(result.structureEvidence.contains("compatible"))
    }

    @Test fun normalRecoveryHandsTheExactRebuiltFileToTheAppBeforeReadingIt() {
        val input = image(KsuImageFixtures.ksuImage(true).copyOf(16384))
        val before = input.readBytes()
        val runner = Runner("ours", ByteArray(5000)).apply {
            candidateOnHandoff = KsuImageFixtures.stockImage()
        }
        val result = recover(WorkMode.KSU, "init_boot", input, runner, true, appUid = 10123)
        assertTrue(result.detail, result.ok)
        assertEquals(listOf("query", "restore", "handoff"), runner.events)
        assertEquals(listOf(KsuTimeouts.COMMAND_MS, KsuTimeouts.BOOT_RESTORE_MS,
            KsuTimeouts.COMMAND_MS), runner.timeouts)
        val script = runner.handoffs.single()
        val output = runner.restoredOutput!!
        assertTrue(script.contains("F='${output.absolutePath}'"))
        assertTrue(script.contains("D='${output.parentFile.absolutePath}'"))
        assertTrue(script.contains("/system/bin/chown 10123:10123 \"\$F\""))
        assertTrue(script.contains("/system/bin/chmod 0600 \"\$F\""))
        assertTrue(script.contains("[ ! -L \"\$F\" ]"))
        assertTrue(script.contains("stat -c '%u:%g:%a'"))
        assertTrue(script.contains("stat -c '%C'"))
        assertFalse(script.contains(" -R "))
        assertArrayEquals(before, input.readBytes())
        assertArrayEquals(KsuImageFixtures.stockImage().copyOf(16384), result.image!!.readBytes())
    }

    @Test fun failedOwnershipHandoffIsReturnedBeforeAnyAppImageRead() {
        val key = "H".repeat(48)
        val runner = Runner("ours", ByteArray(5000)).apply {
            handoffCode = 75
            handoffError = "owner mismatch key=$key"
        }
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()),
            runner, true, appUid = 10123)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_OUTPUT_HANDOFF_FAILED", result.code)
        assertTrue(result.detail.contains("code=75"))
        assertTrue(result.detail.contains("stdout=handoff"))
        assertTrue(result.detail.contains("stderr=owner mismatch"))
        assertFalse(result.detail.contains(key))
        assertFalse(logs.joinToString().contains(key))
        assertEquals(listOf("query", "restore", "handoff"), runner.events)
    }

    @Test fun handoffTransportFailureRetainsTheOperationWithoutAFalseExitCode() {
        val runner = Runner("ours", ByteArray(5000)).apply {
            handoffException = IllegalStateException("handoff transport closed")
        }
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()),
            runner, true, appUid = 10123)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_OUTPUT_HANDOFF_FAILED", result.code)
        assertTrue(result.detail.contains("handoff transport closed"))
        assertTrue(result.detail.contains("chown 10123:10123"))
        assertFalse(result.detail.contains("code="))
    }

    @Test fun invalidAppIdentityDoesNotRunAnOwnershipCommand() {
        for (uid in listOf(0, -1)) {
            val runner = Runner("ours", KsuImageFixtures.stockImage())
            val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()),
                runner, true, appUid = uid)
            assertFalse(result.ok)
            assertEquals("SOURCE_RECOVERY_OUTPUT_HANDOFF_FAILED", result.code)
            assertTrue(runner.handoffs.isEmpty())
        }
    }

    @Test fun appIdentityDoesNotAddCommandsForAnUnchangedNonSource() {
        val runner = Runner("stock")
        val input = image(KsuImageFixtures.stockImage())
        val result = recover(WorkMode.KSU, "init_boot", input, runner, false, appUid = 10123)
        assertTrue(result.detail, result.ok)
        assertEquals(input, result.image)
        assertEquals(listOf("query"), runner.events)
        assertTrue(runner.handoffs.isEmpty())
    }

    @Test fun detectedKsuSourceIsRecoveredEvenWithoutAnEarlierSourceHint() {
        val input = image(KsuImageFixtures.ksuImage())
        val result = recover(WorkMode.KSU, "init_boot", input, Runner("compatible", KsuImageFixtures.stockImage()), false)
        assertTrue(result.detail, result.ok)
        assertNotEquals(input.canonicalFile, result.image!!.canonicalFile)
    }

    @Test fun stockAndForeignNonSourcesAreReturnedWithoutAnyRewrite() {
        for (state in listOf("stock", "foreign")) {
            val input = image(if (state == "stock") KsuImageFixtures.stockImage() else KsuImageFixtures.foreignImage())
            val runner = Runner(state)
            val result = recover(WorkMode.KSU, "init_boot", input, runner, false)
            assertTrue(result.ok)
            assertEquals(input, result.image)
            assertEquals(1, runner.commands.size)
        }
    }

    @Test fun stockAndForeignDoNotSilentlySatisfyAKnownSourceRecovery() {
        for (state in listOf("stock", "foreign")) {
            val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.stockImage()), Runner(state), true)
            assertFalse(result.ok)
            assertEquals("SOURCE_RECOVERY_STATE_MISMATCH", result.code)
            assertTrue(result.detail.contains(state))
        }
    }

    @Test fun validBootWithoutRamdiskIsAnUnchangedNonSourceWithoutACommand() {
        val runner = Runner("unknown")
        val input = image(boot(ByteArray(0)))
        val result = recover(WorkMode.KSU, "boot", input, runner, false)
        assertTrue(result.ok)
        assertEquals(input, result.image)
        assertTrue(runner.commands.isEmpty())
    }

    @Test fun knownSourceWithoutRamdiskRetainsTheActualUnknownResult() {
        val result = recover(WorkMode.KSU, "boot", image(boot(ByteArray(0))), Runner("unknown"), true)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_STATE_UNKNOWN", result.code)
        assertTrue(result.detail.contains("stdout=unknown"))
    }

    @Test fun unknownAndMalformedMachineOutputAreErrorsEvenForAnUnknownSource() {
        for (state in listOf("unknown", "", "- cannot parse\nunknown", "stock\nignored error")) {
            val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.stockImage()), Runner(state), false)
            assertFalse(state, result.ok)
            assertEquals("SOURCE_RECOVERY_STATE_UNKNOWN", result.code)
        }
    }

    @Test fun classificationExitCodeAndBothStreamsArePreserved() {
        val runner = Runner("ours").apply { queryCode = 37; queryError = "query failed" }
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()), runner, true)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_COMMAND_FAILED", result.code)
        assertTrue(result.detail.contains("code=37"))
        assertTrue(result.detail.contains("stdout=ours"))
        assertTrue(result.detail.contains("stderr=query failed"))
        assertEquals(1, runner.commands.size)
    }

    @Test fun restoreExitCodeArgvAndLogsAreReturnedWithSdkKeysRedacted() {
        val key = "A".repeat(48)
        val runner = Runner("ours").apply { restoreCode = 73; restoreError = "key=$key denied" }
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()), runner, true,
            daemon = File(temporary.root, "$key/ksud").absolutePath)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_COMMAND_FAILED", result.code)
        assertTrue(result.detail.contains("code=73"))
        assertTrue(result.detail.contains("stdout=restored"))
        assertTrue(result.detail.contains("<REDACTED-KEY>"))
        assertFalse(result.detail.contains(key))
        assertFalse(logs.joinToString().contains(key))
        assertEquals(2, runner.commands.size)
    }

    @Test fun transportExceptionsRetainTheirCommandAndMessageWithoutInventingAnExitCode() {
        val key = "B".repeat(48)
        val result = ModeSwitchSourceRecovery(emptyAssets, File(temporary.root, "receipts"),
            emptyList(), "/fixture/ksud", KsuRootCommandRunner { _, _ ->
                throw IllegalStateException("transport closed key=$key")
            }, logs::add).recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()),
                temporary.newFolder("transport-output"), true)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_COMMAND_FAILED", result.code)
        assertTrue(result.detail.contains("argv="))
        assertTrue(result.detail.contains("transport closed"))
        assertFalse(result.detail.contains("code="))
        assertFalse(result.detail.contains(key))
        assertTrue(logs.any { "argv=" in it && "transport closed" in it && key !in it })
    }

    @Test fun successfulExitWithoutAnOutputIsReportedAsMissing() {
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()), Runner("ours"), true)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_OUTPUT_MISSING", result.code)
    }

    @Test fun corruptRebuiltContainerIsNotPublished() {
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()), Runner("ours", ByteArray(5000)), true)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_CONTAINER_INVALID", result.code)
        assertTrue(result.detail.contains("INVALID_MAGIC"))
    }

    @Test fun rebuildingARamdiskMayNotReplaceTheBootKernel() {
        val changed = boot(KsuImageFixtures.stockRamdisk()).apply { this[4096] = 1 }
        val result = recover(WorkMode.KSU, "boot", image(boot(KsuImageFixtures.ksuRamdisk())), Runner("ours", changed), true)
        assertFalse(result.ok)
        assertEquals(KsuKernelPreservation.CODE_KERNEL_CHANGED, result.code)
    }

    @Test fun oversizedOutputIsRejectedWithoutTruncationOrInputMutation() {
        val input = image(KsuImageFixtures.ksuImage())
        val before = input.readBytes()
        val runner = Runner("ours", KsuImageFixtures.stockImage().copyOf(input.length().toInt() + 4096))
        val result = recover(WorkMode.KSU, "init_boot", input, runner, true)
        assertFalse(result.ok)
        assertEquals(ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID, result.code)
        assertArrayEquals(before, input.readBytes())
    }

    @Test fun invalidInputIsNotTreatedAsTheNoRamdiskCase() {
        val runner = Runner("stock")
        val result = recover(WorkMode.KSU, "boot", image(ByteArray(4096)), runner, false)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_CONTAINER_INVALID", result.code)
        assertTrue(result.detail.contains("INVALID_MAGIC"))
        assertTrue(runner.commands.isEmpty())
    }

    @Test fun aCommandThatMutatesItsInputDoesNotPublishARecovery() {
        val runner = Runner("ours", KsuImageFixtures.stockImage()).apply { mutateInput = true }
        val result = recover(WorkMode.KSU, "init_boot", image(KsuImageFixtures.ksuImage()), runner, true)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_INPUT_CHANGED", result.code)
    }

    @Test fun ultraUsesTheProvenOriginalBeforeExactReverseAndNeverCallsKsud() {
        val fixture = ultra()
        val runner = Runner("ours")
        val before = fixture.candidate.readBytes()
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, runner, true,
            fixture.assets, listOf(fixture.original), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertEquals(ModeSwitchHashes.sha256(fixture.original), result.sha256)
        assertTrue(result.structureEvidence.contains("LOCAL_PREIMAGE"))
        assertArrayEquals(before, fixture.candidate.readBytes())
        assertTrue(runner.commands.isEmpty())
    }

    @Test fun ultraUsesReceiptProvenRecoveryWithoutAnOriginalImage() {
        val fixture = ultra()
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, Runner("ours"), true,
            fixture.assets, emptyList(), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertEquals(ModeSwitchHashes.sha256(fixture.original), result.sha256)
        assertTrue(result.structureEvidence.contains("EXACT_SPEC_REVERSE"))
    }

    @Test fun ultraFullPartitionSnapshotProducesAFullLengthReceiptProvenBase() {
        val fixture = ultra(65536)
        val before = fixture.candidate.readBytes()
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, Runner("ours"), true,
            fixture.assets, emptyList(), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertEquals(65536L, result.size)
        assertEquals(fixture.candidate.length(), result.image!!.length())
        assertEquals(ModeSwitchHashes.sha256(fixture.original), result.sha256)
        assertArrayEquals(before, fixture.candidate.readBytes())
    }

    @Test fun ultraGeneratedSourceRecoversWithoutCatalogueReceiptOrBackup() {
        val fixture = generatedUltra()
        val before = fixture.candidate.readBytes()
        val runner = Runner("ours")
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, runner, true,
            emptyAssets, emptyList(), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertTrue(result.structureEvidence.contains("IMAGE_BOUND_KERNEL_REVERSE"))
        assertEquals(fixture.candidate.length(), result.size)
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.original), UltraKernelPlan.readKernel(result.image!!))
        assertNull(BootImageRebuilder.readRecoveryRecord(result.image))
        assertArrayEquals(before, fixture.candidate.readBytes())
        assertTrue(runner.commands.isEmpty())
    }

    @Test fun ultraGeneratedSourceIsDetectedWithoutAnEarlierSourceHint() {
        val fixture = generatedUltra()
        File(fixture.receipts, "candidate-generated-broken.json").writeText("{")
        File(fixture.receipts, "candidate-generated-broken.spec").writeText("broken")
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, Runner("ours"), false,
            emptyAssets, emptyList(), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertTrue(result.structureEvidence.contains("IMAGE_BOUND_KERNEL_REVERSE"))
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.original), UltraKernelPlan.readKernel(result.image!!))
    }

    @Test fun ultraGeneratedRecoveryPreservesChangesOutsideItsOwnRanges() {
        val fixture = generatedUltra()
        val bytes = fixture.candidate.readBytes().apply {
            this[44] = 'x'.code.toByte()
            this[4096 + 4095] = 22
        }
        fixture.candidate.writeBytes(bytes)
        val expected = UltraKernelPlan.readKernel(fixture.original).apply { this[4095] = 22 }
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, Runner("ours"), true,
            emptyAssets, emptyList(), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertArrayEquals(expected, UltraKernelPlan.readKernel(result.image!!))
        assertEquals('x'.code.toByte(), result.image.readBytes()[44])
        assertArrayEquals(bytes, fixture.candidate.readBytes())
    }

    @Test fun ultraGeneratedRangeDamageReturnsTheActualFailureWithoutPublishingAnImage() {
        val fixture = generatedUltra()
        val bytes = fixture.candidate.readBytes().apply {
            this[4096 + 1024] = (this[4096 + 1024].toInt() xor 1).toByte()
        }
        fixture.candidate.writeBytes(bytes)
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, Runner("ours"), true,
            emptyAssets, emptyList(), fixture.receipts)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_FAILED", result.code)
        assertTrue(result.detail.contains("ULTRA_KERNEL_RECOVERY_CURRENT_MISMATCH"))
        assertNull(result.image)
        assertArrayEquals(bytes, fixture.candidate.readBytes())
    }

    @Test fun ultraGeneratedRecordDamageReturnsTheActualFailureWithoutUsingTheInputAsARecovery() {
        val fixture = generatedUltra()
        val record = requireNotNull(BootImageRebuilder.readRecoveryRecord(fixture.candidate)).apply {
            this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
        }
        val component = temporary.newFile("record-component.img").apply {
            writeBytes(UltraKernelPlan.readKernel(fixture.candidate))
        }
        val malformed = temporary.newFile("damaged-record.img").apply { delete() }
        BootImageRebuilder.rebuild(fixture.candidate, component, malformed, record)
        val before = malformed.readBytes()
        val result = recover(WorkMode.LITE, "boot", malformed, Runner("ours"), false,
            emptyAssets, emptyList(), fixture.receipts)
        assertFalse(result.ok)
        assertEquals("SOURCE_RECOVERY_FAILED", result.code)
        assertTrue(result.detail.contains("ULTRA_KERNEL_RECOVERY_CHECKSUM"))
        assertNull(result.image)
        assertArrayEquals(before, malformed.readBytes())
    }

    @Test fun ultraGeneratedSourceStillUsesAProvenOriginalBeforeItsEmbeddedInverse() {
        val fixture = generatedUltra(keepReceipts = true)
        val result = recover(WorkMode.LITE, "boot", fixture.candidate, Runner("ours"), true,
            emptyAssets, listOf(fixture.original), fixture.receipts)
        assertTrue(result.detail, result.ok)
        assertTrue(result.structureEvidence.contains("LOCAL_PREIMAGE"))
        assertArrayEquals(UltraKernelPlan.readKernel(fixture.original), UltraKernelPlan.readKernel(result.image!!))
    }

    @Test fun ultraKnownSourceNeedsRecoveryEvidenceButUnknownSourceIsPreserved() {
        val input = image(boot(ByteArray(0)))
        val known = recover(WorkMode.LITE, "boot", input, Runner("ours"), true)
        assertFalse(known.ok)
        assertEquals("SOURCE_RECOVERY_UNAVAILABLE", known.code)
        val unknown = recover(WorkMode.LITE, "boot", input, Runner("ours"), false)
        assertTrue(unknown.ok)
        assertEquals(input, unknown.image)
    }

    @Test fun stockInitBootIsNotMisrepresentedAsAnOwnedSourceCarrier() {
        val input = image(KsuImageFixtures.stockImage())
        val known = recover(WorkMode.LITE, "init_boot", input, Runner("ours"), true)
        assertFalse(known.ok)
        assertEquals("SOURCE_RECOVERY_UNAVAILABLE", known.code)
        val unknown = recover(WorkMode.LITE, "init_boot", input, Runner("ours"), false)
        assertTrue(unknown.ok)
        assertEquals(input, unknown.image)
    }

    private fun recover(from: WorkMode, partition: String, input: File, runner: Runner, known: Boolean,
        assets: UltraKernelAssetSource = emptyAssets, originals: List<File> = emptyList(),
        receipts: File = File(temporary.root, "no-receipts"), daemon: String = "/fixture/ksud",
        appUid: Int? = null): CandidateResult =
        ModeSwitchSourceRecovery(assets, receipts, originals, daemon, runner, logs::add, appUid)
            .recover(from, partition, input, temporary.newFolder("output-${sequence++}"), known)

    private fun image(bytes: ByteArray): File = temporary.newFile("input-${sequence++}.img").apply { writeBytes(bytes) }

    private class Runner(val state: String, val candidate: ByteArray? = null) : KsuRootCommandRunner {
        val commands = mutableListOf<List<String>>()
        val timeouts = mutableListOf<Long>()
        val handoffs = mutableListOf<String>()
        val events = mutableListOf<String>()
        var queryCode = 0
        var queryError = ""
        var restoreCode = 0
        var restoreError = ""
        var mutateInput = false
        var handoffCode = 0
        var handoffError = ""
        var handoffException: Exception? = null
        var candidateOnHandoff: ByteArray? = null
        var restoredOutput: File? = null
        override fun run(commandLine: String, timeoutMs: Long): KsuShellResult {
            timeouts += timeoutMs
            if (commandLine.startsWith("D=")) {
                handoffs += commandLine
                events += "handoff"
                handoffException?.let { throw it }
                if (handoffCode == 0) candidateOnHandoff?.let { restoredOutput!!.writeBytes(it) }
                return KsuShellResult(handoffCode, listOf("handoff"), listOf(handoffError))
            }
            val argv = KsuImageFixtures.splitCommandLine(commandLine)
            commands += argv
            if (argv[1] == "boot-info") {
                events += "query"
                return KsuShellResult(queryCode, state.lines(), listOf(queryError))
            }
            require(argv[1] == "boot-restore" && "--file-only" in argv)
            events += "restore"
            if (restoreCode == 0 && candidate != null) {
                val output = File(argv[argv.indexOf("-o") + 1], argv[argv.indexOf("--out-name") + 1])
                output.writeBytes(candidate)
                restoredOutput = output
            }
            if (mutateInput) File(argv[argv.indexOf("--boot") + 1]).appendBytes(byteArrayOf(1))
            return KsuShellResult(restoreCode, listOf("restored"), listOf(restoreError))
        }
    }

    private fun boot(ramdisk: ByteArray, kernel: ByteArray = ByteArray(8192)): ByteArray {
        val ramdiskStart = 4096 + kernel.size
        val end = (ramdiskStart + ramdisk.size + 4095) / 4096 * 4096
        return ByteArray(end).apply {
            ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).apply {
                put("ANDROID!".toByteArray()); putInt(8, kernel.size); putInt(12, ramdisk.size)
                putInt(20, 1584); putInt(40, 4)
            }
            kernel.copyInto(this, 4096); ramdisk.copyInto(this, ramdiskStart)
        }
    }

    private data class Ultra(val assets: UltraKernelAssetSource, val original: File, val candidate: File, val receipts: File)

    private fun generatedUltra(keepReceipts: Boolean = false): Ultra {
        val release = "6.6.89-android15-source-recovery-fixture"
        val raw = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
        }
        val original = image(boot(ByteArray(0), raw))
        val credential = UltraKernelCredential.of("Ab1".repeat(16))
        val plan = UltraKernelPlan.fromRecords(release,
            listOf(UltraKernelPlan.PatchRecord("fixture", 1024, ByteArray(48), credential.copySecret()),
                UltraKernelPlan.PatchRecord("path", 2048, ByteArray(UltraKernelCredential.INIT_PATH_FIELD),
                    credential.initPathField(UltraKernelCredential.INIT_PATH_FIELD))),
            credential, baseKernelSha256 = UltraKernelSpec.sha256(raw))
            .let { it.withDerived(it.apply(raw).derived) }
        val text = plan.specText(plan.credential)
        val asset = UltraKernelGeneratedAsset.of(plan, original.length(), 0, text)
        val receipts = temporary.newFolder("generated-receipts-${sequence++}")
        val candidate = UltraKernelBuilder(receipts).generate(original, asset, UltraKernelSpec.parse(text)).image
        if (!keepReceipts) receipts.listFiles().orEmpty().filter { it != candidate }.forEach { it.deleteRecursively() }
        return Ultra(emptyAssets, original, candidate, receipts)
    }

    private fun ultra(partitionSize: Int? = null): Ultra {
        val release = "6.6.89-android15-source-recovery-fixture"
        val kernel = ByteArray(8192).apply {
            "ARMd".toByteArray().copyInto(this, 56)
            "Linux version $release (fixture)".toByteArray().copyInto(this, 128)
        }
        val specBytes = "#kernel=$release\n1024|00|01".toByteArray()
        val spec = UltraKernelSpec.parse(specBytes.toString(Charsets.UTF_8))
        val meta = buildJsonObject {
            put("schema", 1); put("kernelRelease", release); put("id", "fixture"); put("spec", "fixture.spec")
            put("specSha256", UltraKernelSpec.sha256(specBytes)); put("patchCount", 1)
            put("baseKernelSha256", UltraKernelSpec.sha256(kernel))
            put("expectedKernelSha256", UltraKernelSpec.sha256(spec.apply(kernel).kernel))
            put("expectedImageSize", 16384); put("verification", "experimental"); put("source", "model")
        }.toString().toByteArray()
        val assets = UltraKernelMemoryAssets(mapOf(
            "ultra-kernels/releases/$release/meta.json" to meta,
            "ultra-kernels/releases/$release/fixture.spec" to specBytes,
        ))
        val bytes = boot(ByteArray(0), kernel)
        val original = image(if (partitionSize == null) bytes else bytes.copyOf(partitionSize))
        val receipts = temporary.newFolder("receipts-${sequence++}")
        val asset = UltraKernelReleaseCatalog.load(assets).assetsFor(release).single()
        val built = UltraKernelBuilder(receipts).generate(original, asset, spec).image
        val candidate = if (partitionSize == null) built else image(built.readBytes().copyOf(partitionSize))
        return Ultra(assets, original, candidate, receipts)
    }
}
