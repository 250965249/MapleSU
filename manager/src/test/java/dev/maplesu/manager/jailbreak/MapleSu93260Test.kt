package dev.maplesu.manager.jailbreak

import dev.maplesu.manager.runtime.hookPrepareBudgetMillis
import me.yuki.fina.adbroot.core.KernelMap
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class MapleSu93260Test {
    private val request = JailbreakRequest("maplesu_93260", "attempt-a", "boot-a",
        softReboot = false, rootBackend = JailbreakRequest.BACKEND_KSU)

    private fun source() = JSONObject().apply {
        put("schema", "maplesu.93260.source.v1")
        put("provider", request.method)
        put("attempt", request.attemptId)
        put("bootId", request.bootId)
        put("exitCode", 0)
        put("enforcingBefore", 1)
        put("enforcingFinal", 1)
    }

    @Test fun sourceRequiresBoundRestorationAndSuccessfulHandover() {
        assertNull(MapleSu93260Attempt.sourceRefusal(source().toString(), request, 1))
        for (key in listOf("schema", "provider", "attempt", "bootId")) {
            assertEquals("MAPLESU_93260_SOURCE_BINDING_MISMATCH",
                MapleSu93260Attempt.sourceRefusal(source().put(key, "other").toString(), request, 1))
        }
        for (key in listOf("enforcingBefore", "enforcingFinal")) {
            assertEquals("MAPLESU_93260_RESTORE_FAILED",
                MapleSu93260Attempt.sourceRefusal(source().put(key, 0).toString(), request, 1))
        }
        assertEquals("MAPLESU_93260_HANDOVER_FAILED:65",
            MapleSu93260Attempt.sourceRefusal(source().put("exitCode", 65).toString(), request, 1))
        assertEquals("MAPLESU_93260_SOURCE_EVIDENCE_INVALID",
            MapleSu93260Attempt.sourceRefusal("{}", request, 1))
    }

    @Test fun successfulNormalHandoverEndsEnforcingFromPermissiveEntry() {
        val receipt = source().put("enforcingBefore", 0).put("enforcingFinal", 0)
        assertEquals("MAPLESU_93260_RESTORE_FAILED",
            MapleSu93260Attempt.sourceRefusal(receipt.toString(), request, 0))
        assertNull(MapleSu93260Attempt.sourceRefusal(receipt.put("enforcingFinal", 1).toString(), request, 0))
    }

    @Test fun failedNormalAndUltraHandoverPreservePermissiveEntry() {
        val receipt = source().put("enforcingBefore", 0).put("enforcingFinal", 0)
        assertEquals("MAPLESU_93260_HANDOVER_FAILED:65", MapleSu93260Attempt.sourceRefusal(
            receipt.put("exitCode", 65).toString(), request, 0))
        assertNull(MapleSu93260Attempt.sourceRefusal(receipt.put("exitCode", 0).toString(),
            request.copy(rootBackend = JailbreakRequest.BACKEND_HOOK), 0))
    }

    @Test fun productionRestoreTailVerifiesNormalSuccessAndFailureTargets() {
        val directory = Files.createTempDirectory("normal-selinux-tail-").toFile()
        val bash = if (System.getProperty("os.name")?.startsWith("Windows") == true)
            "C:/Program Files/Git/bin/bash.exe" else "/bin/bash"
        try {
            for (backend in listOf(JailbreakRequest.BACKEND_KSU, JailbreakRequest.BACKEND_HOOK)) {
                for (entry in listOf(0, 1)) {
                    for (code in listOf(0, 65)) {
                        val current = request.copy(rootBackend = backend)
                        val batch = MapleSu93260Attempt.batch(directory, current, File(directory, "receipt"), entry)
                        val finish = batch.substringAfter("finish() {").substringBefore("trap finish EXIT")
                        File(directory, "fixture.sh").writeText("""
                            ENTRY=$entry
                            WINDOW=1
                            RECEIPT_OPEN=1
                            DISPATCHER=0
                            kill() { :; }
                            exec 8>enforce 9<enforce 7>receipt
                            finish() { $finish
                            trap finish EXIT
                            exit $code
                        """.trimIndent())
                        val process = ProcessBuilder(bash, "fixture.sh").directory(directory)
                            .redirectErrorStream(true).start()
                        assertTrue("restore tail timed out", process.waitFor(5, TimeUnit.SECONDS))
                        assertEquals(process.inputStream.bufferedReader().readText(), code, process.exitValue())
                        val receipt = JSONObject(File(directory, "receipt").readText())
                        val expected = if (backend == JailbreakRequest.BACKEND_KSU && code == 0) 1 else entry
                        assertEquals(expected, receipt.getInt("enforcingFinal"))
                        assertEquals(expected.toString(), File(directory, "enforce").readText().trim())
                    }
                }
            }
        } finally { directory.deleteRecursively() }
    }

    @Test fun partialSourceReceiptWaitsAndReportsItsCompletion() {
        val file = Files.createTempFile("source-receipt-", ".json").toFile()
        try {
            file.writeText("{\"schema\":")
            val messages = mutableListOf<String>()
            MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                timeoutMillis = 2000) { message ->
                messages += message
                if (messages.size == 1) file.writeText(source().toString())
            }
            assertTrue(messages.first().contains("等待来源收尾回执"))
            assertTrue(messages.last().contains("来源收尾回执已收到"))
        } finally { file.delete() }
    }

    @Test fun emptySourceReceiptTimesOutWithVisibleProgress() {
        val file = Files.createTempFile("source-receipt-", ".json").toFile()
        try {
            val messages = mutableListOf<String>()
            val failure = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                    timeoutMillis = 50, progress = messages::add)
            }.exceptionOrNull()
            assertTrue(failure is IOException)
            assertEquals("MAPLESU_93260_HANDOVER_TIMEOUT", failure?.message)
            assertTrue(messages.first().contains("文件=0 bytes"))
            assertTrue(messages.last().contains("等待超时"))
        } finally { file.delete() }
    }

    @Test fun sourceWaitPreservesBackendFailureAndDispatchError() {
        val file = Files.createTempFile("source-receipt-", ".json").toFile()
        try {
            file.writeText(source().put("exitCode", 65).toString())
            val rejected = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference())
            }.exceptionOrNull()
            assertEquals("MAPLESU_93260_HANDOVER_FAILED:65", rejected?.message)
            file.writeText("")
            val dispatch = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference("dispatch failed"),
                    timeoutMillis = 50)
            }.exceptionOrNull()
            assertEquals("MAPLESU_93260_DISPATCH_FAILED:dispatch failed", dispatch?.message)
        } finally { file.delete() }
    }

    @Test fun interruptedSourceWaitExitsAsCancelledAndRetainsInterruptFlag() {
        val file = Files.createTempFile("source-receipt-", ".json").toFile()
        try {
            val failure = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference()) {
                    Thread.currentThread().interrupt()
                }
            }.exceptionOrNull()
            assertEquals("JAILBREAK_CANCELLED", failure?.message)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted(); file.delete() }
    }

    private fun normalHandover() = JSONObject().apply {
        put("schema", "maplesu.handover.v1")
        put("provider", request.method)
        put("bootId", request.bootId)
        put("attempt", request.attemptId)
        put("target", "normal")
        put("verdict", "OK")
        put("carrier", JSONObject().put("kind", "ksu-lkm").put("ksu", "LATE_LOAD_OK"))
    }

    @Test fun normalDoesNotWaitForSourceExitAfterBoundHandoverAndRestore() {
        val file = Files.createTempFile("normal-source-", ".json").toFile()
        try {
            var restored = false
            val messages = mutableListOf<String>()
            MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                timeoutMillis = 250, readNormalHandover = { normalHandover().toString() },
                restoreNormal = { restored = true; true }, progress = messages::add)
            assertTrue("Normal must verify restoration before proceeding", restored)
            assertTrue(messages.last().contains("Normal"))
        } finally { file.delete() }
    }

    @Test fun normalRejectsAnotherBootAttemptOrProviderBeforeRootAccess() {
        val file = Files.createTempFile("normal-source-", ".json").toFile()
        try {
            for (key in listOf("bootId", "attempt", "provider", "target")) {
                var restored = false
                val failure = runCatching {
                    MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                        timeoutMillis = 100, readNormalHandover = { normalHandover().put(key, "other").toString() },
                        restoreNormal = { restored = true; true })
                }.exceptionOrNull()
                assertEquals("GHOSTLOCK_HANDOVER_BINDING_MISMATCH", failure?.message)
                assertFalse(restored)
            }
        } finally { file.delete() }
    }

    @Test fun normalBackendFailureIsNotHiddenByMissingSourceReceipt() {
        val file = Files.createTempFile("normal-source-", ".json").toFile()
        try {
            val failure = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                    timeoutMillis = 100,
                    readNormalHandover = { normalHandover().put("verdict", "FAILED").put("token", "LOAD_FAILED").toString() },
                    restoreNormal = { fail("Failed handover must not access root"); true })
            }.exceptionOrNull()
            assertEquals("LOAD_FAILED", failure?.message)
        } finally { file.delete() }
    }

    @Test fun normalKeepsWaitingUntilRestorationIsVerified() {
        val file = Files.createTempFile("normal-source-", ".json").toFile()
        try {
            file.writeText("{\"schema\":")
            var calls = 0
            MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                timeoutMillis = 2000, readNormalHandover = { normalHandover().toString() },
                restoreNormal = { ++calls >= 2 })
            assertEquals(2, calls)
        } finally { file.delete() }
    }

    @Test fun ultraStillRequiresSourceCompletionAndNeverRunsNormalRestore() {
        val file = Files.createTempFile("ultra-source-", ".json").toFile()
        try {
            var restored = false
            val failure = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request.copy(rootBackend = JailbreakRequest.BACKEND_HOOK),
                    1, { false }, AtomicReference(), timeoutMillis = 100,
                    readNormalHandover = { normalHandover().toString() },
                    restoreNormal = { restored = true; true })
            }.exceptionOrNull()
            assertEquals("MAPLESU_93260_HANDOVER_TIMEOUT", failure?.message)
            assertFalse(restored)
        } finally { file.delete() }
    }

    @Test fun sourceFailureTakesPrecedenceOverNormalCompletion() {
        val file = Files.createTempFile("normal-source-", ".json").toFile()
        try {
            file.writeText(source().put("exitCode", 65).toString())
            val failure = runCatching {
                MapleSu93260Attempt.awaitSourceReceipt(file, request, 1, { false }, AtomicReference(),
                    timeoutMillis = 100, readNormalHandover = { normalHandover().toString() },
                    restoreNormal = { fail("Source failure must be preserved"); true })
            }.exceptionOrNull()
            assertEquals("MAPLESU_93260_HANDOVER_FAILED:65", failure?.message)
        } finally { file.delete() }
    }

    @Test fun thirdMethodRequiresShizukuButNoGhostlockProfile() {
        assertFalse(JailbreakSelectionUi(JailbreakMethod.MAPLESU_93260, true, false)
            .canStart(false, true, false, false, false))
        assertTrue(JailbreakSelectionUi(JailbreakMethod.MAPLESU_93260, false, true)
            .canStart(false, true, false, false, true))
        assertFalse(JailbreakSelectionUi(JailbreakMethod.MAPLESU_93260, false, true)
            .showGhostlockConfiguration)
        assertTrue(JailbreakSelectionUi(JailbreakMethod.DIRTYFRAG, false, false)
            .canStart(false, true, false, false, false))
    }

    @Test fun admissionUsesFullRelease() {
        val target = JailbreakTarget("16", 36, KernelMap.KERNEL_RELEASE, "arm64-v8a",
            "vivo", "soc", "fingerprint", "boot-a", "unknown")
        assertTrue(JailbreakAdmission.assess(JailbreakMethod.MAPLESU_93260, target).canStart)
        assertTrue(JailbreakAdmission.assess(JailbreakMethod.MAPLESU_93260,
            target.copy(kernelRelease = KernelMap.KERNEL_RELEASE.replace("dd6fd5c98918", "376529f3e739")))
            .blockers.contains(JailbreakBlocker.MAPLESU_93260_KERNEL_UNSUPPORTED))
    }

    @Test fun originalPollingLoopsFitTheOuterBudget() {
        // waitBoot: 180 * (5 s RPC + 1 s delay). startFake: 90 * (2 * 10 s + 3 s).
        val retainedPolling = 180 * 6_000L + 90 * 23_000L
        assertTrue(hookPrepareBudgetMillis(request) > retainedPolling + 300_000L)
        assertEquals(hookPrepareBudgetMillis(request), hookPrepareBudgetMillis(
            request.copy(rootBackend = JailbreakRequest.BACKEND_HOOK)))
    }

    @Test fun successfulThirdMethodKeepsItsCredentialAnchors() {
        val state = JailbreakSelectionState(method = JailbreakMethod.MAPLESU_93260,
            shizuku = ShizukuAccess.State(true, true))
        assertFalse(state.softRebootAvailable)
    }

    @Test fun anotherProviderReceiptDoesNotProveThisSource() {
        val receipt = JSONObject().put("schema", "maplesu.handover.v1")
            .put("bootId", request.bootId).put("attempt", request.attemptId).put("target", "normal")
            .put("provider", "ghostlock").put("verdict", "OK")
        assertEquals("GHOSTLOCK_HANDOVER_BINDING_MISMATCH", GhostlockHandover.refusal(receipt.toString(), request))
        receipt.put("provider", request.method)
            .put("carrier", JSONObject().put("kind", "ksu-lkm").put("ksu", "LATE_LOAD_OK"))
        assertNull(GhostlockHandover.refusal(receipt.toString(), request))
    }

    @Test fun batchOpensAppDataInTheWindowAndPublishesOnlyAfterReadback() {
        val home = File("/data/user/0/dev.maplesu.manager")
        val receipt = File("/data/user_de/0/dev.maplesu.manager/files/jailbreak/maplesu-93260-source.json")
        for (backend in listOf(JailbreakRequest.BACKEND_KSU, JailbreakRequest.BACKEND_HOOK)) {
            for (entry in listOf(0, 1)) {
                val script = MapleSu93260Attempt.batch(home, request.copy(rootBackend = backend), receipt, entry)
                assertTrue(script.indexOf("trap finish EXIT") < script.indexOf("printf 0 >&8"))
                assertTrue(script.indexOf("exec 8>") < script.indexOf("printf 0 >&8"))
                assertTrue(script.indexOf("exec 9<") < script.indexOf("printf 0 >&8"))
                assertTrue(script.indexOf("printf 0 >&8") < script.indexOf("exec 7>'"))
                assertTrue(script.indexOf("IFS= read -r FINAL <&9 || :") < script.indexOf("\"schema\""))
                assertFalse(script.contains("FINAL=\$(cat <&9)"))
                assertTrue(script.contains("kill -STOP \"\$DISPATCHER\""))
                assertTrue(script.contains("export MAPLESU_KALLSYMS_PATH=/data/local/tmp/kall"))
                val target = if (backend == JailbreakRequest.BACKEND_KSU) "normal" else "ultra"
                assertTrue(script.contains("--handover --target $target --phase pre"))
                val finish = script.substringAfter("finish() {").substringBefore("trap finish EXIT")
                assertTrue(finish.contains("RESTORE=\$ENTRY"))
                assertTrue(finish.contains("if [ '$target' = normal ] && [ \"\$CODE\" = 0 ]; then RESTORE=1; fi"))
                assertTrue(finish.contains("echo \"\$RESTORE\" >&8"))
                assertTrue(finish.contains("echo '{\"schema\":\"maplesu.93260.source.v1\""))
                assertFalse(Regex("(?m)^\\s*printf\\s").containsMatchIn(finish))
                File("build/reports/maplesu-93260-batches/$target-$entry.sh").apply {
                    parentFile!!.mkdirs()
                    writeText(script)
                }
            }
        }
        // The plant engine's wrapper owns the conditional export: feeding the
        // patched ksud an all-zero table is worse than letting it fall back.
        val plant = MapleSu93260Attempt.batch(home, request, receipt, 1, kallsymsEnv = false)
        assertFalse(plant.contains("export MAPLESU_KALLSYMS_PATH"))
        assertTrue(plant.contains("--handover --target normal --phase pre"))
    }

    /**
     * The retained engine's post-exploit block is the product contract: same
     * helper, same arguments, same order, same snapshot variable. A plant profile
     * differs only by letting the wrapper decide the symbol input.
     */
    @Test fun retainedHandoverBlockStaysByteIdentical() {
        val home = File("/data/user/0/dev.maplesu.manager")
        val receipt = File("/data/user_de/0/dev.maplesu.manager/files/jailbreak/source.json")
        val helper = File(home, "bs").path
        val ksud = File(home, "ksud").path
        val invocation = "'$helper' --handover --target normal --phase pre " +
            "--attempt 'attempt-a' --boot 'boot-a' --entry-enforcing 1 --ksud '$ksud'"
        val script = MapleSu93260Attempt.batch(home, request, receipt, 1)
        val expected = "export MAPLESU_KALLSYMS_PATH=/data/local/tmp/kall\n" + invocation
        assertTrue("retained handover block changed:\n" + script, script.contains(expected))
        val plant = MapleSu93260Attempt.batch(home, request, receipt, 1, kallsymsEnv = false)
        assertTrue("plant must reuse the same helper call:\n" + plant, plant.contains(invocation))
    }
}
