package dev.maplesu.manager.workmode.service

import dev.maplesu.installer.InstallerMultiPartitionTransaction
import dev.maplesu.installer.StepRole
import dev.maplesu.installer.SwitchFacts
import dev.maplesu.installer.SwitchFailure
import dev.maplesu.installer.SwitchPlan
import dev.maplesu.installer.SwitchStep
import dev.maplesu.installer.WorkMode as InstallerMode
import dev.maplesu.manager.installer.InstallerSnapshot
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.switch.*
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.util.UUID
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Exercises persistence and pure recovery seams; never invokes an Android partition provider. */
class LocalInstallerGatewayPersistenceTest {
    @get:Rule val temporary = TemporaryFolder()

    private inner class Fixture {
        val root = temporary.newFolder()
        val authority = FileSwitchAuthority(File(root, "authority"), Clock { 1000 })
        val request = ModeSwitchRequest(UUID.randomUUID().toString(), WorkMode.LITE, WorkMode.KSU, "bl-fixture")
        val bootPre = File(root, "boot-pre").apply { writeText("P".repeat(4096)) }
        val initPre = File(root, "init-pre").apply { writeText("S".repeat(4096)) }
        val bootBase = File(root, "boot-base").apply { writeText("B".repeat(4096)) }
        val candidate = File(root, "candidate").apply { writeText("C".repeat(4096)) }
        val partitions = linkedMapOf("boot" to FakePartition("boot", bootPre.readBytes()),
            "init_boot" to FakePartition("init_boot", initPre.readBytes()))
        val sink = RecordingSink()
        val plan = InstallerMultiPartitionTransaction.prepare(
            SwitchPlan.Request(SwitchPlan.SCHEMA, request.switchId, InstallerMode.LITE, InstallerMode.KSU,
                request.baselineId, "boot-before", mapOf(SwitchPlan.DEVICE_SLOT to "_a",
                    SwitchPlan.DEVICE_FIRMWARE to "fixture-fw", SwitchPlan.DEVICE_KERNEL to "fixture-kernel",
                    SwitchPlan.DEVICE_SELINUX to "Enforcing"), listOf(
                    step("init_boot", StepRole.WRITE_CANDIDATE, candidate, initPre),
                    step("boot", StepRole.RESTORE_BASELINE, bootBase, bootPre),
                )), FakePartitionProvider(partitions), sink,
        )
        val record = SwitchRecord(switchId = request.switchId, planSha256 = plan.planSha256,
            state = SwitchStateNames.COMMIT, stage = "S4", fromMode = "LITE", toMode = "KSU",
            baselineId = request.baselineId, startBootId = plan.startBootId,
            artifacts = mapOf("candidate-init_boot" to candidate.absolutePath, "base-boot" to bootBase.absolutePath,
                "pre-init_boot" to initPre.absolutePath, "pre-boot" to bootPre.absolutePath) +
                plan.flatFields().mapKeys { (key, _) -> SwitchRecord.PREPARED_PLAN_PREFIX + key })

        init { authority.write(record) }

        private fun step(name: String, role: StepRole, image: File, pre: File) = SwitchStep(name, role,
            image.length(), image.toPath(), ModeSwitchHashes.sha256(image), pre.toPath(),
            ModeSwitchHashes.sha256(pre), ModeSwitchHashes.tailSha256(image))

        fun gateway(source: SwitchAuthority? = authority) = LocalInstallerGateway(File(root, "baseline"),
            authority = source) { throw AssertionError("plan loading must not prepare or open a journal") }
    }

    private fun recovered(gateway: LocalInstallerGateway, request: ModeSwitchRequest): SwitchPlan? {
        val method = LocalInstallerGateway::class.java.getDeclaredMethod("preparedPlan", ModeSwitchRequest::class.java)
            .apply { isAccessible = true }
        try { return method.invoke(gateway, request) as SwitchPlan? }
        catch (failure: InvocationTargetException) { throw failure.cause!! }
    }

    private fun cacheSize(gateway: LocalInstallerGateway): Int =
        (LocalInstallerGateway::class.java.getDeclaredField("plans").apply { isAccessible = true }
            .get(gateway) as Map<*, *>).size

    @Test fun newGatewayLoadsTheExactAuthorityPlanAndCachesOnlyAfterSuccess() {
        val fixture = Fixture()
        val gateway = fixture.gateway()
        val plan = recovered(gateway, fixture.request)!!
        assertEquals(fixture.plan.flatFields(), plan.flatFields())
        assertEquals(fixture.plan.device, plan.device)
        assertEquals(1, cacheSize(gateway))
        assertSame(plan, recovered(gateway, fixture.request))
        assertEquals(1, fixture.sink.events.count { it.op == dev.maplesu.installer.SwitchOp.PREPARED })
        assertTrue(fixture.partitions.values.all { it.writeLog.isEmpty() })
    }

    @Test fun deletedCandidateDoesNotPreventLoadingThePlanForRollbackOrVerify() {
        val fixture = Fixture()
        assertTrue(fixture.candidate.delete())
        val plan = recovered(fixture.gateway(), fixture.request)!!
        assertEquals(fixture.plan.flatFields(), plan.flatFields())
        assertFalse(fixture.candidate.exists())
        assertEquals(1, fixture.sink.events.count { it.op == dev.maplesu.installer.SwitchOp.PREPARED })
        assertTrue(fixture.partitions.values.all { it.writeLog.isEmpty() })
    }

    @Test fun malformedOrMismatchedRecordsAreNotCachedAndCanBeRepaired() {
        val fixture = Fixture()
        val prefix = SwitchRecord.PREPARED_PLAN_PREFIX
        val mutations = listOf<Pair<String, (SwitchRecord) -> SwitchRecord>>(
            "missing key" to { it.copy(artifacts = it.artifacts - (prefix + "step.count")) },
            "schema" to { it.copy(artifacts = it.artifacts + (prefix + "schema" to "unknown")) },
            "record modes" to { it.copy(fromMode = "KSU", toMode = "LITE") },
            "baseline" to { it.copy(baselineId = "wrong-baseline") },
            "start boot" to { it.copy(startBootId = "wrong-boot") },
            "record digest" to { it.copy(planSha256 = "0".repeat(64)) },
            "flat digest" to { it.copy(artifacts = it.artifacts + (prefix + "planSha256" to "0".repeat(64))) },
            "image artifact" to { it.copy(artifacts = it.artifacts + ("base-boot" to File(fixture.root, "other").path)) },
            "missing pre artifact" to { it.copy(artifacts = it.artifacts - "pre-init_boot") },
        )
        for ((name, mutate) in mutations) {
            val gateway = fixture.gateway()
            fixture.authority.write(mutate(fixture.record))
            val failure = assertThrows("$name must fail", SwitchFailure::class.java) {
                recovered(gateway, fixture.request)
            }
            assertEquals(name, ModeSwitchCodes.PLAN_INVALID, failure.code)
            assertEquals(name, 0, cacheSize(gateway))
            fixture.authority.write(fixture.record)
            assertEquals(name, fixture.plan.flatFields(), recovered(gateway, fixture.request)!!.flatFields())
        }
    }

    @Test fun differentRecordIdOrMissingFlatPlanDoesNotInventACacheEntry() {
        val fixture = Fixture()
        for (record in listOf(fixture.record.copy(switchId = UUID.randomUUID().toString()),
            fixture.record.copy(artifacts = fixture.record.artifacts.filterKeys {
                !it.startsWith(SwitchRecord.PREPARED_PLAN_PREFIX)
            }))) {
            fixture.authority.write(record)
            val gateway = fixture.gateway()
            assertNull(recovered(gateway, fixture.request))
            assertEquals(0, cacheSize(gateway))
        }
    }

    @Test fun requestBindingsAreCheckedBeforeLoadingAndOnCacheHits() {
        val fixture = Fixture()
        for (request in listOf(fixture.request.copy(fromMode = WorkMode.KSU, toMode = WorkMode.LITE),
            fixture.request.copy(baselineId = "wrong-baseline"))) {
            val gateway = fixture.gateway()
            assertEquals(ModeSwitchCodes.PLAN_INVALID, assertThrows(SwitchFailure::class.java) {
                recovered(gateway, request)
            }.code)
            assertEquals(0, cacheSize(gateway))
            val valid = recovered(gateway, fixture.request)
            assertEquals(ModeSwitchCodes.PLAN_INVALID, assertThrows(SwitchFailure::class.java) {
                recovered(gateway, request)
            }.code)
            assertSame(valid, recovered(gateway, fixture.request))
        }
        val gateway = fixture.gateway()
        assertNull(recovered(gateway, fixture.request.copy(switchId = UUID.randomUUID().toString())))
        assertEquals(0, cacheSize(gateway))
    }

    @Test fun corruptAuthorityFailsWithoutCachingOrRewritingTheFile() {
        val fixture = Fixture()
        fixture.authority.path().writeText("{broken")
        val gateway = fixture.gateway()
        assertEquals(ModeSwitchCodes.RECOVERY_JOURNAL_CORRUPT, assertThrows(SwitchFailure::class.java) {
            recovered(gateway, fixture.request)
        }.code)
        assertEquals(0, cacheSize(gateway))
        assertEquals("{broken", fixture.authority.path().readText())
    }

    @Test fun absentPlanRollbackReportsRecoveryInsteadOfFalseSuccess() {
        val fixture = Fixture()
        val missing = FileSwitchAuthority(File(fixture.root, "missing-authority"))
        for (gateway in listOf(fixture.gateway(missing), fixture.gateway(null))) {
            val result = gateway.rollback(fixture.request)
            assertFalse(result.ok)
            assertEquals(GatewayState.RECOVERY_REQUIRED, result.state)
            assertEquals(ModeSwitchCodes.PLAN_INVALID, result.code)
            assertEquals(0, cacheSize(gateway))
        }
    }

    @Test fun factsBootIdUsesTheOuterReaderWithoutRecursing() {
        val fixture = Fixture()
        val gateway = fixture.gateway()
        val snapshot = InstallerSnapshot("fixture-kernel", "fixture-fw", "_a", "Enforcing", emptyMap())
        val method = LocalInstallerGateway::class.java.getDeclaredMethod("facts", InstallerSnapshot::class.java)
            .apply { isAccessible = true }
        val facts = method.invoke(gateway, snapshot) as SwitchFacts
        val outer = LocalInstallerGateway::class.java.getDeclaredMethod("bootId").apply { isAccessible = true }
        assertEquals(outer.invoke(gateway), facts.bootId())
        assertEquals(snapshot.kernelRelease, facts.kernelRelease())
        assertEquals(snapshot.slotSuffix, facts.slotSuffix())
    }
}
