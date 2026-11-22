// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 自白名单（`su_auth` 写入本应用包名）的成功 / 失败 / 幂等矩阵（JVM，fake [SuAuthPort]）。
 *
 * <p>这是「重装管理器后不认主」自愈的**前置条件**：只有管理器自己在 `su_auth` 里，
 * 重装后没有 key 也能经 su 拿到 uid 0 去读回 root 备份。
 */
class UltraSelfWhitelistTest {

    private class FakePort(
        var snapshot: List<String>? = emptyList(),
        var addResult: String = "OK",
        var removeResult: String = "OK",
    ) : SuAuthPort {
        val adds = mutableListOf<String>()
        val removes = mutableListOf<String>()
        var snapshotCalls = 0

        override fun snapshot(): List<String>? {
            snapshotCalls++
            return snapshot
        }

        override fun add(packageName: String): String {
            adds += packageName
            if (addResult == "OK") snapshot = (snapshot.orEmpty() + packageName).distinct()
            return addResult
        }

        override fun remove(packageName: String): String {
            removes += packageName
            snapshot = snapshot.orEmpty().filterNot { it == packageName }
            return removeResult
        }
    }

    private val pkg = "dev.maplesu.manager"

    @Test
    fun committedMembershipDoesNotClaimSuccessfulDelivery() {
        var packages = emptyList<String>()
        var writes = 0
        val port = object : SuAuthPort {
            override fun snapshot() = packages
            override fun add(packageName: String): String {
                writes++
                packages = listOf(packageName)
                return "ERR_SU_DELIVERY_INCOMPLETE"
            }
            override fun remove(packageName: String) = "UNEXPECTED"
        }
        val result = UltraSelfWhitelist.ensure(port, pkg)
        assertTrue(result.inList)
        assertTrue(result.listVerified)
        assertFalse(result.added)
        assertEquals("ERR_SU_DELIVERY_INCOMPLETE", result.failure)
        assertFalse(result.succeeded)
        assertEquals(1, writes)
    }

    @Test
    fun okReceiptWithoutPersistedEntryIsNotAConfirmedGrant() {
        val port = object : SuAuthPort {
            override fun snapshot() = emptyList<String>()
            override fun add(packageName: String) = "OK"
            override fun remove(packageName: String) = "OK"
        }
        val result = UltraSelfWhitelist.ensure(port, pkg)
        assertFalse(result.inList)
        assertFalse(result.added)
        assertEquals("READBACK_MISMATCH", result.failure)
    }

    @Test
    fun forceRefreshDoesNotRevokeAnExistingGrant() {
        val port = FakePort(snapshot = listOf(pkg))
        UltraSelfWhitelist.ensure(port, pkg, force = true)
        assertTrue("Refreshing the UID mapping must not remove the working grant", port.removes.isEmpty())
    }

    @Test
    fun failedReadbackDoesNotMasqueradeAsVerified() {
        var reads = 0
        val port = object : SuAuthPort {
            override fun snapshot(): List<String>? = if (reads++ == 0) emptyList() else null
            override fun add(packageName: String) = "OK"
            override fun remove(packageName: String) = "OK"
        }
        val result = UltraSelfWhitelist.ensure(port, pkg)
        assertFalse(result.inList)
        assertFalse(result.listVerified)
        assertEquals("READBACK_FAILED", result.failure)
    }

    @Test
    fun addsSelfWhenAbsentFromList() {
        val port = FakePort(snapshot = listOf("com.example.other"))
        val result = UltraSelfWhitelist.ensure(port, pkg)

        assertTrue(result.inList)
        assertTrue(result.added)
        assertFalse(result.alreadyPresent)
        assertTrue(result.attempted)
        assertTrue(result.listVerified)
        assertEquals(listOf(pkg), port.adds)
    }

    @Test
    fun alreadyPresentIsIdempotentAndDoesNotCallAdd() {
        val port = FakePort(snapshot = listOf("com.example.other", pkg))
        val result = UltraSelfWhitelist.ensure(port, pkg)

        assertTrue(result.inList)
        assertFalse(result.added)
        assertTrue(result.alreadyPresent)
        // 幂等纪律：已在列表里就绝不重复 add。
        assertFalse(result.attempted)
        assertTrue(port.adds.isEmpty())
        assertEquals(1, port.snapshotCalls)
    }

    @Test
    fun addFailureIsReportedWithoutPretendingSuccess() {
        val port = FakePort(snapshot = emptyList(), addResult = "-7")
        val result = UltraSelfWhitelist.ensure(port, pkg)

        assertFalse(result.inList)
        assertFalse(result.added)
        assertTrue(result.attempted)
        assertEquals("ADD_FAILED:-7", result.failure)
        assertEquals(listOf(pkg), port.adds)
    }

    @Test
    fun unreadableInitialSnapshotCanBeVerifiedAfterAdd() {
        // 初始读取失败仍可尝试一次，成功后的快照决定最终状态。
        val port = FakePort(snapshot = null, addResult = "OK")
        val result = UltraSelfWhitelist.ensure(port, pkg)

        assertTrue(result.inList)
        assertTrue(result.added)
        assertTrue(result.listVerified)
        assertEquals(1, port.adds.size)
    }

    @Test
    fun unreadableSnapshotAndAddFailureIsHonest() {
        val port = FakePort(snapshot = null, addResult = "EIO")
        val result = UltraSelfWhitelist.ensure(port, pkg)

        assertFalse(result.inList)
        assertFalse(result.listVerified)
        assertEquals("ADD_FAILED:EIO", result.failure)
    }

    @Test
    fun blankPackageIsRejectedWithoutTouchingSdk() {
        val port = FakePort()
        val result = UltraSelfWhitelist.ensure(port, "   ")

        assertFalse(result.inList)
        assertEquals("EMPTY_PACKAGE", result.failure)
        assertEquals(0, port.snapshotCalls)
        assertTrue(port.adds.isEmpty())
    }

    @Test
    fun forceReaddRefreshesStaleEntryWithoutTouchingOthers() {
        // 设备实测：重装换 UID 后，su_auth 里包名还在，但 Ultra 的 su 重定向不认。
        // SDK add 本身重建 UID 表；这里验证没有先删除原持久条目。
        val port = FakePort(snapshot = listOf("com.example.other", pkg))
        val result = UltraSelfWhitelist.ensure(port, pkg, force = true)

        assertTrue(result.inList)
        assertTrue(result.added)
        assertFalse(result.alreadyPresent)
        assertTrue(result.attempted)
        assertTrue(port.removes.isEmpty())
        assertEquals(listOf(pkg), port.adds)
    }

    @Test
    fun forceReaddOnAbsentEntryDoesNotRemove() {
        val port = FakePort(snapshot = listOf("com.example.other"))
        val result = UltraSelfWhitelist.ensure(port, pkg, force = true)

        assertTrue(result.inList)
        assertTrue(result.added)
        assertTrue(port.removes.isEmpty())
        assertEquals(listOf(pkg), port.adds)
    }

    @Test
    fun forceReaddAddFailureIsReportedHonestly() {
        val port = FakePort(snapshot = listOf(pkg), addResult = "-9")
        val result = UltraSelfWhitelist.ensure(port, pkg, force = true)

        assertFalse(result.inList)
        assertFalse(result.added)
        assertEquals("ADD_FAILED:-9", result.failure)
        assertTrue(port.removes.isEmpty())
        assertEquals(listOf(pkg), port.snapshot)
        assertEquals(1, port.adds.size)
    }

    @Test
    fun summaryCarriesNoKeyOrSecretMaterial() {
        val port = FakePort(snapshot = emptyList())
        val summary = UltraSelfWhitelist.ensure(port, pkg).summary

        assertFalse(UltraSdkLogging.containsKeyLike(summary))
        assertTrue(summary.contains("inList=true"))
        assertTrue(summary.contains("added=true"))
    }
}

/**
 * 安装成功后自动白名单 + key 备份的编排（需求 1 / 3）。
 *
 * <p>[UltraEnvironmentInstaller.afterInstall] 是纯编排：安装回执是否成功决定要不要动手；
 * 白名单/备份失败**绝不**把安装改判失败（需求 1 的「失败只记录不阻断安装」）。
 */
class UltraEnvironmentInstallerAfterInstallTest {

    private class Calls {
        var whitelist = 0
        var backup = 0
    }

    private fun whitelistOk() = UltraSelfWhitelist.Result(
        inList = true,
        added = true,
        alreadyPresent = false,
        attempted = true,
        listVerified = true,
    )

    @Test
    fun failedInstallDoesNotWhitelistOrBackUp() {
        val calls = Calls()
        val outcome = UltraEnvironmentInstaller.afterInstall(
            succeeded = false,
            sdkError = "-1",
            reason = "NOT_INSTALLED",
            whitelist = { calls.whitelist++; whitelistOk() },
            backup = { calls.backup++; "OK" },
        )

        assertFalse(outcome.ok)
        assertEquals(0, calls.whitelist)
        assertEquals(0, calls.backup)
        assertEquals("-1", outcome.sdkError)
        assertEquals("NOT_INSTALLED", outcome.reason)
    }

    @Test
    fun successfulInstallWhitelistsThenBacksUpKey() {
        val calls = Calls()
        val order = mutableListOf<String>()
        val outcome = UltraEnvironmentInstaller.afterInstall(
            succeeded = true,
            sdkError = "OK",
            reason = null,
            whitelist = { order += "whitelist"; calls.whitelist++; whitelistOk() },
            backup = { order += "backup"; calls.backup++; "OK" },
        )

        assertTrue(outcome.ok)
        assertEquals(1, calls.whitelist)
        assertEquals(1, calls.backup)
        assertEquals(listOf("whitelist", "backup"), order)
        assertEquals("OK", outcome.backup)
    }

    @Test
    fun whitelistFailureKeepsInstallSuccessfulAndStillBacksUp() {
        val calls = Calls()
        val outcome = UltraEnvironmentInstaller.afterInstall(
            succeeded = true,
            sdkError = "OK",
            reason = null,
            whitelist = {
                calls.whitelist++
                UltraSelfWhitelist.Result(
                    inList = false,
                    added = false,
                    alreadyPresent = false,
                    attempted = true,
                    listVerified = true,
                    failure = "ADD_FAILED:-7",
                )
            },
            backup = { calls.backup++; "OK" },
        )

        // 安装本身仍然成功；白名单失败只记录。
        assertTrue(outcome.ok)
        assertEquals(1, calls.whitelist)
        // 备份使用内核 Key 通道，与 su_auth 刷新结果独立。
        assertEquals(1, calls.backup)
        assertEquals("OK", outcome.backup)
        assertTrue(outcome.whitelist.orEmpty().contains("ADD_FAILED:-7"))
    }

    @Test
    fun whitelistExceptionKeepsInstallSuccessfulAndStillBacksUp() {
        val calls = Calls()
        val outcome = UltraEnvironmentInstaller.afterInstall(
            succeeded = true,
            sdkError = "OK",
            reason = null,
            whitelist = { throw IllegalStateException("jni gone") },
            backup = { calls.backup++; "OK" },
        )

        assertTrue(outcome.ok)
        assertEquals(1, calls.backup)
        assertEquals("OK", outcome.backup)
        assertEquals("EXCEPTION:WHITELIST", outcome.whitelist)
    }

    @Test
    fun backupExceptionKeepsInstallSuccessful() {
        val outcome = UltraEnvironmentInstaller.afterInstall(
            succeeded = true,
            sdkError = "OK",
            reason = null,
            whitelist = { whitelistOk() },
            backup = { throw IllegalStateException("no root") },
        )

        assertTrue(outcome.ok)
        assertEquals("EXCEPTION:IllegalStateException", outcome.backup)
    }

    @Test
    fun outcomeSummaryNeverContainsKeyMaterial() {
        val outcome = UltraEnvironmentInstaller.afterInstall(
            succeeded = true,
            sdkError = "OK",
            reason = null,
            whitelist = { whitelistOk() },
            backup = { UltraRecoveryKeyStore.REASON_OK },
        )

        assertFalse(UltraSdkLogging.containsKeyLike(outcome.summary))
    }
}
