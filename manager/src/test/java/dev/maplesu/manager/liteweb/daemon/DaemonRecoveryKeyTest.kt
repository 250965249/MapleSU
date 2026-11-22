package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.liteweb.LiteWebUnhideCodes
import dev.maplesu.manager.runtime.ultra.UltraRecoveryKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * D1（2026-10-31 真机）：daemon 侧撤销授权拿不到正确的 androidId → rootkey 解不开 → 永久 409
 *（`HIDDEN_SU_AUTH_BACKEND_UNAVAILABLE / rootkey_or_androidid_unavailable`）。
 *
 * 这里锁三件事：
 *  1. **identity 优先**：App 激活时落盘的 `identity.json`（App 作用域 androidId）能解 rootkey，
 *     即使系统 androidId 不同（真机就是这个组合）；
 *  2. **回退**：identity 缺失/损坏/解不开时，旧逻辑（`settings get secure android_id`）仍然可用；
 *  3. **不假成功**：`remove_su_auth` 之后的**回读**若不干净（宿主仍在列表 / 列表读不到）必须失败。
 *
 * 这些用例只覆盖纯判定（[DaemonRecoveryKey] / [SuAuthReadbackPolicy]），不加载 Ultra SDK。
 */
class DaemonRecoveryKeyTest {

    private val pkg = "dev.maplesu.manager"

    /** App 作用域值（真机上 App 通过 `Settings.Secure` 读到的那一个）。 */
    private val appAndroidId = "0123456789abcdef"

    /** `settings get secure android_id` 读到的系统值（Android 8+ 与上者不同）。 */
    private val systemAndroidId = "fedcba9876543210"

    private val key = "K".repeat(UltraRecoveryKey.KEY_LENGTH)

    private fun sealed(androidId: String, packageName: String = pkg): String =
        requireNotNull(UltraRecoveryKey.seal(key, androidId, packageName)) { "seal failed" }

    private fun identity(androidId: String = appAndroidId, packageName: String = pkg) =
        requireNotNull(RecoveryIdentity.of(androidId, packageName, 10_123))

    private fun ok(outcome: DaemonRecoveryKey.Outcome): DaemonRecoveryKey.Outcome.Ok =
        outcome as? DaemonRecoveryKey.Outcome.Ok ?: error("expected Ok, got $outcome")

    private fun missing(outcome: DaemonRecoveryKey.Outcome): DaemonRecoveryKey.Outcome.Missing =
        outcome as? DaemonRecoveryKey.Outcome.Missing ?: error("expected Missing, got $outcome")

    // ── 身份来源 ──────────────────────────────────────────────────────────

    @Test
    fun identityFileAndroidIdDecryptsRootkeyEvenWhenSystemValueDiffers() {
        // 真机现场：rootkey 是 App 用**应用作用域** androidId 封的，daemon 只能读到系统值。
        val outcome = DaemonRecoveryKey.resolve(
            payload = sealed(appAndroidId),
            identity = identity(),
            systemAndroidId = systemAndroidId,
            managerPackage = pkg,
        )
        assertEquals(key, ok(outcome).key)
        assertEquals(DaemonRecoveryKey.SOURCE_IDENTITY, ok(outcome).source)
    }

    @Test
    fun withoutIdentityTheOldSystemValueFallbackStillWorks() {
        // 老版本激活过、没有 identity.json 的现场：行为必须与修复前一致。
        val outcome = DaemonRecoveryKey.resolve(
            payload = sealed(systemAndroidId),
            identity = null,
            systemAndroidId = systemAndroidId,
            managerPackage = pkg,
        )
        assertEquals(key, ok(outcome).key)
        assertEquals(DaemonRecoveryKey.SOURCE_SYSTEM, ok(outcome).source)
    }

    @Test
    fun identityFromAnotherSignatureFallsBackToSystemValueInsteadOfFailing() {
        // identity.json 在但装的是另一份 App（换签名/清数据后的旧文件）→ 解不开就用系统值。
        val stale = identity(androidId = "1111222233334444")
        val outcome = DaemonRecoveryKey.resolve(
            payload = sealed(systemAndroidId),
            identity = stale,
            systemAndroidId = systemAndroidId,
            managerPackage = pkg,
        )
        assertEquals(key, ok(outcome).key)
        assertEquals(DaemonRecoveryKey.SOURCE_SYSTEM, ok(outcome).source)
    }

    @Test
    fun identityPackageNameIsTriedWhenItDiffersFromTheRunningPackage() {
        // 改包名现场：rootkey 是按 identity 里记录的包名封的。
        val renamed = "dev.maplesu.manager.beta"
        val outcome = DaemonRecoveryKey.resolve(
            payload = sealed(appAndroidId, renamed),
            identity = identity(packageName = renamed),
            systemAndroidId = null,
            managerPackage = pkg,
        )
        assertEquals(key, ok(outcome).key)
        assertEquals(DaemonRecoveryKey.SOURCE_IDENTITY, ok(outcome).source)
    }

    // ── 显式失败（不许假成功） ────────────────────────────────────────────

    @Test
    fun undecryptableRootkeyFailsExplicitlyAndLeaksNothing() {
        val outcome = missing(
            DaemonRecoveryKey.resolve(
                payload = sealed("9999888877776666"),
                identity = identity(),
                systemAndroidId = systemAndroidId,
                managerPackage = pkg,
            ),
        )
        assertTrue(outcome.detail.startsWith(DaemonRecoveryKey.WHY_UNDECRYPTABLE))
        assertTrue("要能看出两个来源都试过：${outcome.detail}", outcome.detail.contains("identity=1"))
        assertTrue(outcome.detail.contains("system=1"))
        // detail 是机器码：不含 androidId、不含 key、不含密文。
        assertFalse("不许把 androidId 写进回执", outcome.detail.contains(appAndroidId))
        assertFalse(outcome.detail.contains(systemAndroidId))
        assertFalse("不许把 key 写进回执", outcome.detail.contains(key))
    }

    @Test
    fun absentRootkeyIsDistinctFromForeignFormat() {
        assertEquals(
            DaemonRecoveryKey.WHY_ROOTKEY_ABSENT,
            missing(DaemonRecoveryKey.resolve(null, identity(), systemAndroidId, pkg)).detail,
        )
        assertEquals(
            DaemonRecoveryKey.WHY_ROOTKEY_ABSENT,
            missing(DaemonRecoveryKey.resolve("   ", identity(), systemAndroidId, pkg)).detail,
        )
        assertEquals(
            DaemonRecoveryKey.WHY_ROOTKEY_NOT_OURS,
            missing(DaemonRecoveryKey.resolve("bm90LW91cnM=", identity(), systemAndroidId, pkg)).detail,
        )
    }

    @Test
    fun noAndroidIdAnywhereFailsAsUnavailable() {
        val outcome = missing(
            DaemonRecoveryKey.resolve(
                payload = sealed(appAndroidId),
                identity = null,
                systemAndroidId = null,
                managerPackage = pkg,
            ),
        )
        assertEquals(DaemonRecoveryKey.WHY_NO_ANDROID_ID, outcome.detail)
    }

    @Test
    fun corruptedIdentityIsTreatedAsAbsentAndFallsBack() {
        // 损坏的 identity.json 解析为 null（严格白名单），不是「用它试一次」。
        assertNull(RecoveryIdentity.parse("{\"v\":1,\"androidId\":\"$appAndroidId\"}"))
        val outcome = DaemonRecoveryKey.resolve(
            payload = sealed(systemAndroidId),
            identity = RecoveryIdentity.parse("garbage"),
            systemAndroidId = systemAndroidId,
            managerPackage = pkg,
        )
        assertEquals(DaemonRecoveryKey.SOURCE_SYSTEM, ok(outcome).source)
    }

    // ── 回读判定（remove_su_auth 之后） ───────────────────────────────────

    @Test
    fun readbackWithoutHostPackageIsSuccess() {
        val result = SuAuthReadbackPolicy.verify(
            hostPackage = "com.example.host",
            packages = listOf("bin.mt.plus"),
            listReadable = true,
            remaining = 1,
            source = DaemonRecoveryKey.SOURCE_IDENTITY,
        )
        assertTrue(result.ok)
        assertTrue("回执要能区分用的是 identity 还是系统值：${result.detail}", result.detail.contains("id=identity"))
        assertTrue(result.detail.contains("remaining=1"))
    }

    @Test
    fun readbackStillListingHostIsFailure() {
        val result = SuAuthReadbackPolicy.verify(
            hostPackage = "com.example.host",
            packages = listOf("com.example.host", "bin.mt.plus"),
            listReadable = true,
            remaining = 2,
            source = DaemonRecoveryKey.SOURCE_IDENTITY,
        )
        assertFalse("宿主还在授权列表里绝不能报成功", result.ok)
        assertEquals(LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, result.code)
        assertTrue(result.detail.contains("still_listed"))
    }

    @Test
    fun unparsableReadbackIsFailureNotSuccess() {
        assertFalse(
            SuAuthReadbackPolicy.verify(
                hostPackage = "com.example.host",
                packages = emptyList(),
                listReadable = false,
                remaining = 0,
                source = DaemonRecoveryKey.SOURCE_IDENTITY,
            ).ok,
        )
        val nullPackages = SuAuthReadbackPolicy.verify(
            hostPackage = "com.example.host",
            packages = null,
            listReadable = true,
            remaining = 0,
            source = DaemonRecoveryKey.SOURCE_SYSTEM,
        )
        assertFalse("读不到列表 ≠ 已撤销", nullPackages.ok)
        assertEquals(SuAuthReadbackPolicy.READBACK_UNPARSABLE, nullPackages.detail)
    }
}
