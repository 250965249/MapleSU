package dev.maplesu.manager.liteweb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LiteWebSuperuserTest {
    private val target = "com.example.application"
    private val other = "com.concurrent.application"
    private val managerPackage = "dev.maplesu.manager"
    private val host = "com.example.host"
    private val sdk = TestSuSdk()
    private var catalog = LiteWebSuCatalog(listOf(LiteWebSuApplication(target, 10123)), true, true)
    private var protection: () -> Set<String> = { setOf(managerPackage, host) }
    private val manager = LiteWebSuperuserManager(sdk, { catalog }, { protection() })

    @Test fun authorityBackedRevokeIsNotCompensatedBackIntoAGrant() {
        sdk.grants += target
        sdk.onWrite = { name, allowed ->
            if (allowed) sdk.grants += name else sdk.grants -= name
            LiteWebSuResult.Failed("SDK_MIRROR_PENDING")
        }
        val authoritySdk = object : LiteWebSuSdk by sdk {
            override val retainsCommittedDecisions = true
        }
        val authorityManager = LiteWebSuperuserManager(authoritySdk, { catalog }, { protection() })
        val result = authorityManager.setAllowed(target, false) as LiteWebSuResult.Failed
        assertEquals("pending-apply", result.rollback)
        assertFalse(target in sdk.grants)
        assertEquals(listOf(target to false), sdk.writes)
    }

    @Test fun successfulGrantAndRevokeRequireMembershipReadback() {
        val granted = manager.setAllowed(target, true) as LiteWebSuResult.Ok
        assertEquals(LiteWebSuMutation(target, true, true), granted.value)
        assertEquals(2, sdk.reads)
        val revoked = manager.setAllowed(target, false) as LiteWebSuResult.Ok
        assertEquals(LiteWebSuMutation(target, false, true), revoked.value)
        assertEquals(listOf(target to true, target to false), sdk.writes)
        assertTrue(sdk.grants.isEmpty())
    }

    @Test fun repeatedGrantIsIdempotentAndDoesNotWrite() {
        sdk.grants += target
        assertEquals(LiteWebSuMutation(target, true, false), (manager.setAllowed(target, true) as LiteWebSuResult.Ok).value)
        assertTrue(sdk.writes.isEmpty())
    }

    @Test fun managerAndHostAreProtectedAtTheBackend() {
        sdk.grants += setOf(managerPackage, host)
        for (name in listOf(managerPackage, host)) {
            assertEquals("SU_AUTH_PROTECTED", (manager.setAllowed(name, false) as LiteWebSuResult.Failed).code)
        }
        assertTrue(sdk.writes.isEmpty())
    }

    @Test fun unknownProtectionFailsBeforeAnyGrantOrRevoke() {
        protection = { error("unreadable host state") }
        val failure = manager.setAllowed(target, true) as LiteWebSuResult.Failed
        assertTrue(failure.unavailable)
        assertTrue(sdk.writes.isEmpty())
    }

    @Test fun catalogFailureOrMissingInstallationDoesNotGrant() {
        catalog = LiteWebSuCatalog()
        assertEquals("SU_AUTH_CATALOG_UNAVAILABLE", (manager.setAllowed(target, true) as LiteWebSuResult.Failed).code)
        catalog = LiteWebSuCatalog(emptyList(), true, true)
        assertEquals("SU_AUTH_PACKAGE_NOT_INSTALLED", (manager.setAllowed(target, true) as LiteWebSuResult.Failed).code)
        assertTrue(sdk.writes.isEmpty())
    }

    @Test fun staleUninstalledGrantCanStillBeRevoked() {
        sdk.grants += target
        catalog = LiteWebSuCatalog()
        assertTrue(manager.setAllowed(target, false) is LiteWebSuResult.Ok)
        assertFalse(target in sdk.grants)
    }

    @Test fun failedReceiptAfterMutationCompensatesOnlyThisPackage() {
        sdk.onWrite = { name, allowed ->
            if (allowed) {
                sdk.grants += setOf(name, other)
                LiteWebSuResult.Failed("SDK_WRITE_FAILED")
            } else {
                sdk.grants -= name
                LiteWebSuResult.Ok(Unit)
            }
        }
        val failure = manager.setAllowed(target, true) as LiteWebSuResult.Failed
        assertEquals("SDK_WRITE_FAILED", failure.code)
        assertEquals("verified", failure.rollback)
        assertEquals(setOf(other), sdk.grants)
        assertEquals(listOf(target to true, target to false), sdk.writes)
    }

    @Test fun failedRevokeRestoresOriginalGrantButKeepsConcurrentOtherGrant() {
        sdk.grants += target
        sdk.onWrite = { name, allowed ->
            if (!allowed) {
                sdk.grants -= name
                sdk.grants += other
                LiteWebSuResult.Failed("SDK_REMOVE_FAILED")
            } else {
                sdk.grants += name
                LiteWebSuResult.Ok(Unit)
            }
        }
        val failure = manager.setAllowed(target, false) as LiteWebSuResult.Failed
        assertEquals("verified", failure.rollback)
        assertEquals(setOf(target, other), sdk.grants)
    }

    @Test fun successfulReceiptWithoutStateChangeIsFailure() {
        sdk.onWrite = { _, _ -> LiteWebSuResult.Ok(Unit) }
        val failure = manager.setAllowed(target, true) as LiteWebSuResult.Failed
        assertEquals("SU_AUTH_READBACK_FAILED", failure.code)
        assertEquals("not-needed", failure.rollback)
        assertEquals(listOf(target to true), sdk.writes)
    }

    @Test fun unreadableAfterWriteRequiresVerifiedCompensation() {
        sdk.onRead = {
            if (sdk.reads == 2) LiteWebSuResult.Failed("UNREADABLE", unavailable = true)
            else LiteWebSuResult.Ok(sdk.grants.toSet())
        }
        val failure = manager.setAllowed(target, true) as LiteWebSuResult.Failed
        assertEquals("SU_AUTH_READBACK_FAILED", failure.code)
        assertEquals("verified", failure.rollback)
        assertTrue(sdk.grants.isEmpty())
    }

    @Test fun failedCompensationNeverClaimsRestoredOrSuccessful() {
        sdk.onWrite = { name, _ -> sdk.grants += name; LiteWebSuResult.Failed("SDK_FAILED") }
        val failure = manager.setAllowed(target, true) as LiteWebSuResult.Failed
        assertEquals("failed", failure.rollback)
        assertTrue(target in sdk.grants)
    }

    @Test fun unreadableListStopsBeforeMutationAndIsNotAnEmptySnapshot() {
        sdk.onRead = { LiteWebSuResult.Failed("SU_AUTH_LIST_UNREADABLE", unavailable = true) }
        assertTrue(manager.snapshot() is LiteWebSuResult.Failed)
        assertTrue(manager.setAllowed(target, true) is LiteWebSuResult.Failed)
        assertTrue(sdk.writes.isEmpty())
    }

    @Test fun packageGlobalSnapshotKeepsUsersAndOrphanGrantsWithoutInventingUid() {
        sdk.grants += setOf(target, other)
        catalog = LiteWebSuCatalog(listOf(LiteWebSuApplication(target, 10123), LiteWebSuApplication(target, 1010123)), true, true)
        val snapshot = (manager.snapshot() as LiteWebSuResult.Ok).value
        val json = snapshot.json()
        assertTrue(json.contains("\"scope\":\"package-global\""))
        assertTrue(json.contains("\"uid\":1010123,\"userId\":10"))
        assertTrue(json.contains("\"packageName\":\"$other\",\"uid\":null,\"userId\":null,\"installed\":false"))
        for (capability in listOf("uidPolicy", "userScopedPolicy", "expiry", "profiles")) {
            assertTrue(json.contains("\"$capability\":false"))
        }
    }

    @Test fun loggingWriteIsReadBackAndFailedWriteRestoresPriorSetting() {
        assertEquals(true, (manager.setLogging(true) as LiteWebSuResult.Ok).value)
        sdk.failLoggingWrite = true
        val failure = manager.setLogging(false) as LiteWebSuResult.Failed
        assertEquals("verified", failure.rollback)
        assertTrue(sdk.logging)
    }

    @Test fun clearLogRequiresAnEmptyReadbackAndReadIsBounded() {
        sdk.logText = "x".repeat(LiteWebSuperuserManager.MAX_LOG_CHARS + 17)
        val log = (manager.log() as LiteWebSuResult.Ok).value
        assertEquals(LiteWebSuperuserManager.MAX_LOG_CHARS, log.text.length)
        assertTrue(log.truncated)
        sdk.clearChangesState = false
        assertEquals("SU_LOG_READBACK_FAILED", (manager.clearLog() as LiteWebSuResult.Failed).code)
        sdk.clearChangesState = true
        assertTrue(manager.clearLog() is LiteWebSuResult.Ok)
    }

    @Test fun environmentLogsDoNotExposeRecoveryTokens() {
        val token = "abcdef0123456789".repeat(4)
        sdk.logText = "open http://127.0.0.1:18427/x7k9f/$token/ now"
        val safe = (manager.log() as LiteWebSuResult.Ok).value.text
        assertFalse(safe.contains(token))
        assertTrue(safe.contains("<REDACTED-TOKEN>"))
    }

    @Test fun packageNamesRejectCommandsPathsAndOversizedValues() {
        for (name in listOf("", "../host", "com.app;id", "com.app\nother", "a".repeat(256))) {
            assertEquals("SU_AUTH_PACKAGE_INVALID", (manager.setAllowed(name, true) as LiteWebSuResult.Failed).code)
        }
        assertTrue(sdk.writes.isEmpty())
    }
}

private class TestSuSdk : LiteWebSuSdk {
    val grants = linkedSetOf<String>()
    val writes = mutableListOf<Pair<String, Boolean>>()
    var reads = 0
    var onRead: (() -> LiteWebSuResult<Set<String>>)? = null
    var onWrite: ((String, Boolean) -> LiteWebSuResult<Unit>)? = null
    var logging = false
    var failLoggingWrite = false
    var logText = ""
    var clearChangesState = true
    override fun packages(): LiteWebSuResult<Set<String>> { reads++; return onRead?.invoke() ?: LiteWebSuResult.Ok(grants.toSet()) }
    override fun setAllowed(packageName: String, allowed: Boolean): LiteWebSuResult<Unit> {
        writes += packageName to allowed
        onWrite?.let { return it(packageName, allowed) }
        if (allowed) grants += packageName else grants -= packageName
        return LiteWebSuResult.Ok(Unit)
    }
    override fun loggingEnabled(): LiteWebSuResult<Boolean> = LiteWebSuResult.Ok(logging)
    override fun setLogging(enabled: Boolean): LiteWebSuResult<Unit> {
        logging = enabled
        return if (failLoggingWrite) LiteWebSuResult.Failed("LOG_WRITE_FAILED") else LiteWebSuResult.Ok(Unit)
    }
    override fun log(): LiteWebSuResult<String> = LiteWebSuResult.Ok(logText)
    override fun clearLog(): LiteWebSuResult<Unit> { if (clearChangesState) logText = ""; return LiteWebSuResult.Ok(Unit) }
}
