// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.litehidden.RecoveryIdentity
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * rootKey 恢复备份（`/data/adb/maplesu/recovery/rootkey`）的格式、加密、权限校验与读写。
 *
 * <p>覆盖需求 3：key 存在时用 root 备份（0600、root-only），恢复时校验长度/格式；
 * 以及「读不了 / 不是我们写的 / 解不开」必须与「没有备份」严格区分（不能猜 key）。
 */
class UltraRecoveryKeyStoreTest {

    private val key = "Aa1".repeat(16) // 48 printable ASCII
    private val androidId = "0123456789abcdef"
    private val pkg = "dev.maplesu.manager"
    private val uid = 10_123

    @Test
    fun staleKeyOrIdentityReadbackNeverReportsAnUpdatedPermanentBackup() {
        for (staleIdentity in listOf(false, true)) {
            val root = FakeRoot()
            val runner = RootScriptRunner { script ->
                root.run(script).also {
                    if (script.contains("printf %s")) {
                        if (staleIdentity) root.legacyIdentity = RecoveryIdentity.of(androidId, pkg, uid + 1)!!.toJson()
                        else root.file = UltraRecoveryKey.seal("Bb2".repeat(16), androidId, pkg)
                    }
                }
            }
            val result = UltraRecoveryKeyStore.backup(runner, key, androidId, pkg, uid)
            assertFalse("rename/permissions alone do not prove the new key was saved", result.ok)
            assertEquals("READBACK_FAILED", result.reason)
        }
    }

    @Test
    fun newerVerifiedKeyReplacesTheOldBackupAndRestoresAfterAFullReinstall() {
        val root = FakeRoot()
        assertTrue(UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid).ok)
        val next = "Cc3".repeat(16)
        assertTrue(UltraRecoveryKeyStore.backup(root, next, androidId, pkg, uid + 3).ok)
        assertEquals(next, UltraRecoveryKeyStore.restore(root, "fedcba9876543210", pkg).key)
        assertEquals(uid + 3, RecoveryIdentity.parse(root.legacyIdentity)!!.uid)
    }

    /**
     * 假 root：维护一个「设备上的文件」，按脚本类型返回真实 su 语义。
     * 只解析写脚本里的 base64 payload，不接触任何真实文件。
     */
    private class FakeRoot(
        var file: String? = null,
        var statLine: String = "600 0",
        var writeOutput: String? = null,
        /** 设置后，所有读取脚本都返回它（用来模拟通道失败/超时/读不了）。 */
        var readResult: SuExecResult? = null,
        var legacyIdentity: String? = null,
        var identityStatLine: String = "600 0",
        var identityReadResult: SuExecResult? = null,
        var fileSymlink: Boolean = false,
        var identitySymlink: Boolean = false,
        var directoryStatLine: String = "700 0",
        var directorySymlink: Boolean = false,
    ) : RootScriptRunner {
        val scripts = mutableListOf<String>()

        override fun run(script: String): SuExecResult? {
            scripts += script
            return when {
                script.contains("printf %s") -> {
                    if (writeOutput != null) return SuExecResult(1, writeOutput!!)
                    if (statLine != "600 0" || identityStatLine != "600 0") {
                        return SuExecResult(6, "MAPLESU_RK_UNSAFE")
                    }
                    val writes = Regex("""printf %s '([^']*)' > '([^']*)'""").findAll(script)
                        .associate { it.groupValues[2] to it.groupValues[1] }
                    file = writes["${UltraRecoveryKeyStore.PATH}.tmp"] ?: file
                    legacyIdentity = writes["/data/adb/maplesu/recovery/identity.json.tmp"] ?: legacyIdentity
                    SuExecResult(0, "MAPLESU_RK_WROTE\n$statLine\nMAPLESU_RK_IDENTITY_WROTE\n$identityStatLine")
                }

                directorySymlink || directoryStatLine != "700 0" -> SuExecResult(0, "MAPLESU_RK_UNSAFE")

                script.contains("/recovery/identity.json") -> identityReadResult
                    ?: if (identitySymlink || (legacyIdentity != null && identityStatLine != "600 0")) {
                        SuExecResult(0, "MAPLESU_RK_UNSAFE")
                    } else {
                        SuExecResult(0, legacyIdentity?.let { "$identityStatLine\n$it" } ?: "MAPLESU_RK_ABSENT")
                    }

                else -> readResult
                    ?: if (fileSymlink || (file != null && statLine != "600 0")) {
                        SuExecResult(0, "MAPLESU_RK_UNSAFE")
                    } else if (file == null) {
                        SuExecResult(0, "MAPLESU_RK_ABSENT")
                    } else {
                        SuExecResult(0, "$statLine\n${file.orEmpty()}")
                    }
            }
        }
    }

    @Test
    fun restoreUsesSavedIdentityAfterSigningIdentityChanges() {
        val oldId = "0123456789abcdef"
        val root = FakeRoot(
            file = UltraRecoveryKey.seal(key, oldId, pkg),
            legacyIdentity = RecoveryIdentity.of(oldId, pkg, 10_123)!!.toJson(),
        )

        val restored = UltraRecoveryKeyStore.restore(root, "fedcba9876543210", pkg)

        assertEquals(UltraRecoveryKeyStore.REASON_OK, restored.reason)
        assertEquals(key, restored.key)
    }

    @Test
    fun newBackupRemainsRestorableAfterSigningIdentityChanges() {
        val root = FakeRoot()
        assertTrue(UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid).ok)

        assertEquals(key, UltraRecoveryKeyStore.restore(root, "fedcba9876543210", pkg).key)
        assertEquals(RecoveryIdentity.of(androidId, pkg, uid), RecoveryIdentity.parse(root.legacyIdentity))
    }

    @Test
    fun backupPreservesBothFilesWhenSavedIdentityIsForeignOrMalformed() {
        val identities = listOf(
            RecoveryIdentity.of(androidId, "dev.maplesu.other", uid)!!.toJson(),
            "{broken-identity}",
        )
        for (savedIdentity in identities) {
            val original = UltraRecoveryKey.seal(key, "fedcba9876543210", pkg)
            val root = FakeRoot(file = original, legacyIdentity = savedIdentity)

            assertFalse(UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid).ok)
            assertEquals(original, root.file)
            assertEquals(savedIdentity, root.legacyIdentity)
            assertTrue(root.scripts.none { it.contains("printf %s") })
        }
    }

    @Test
    fun backupPreservesBothFilesWhenExistingPermissionsOrLinksAreUnsafe() {
        val unsafeStates: List<(FakeRoot) -> Unit> = listOf(
            { it.statLine = "644 0" },
            { it.identityStatLine = "600 2000" },
            { it.directoryStatLine = "755 0" },
            { it.fileSymlink = true },
            { it.identitySymlink = true },
            { it.directorySymlink = true },
        )
        for (makeUnsafe in unsafeStates) {
            val original = UltraRecoveryKey.seal(key, androidId, pkg)
            val identity = RecoveryIdentity.of(androidId, pkg, uid)!!.toJson()
            val root = FakeRoot(file = original, legacyIdentity = identity)
            makeUnsafe(root)

            val outcome = UltraRecoveryKeyStore.backup(root, key, "fedcba9876543210", pkg, uid)

            assertEquals(UltraRecoveryKeyStore.REASON_MODE_UNVERIFIED, outcome.reason)
            assertEquals(original, root.file)
            assertEquals(identity, root.legacyIdentity)
            assertTrue(root.scripts.none { it.contains("printf %s") })
        }
    }

    @Test
    fun restoreRejectsMalformedForeignOrUnmatchedSavedIdentity() {
        val oldId = "fedcba9876543210"
        val payload = UltraRecoveryKey.seal(key, oldId, pkg)
        val badIdentities = listOf(
            "{broken-identity}",
            RecoveryIdentity.of(oldId, "dev.maplesu.other", uid)!!.toJson(),
            RecoveryIdentity.of(androidId, pkg, uid)!!.toJson(),
        )
        for (identity in badIdentities) {
            val root = FakeRoot(file = payload, legacyIdentity = identity)
            assertEquals(
                UltraRecoveryKeyStore.REASON_DECRYPT_FAILED,
                UltraRecoveryKeyStore.restore(root, androidId, pkg).reason,
            )
        }
    }

    @Test
    fun restoreDoesNotReadIdentityWhenLegacyPayloadMatchesCurrentId() {
        val root = FakeRoot(file = UltraRecoveryKey.seal(key, androidId, pkg))

        assertEquals(key, UltraRecoveryKeyStore.restore(root, androidId, pkg).key)
        assertTrue(root.scripts.none { it.contains("/recovery/identity.json") })
    }

    @Test
    fun restoreRejectsUnsafeBackupAndUnreadableIdentity() {
        val payload = UltraRecoveryKey.seal(key, "fedcba9876543210", pkg)
        val root = FakeRoot(file = payload, statLine = "644 0")
        assertEquals(
            UltraRecoveryKeyStore.REASON_MODE_UNVERIFIED,
            UltraRecoveryKeyStore.restore(root, androidId, pkg).reason,
        )
        val unreadable = FakeRoot(
            file = payload,
            identityReadResult = SuExecResult(-1, "", failure = "START_FAILED"),
        )
        assertEquals(
            UltraRecoveryKeyStore.REASON_DECRYPT_FAILED,
            UltraRecoveryKeyStore.restore(unreadable, androidId, pkg).reason,
        )
    }

    @Test
    fun backupRejectsIncompleteIdentityBeforeRunningRoot() {
        val root = FakeRoot()
        assertEquals(
            UltraRecoveryKeyStore.REASON_IDENTITY_INVALID,
            UltraRecoveryKeyStore.backup(root, key, androidId, pkg, -1).reason,
        )
        assertTrue(root.scripts.isEmpty())
    }

    @Test
    fun backupRejectsFailedExitEvenWithSuccessMarkers() {
        val root = FakeRoot(writeOutput = "MAPLESU_RK_WROTE\n600 0\nMAPLESU_RK_IDENTITY_WROTE\n600 0")

        assertEquals(
            UltraRecoveryKeyStore.REASON_WRITE_FAILED,
            UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid).reason,
        )
    }

    @Test
    fun backupWritesBase64PayloadAndVerifies0600Root() {
        val root = FakeRoot()
        val outcome = UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid)

        assertTrue(outcome.ok)
        assertEquals(UltraRecoveryKeyStore.REASON_OK, outcome.reason)
        assertEquals("/data/adb/maplesu/recovery/rootkey", UltraRecoveryKeyStore.PATH)

        val written = root.file
        assertTrue("backup payload must be present", written != null)
        // 落盘内容必须是 base64 单行（不是明文 key），且能解回同一个 key。
        assertFalse(written!!.contains(key))
        assertTrue(UltraRecoveryKey.looksLikeRecoveryPayload(written))
        assertEquals(key, UltraRecoveryKey.open(written, androidId, pkg))

        val writeScript = root.scripts.last { it.contains("printf %s") && it.contains(UltraRecoveryKeyStore.PATH) }
        assertTrue(writeScript.contains("chmod 600"))
        assertTrue(writeScript.contains("/data/adb/maplesu/recovery/rootkey"))
        // 写脚本必须自带权限回读（stat 或 ls），否则 MODE_UNVERIFIED 永远成立。
        assertTrue(writeScript.contains("stat -c") || writeScript.contains("ls -ln"))
    }

    @Test
    fun backupRejectsMalformedKeyWithoutRunningRoot() {
        listOf(null, "", "short", "A".repeat(47), "A".repeat(49), "A".repeat(47) + " ").forEach { bad ->
            val root = FakeRoot()
            val outcome = UltraRecoveryKeyStore.backup(root, bad, androidId, pkg, uid)
            assertFalse("key='$bad' must be rejected", outcome.ok)
            assertEquals(UltraRecoveryKeyStore.REASON_KEY_INVALID, outcome.reason)
            assertTrue("no root script for invalid key", root.scripts.isEmpty())
        }
    }

    @Test
    fun backupIsIdempotentForSameKey() {
        val root = FakeRoot()
        val first = UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid)
        assertEquals(UltraRecoveryKeyStore.REASON_OK, first.reason)
        val scriptsAfterFirst = root.scripts.size

        val second = UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid)
        assertTrue(second.ok)
        assertTrue(second.skipped)
        assertEquals(UltraRecoveryKeyStore.REASON_ALREADY, second.reason)
        // 第二次只检查两份现有文件，不重写。
        assertEquals(scriptsAfterFirst + 2, root.scripts.size)
        assertEquals(1, root.scripts.count { it.contains("printf %s") })
    }

    @Test
    fun backupRewritesWhenExistingPayloadIsForeign() {
        val root = FakeRoot(file = "someone-elses-file")
        val outcome = UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid)

        assertTrue(outcome.ok)
        assertFalse(outcome.skipped)
        assertEquals(1, root.scripts.count { it.contains("printf %s") })
        assertEquals(key, UltraRecoveryKey.open(root.file, androidId, pkg))
    }

    @Test
    fun backupRejectsUnsafeStagedPermissionsWithoutPublishingFiles() {
        val root = FakeRoot(statLine = "644 0")
        val outcome = UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid)

        assertFalse(outcome.ok)
        assertEquals(UltraRecoveryKeyStore.REASON_MODE_UNVERIFIED, outcome.reason)
        // 临时文件权限不合格时不发布任何文件。
        assertNull(root.file)
        assertNull(root.legacyIdentity)
    }

    @Test
    fun backupReportsWriteFailure() {
        val outcome = UltraRecoveryKeyStore.backup(
            FakeRoot(writeOutput = ""),
            key,
            androidId,
            pkg,
            uid,
        )
        assertFalse(outcome.ok)
        assertEquals(UltraRecoveryKeyStore.REASON_WRITE_FAILED, outcome.reason)
    }

    @Test
    fun backupReportsMissingRootChannel() {
        val outcome = UltraRecoveryKeyStore.backup(
            RootScriptRunner { null },
            key,
            androidId,
            pkg,
            uid,
        )
        assertFalse(outcome.ok)
        assertEquals(UltraRecoveryKeyStore.REASON_NO_ROOT, outcome.reason)
    }

    @Test
    fun restoreReadsBackWhatBackupWrote() {
        val root = FakeRoot()
        assertEquals(
            UltraRecoveryKeyStore.REASON_OK,
            UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid).reason,
        )

        val restored = UltraRecoveryKeyStore.restore(root, androidId, pkg)
        assertTrue(restored.ok)
        assertEquals(UltraRecoveryKeyStore.REASON_OK, restored.reason)
        assertEquals(key, restored.key)
    }

    @Test
    fun restoreDistinguishesAbsentFromForeignFiles() {
        assertEquals(
            UltraRecoveryKeyStore.REASON_ABSENT,
            UltraRecoveryKeyStore.restore(FakeRoot(file = null), androidId, pkg).reason,
        )
        // 空文件 = 存在但不是我们的格式（不能报 ABSENT，也不能猜 key）。
        assertEquals(
            UltraRecoveryKeyStore.REASON_NOT_OURS,
            UltraRecoveryKeyStore.restore(FakeRoot(file = ""), androidId, pkg).reason,
        )
        assertEquals(
            UltraRecoveryKeyStore.REASON_NOT_OURS,
            UltraRecoveryKeyStore.restore(FakeRoot(file = "hello world"), androidId, pkg).reason,
        )
    }

    @Test
    fun restoreRejectsUnreadableChannelAndUnreadableFile() {
        // 通道级失败（exec 异常）不能被当成「没有备份」。
        assertEquals(
            UltraRecoveryKeyStore.REASON_UNREADABLE,
            UltraRecoveryKeyStore.restore(
                FakeRoot(readResult = SuExecResult(-1, "", failure = "START_FAILED")),
                androidId,
                pkg,
            ).reason,
        )
        assertEquals(
            UltraRecoveryKeyStore.REASON_UNREADABLE,
            UltraRecoveryKeyStore.restore(
                FakeRoot(readResult = SuExecResult(0, "MAPLESU_RK_UNREADABLE")),
                androidId,
                pkg,
            ).reason,
        )
        assertEquals(
            UltraRecoveryKeyStore.REASON_UNREADABLE,
            UltraRecoveryKeyStore.restore(
                FakeRoot(readResult = SuExecResult(-1, "", timedOut = true)),
                androidId,
                pkg,
            ).reason,
        )
    }

    @Test
    fun legacyBackupWithoutIdentityRejectsChangedAndroidIdOrPackage() {
        val root = FakeRoot(file = UltraRecoveryKey.seal(key, androidId, pkg))

        assertEquals(
            UltraRecoveryKeyStore.REASON_DECRYPT_FAILED,
            UltraRecoveryKeyStore.restore(root, "another-android-id", pkg).reason,
        )
        assertEquals(
            UltraRecoveryKeyStore.REASON_DECRYPT_FAILED,
            UltraRecoveryKeyStore.restore(root, androidId, "dev.maplesu.other").reason,
        )
    }

    @Test
    fun restoreRejectsTamperedPayload() {
        val root = FakeRoot()
        UltraRecoveryKeyStore.backup(root, key, androidId, pkg, uid)
        val raw = Base64.getDecoder().decode(root.file)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
        root.file = Base64.getEncoder().encodeToString(raw)

        val restored = UltraRecoveryKeyStore.restore(root, androidId, pkg)
        assertFalse(restored.ok)
        assertEquals(UltraRecoveryKeyStore.REASON_DECRYPT_FAILED, restored.reason)
    }

    @Test
    fun restoreValidatesRecoveredKeyFormat() {
        // 备份层只接受 48 字符 key（seal 与 open 双重校验，恢复时不会拿半成品）。
        assertNull(UltraRecoveryKey.seal("too-short", androidId, pkg))
        assertNull(UltraRecoveryKey.seal("A".repeat(49), androidId, pkg))
        assertNull(UltraRecoveryKey.open(UltraRecoveryKey.seal(key, androidId, pkg), androidId, pkg + "x"))
    }

    @Test
    fun permissionParserAcceptsStatAndLsFormats() {
        assertEquals(true, UltraRecoveryKeyStore.parsePermissions("MAPLESU_RK_WROTE\n600 0"))
        assertEquals(false, UltraRecoveryKeyStore.parsePermissions("644 0"))
        assertEquals(false, UltraRecoveryKeyStore.parsePermissions("600 2000"))
        assertEquals(
            true,
            UltraRecoveryKeyStore.parsePermissions(
                "-rw------- 1 0 0 128 2026-10-30 12:00 /data/adb/maplesu/recovery/rootkey",
            ),
        )
        assertEquals(
            false,
            UltraRecoveryKeyStore.parsePermissions(
                "-rw-r--r-- 1 0 0 128 2026-10-30 12:00 /data/adb/maplesu/recovery/rootkey",
            ),
        )
        assertNull(UltraRecoveryKeyStore.parsePermissions(null))
        assertNull(UltraRecoveryKeyStore.parsePermissions("no permissions here"))
    }
}

/** 备份格式与 AES-GCM 往返（纯 JVM）。 */
class UltraRecoveryKeyTest {

    private val key = "Zz9".repeat(16)

    @Test
    fun sealOpenRoundTrip() {
        val sealed = UltraRecoveryKey.seal(key, "android", "dev.maplesu.manager")
        assertTrue(sealed != null)
        assertFalse(sealed!!.contains(key))
        assertEquals(key, UltraRecoveryKey.open(sealed, "android", "dev.maplesu.manager"))
    }

    @Test
    fun nonceMakesCiphertextUnique() {
        val a = UltraRecoveryKey.seal(key, "android", "pkg")
        val b = UltraRecoveryKey.seal(key, "android", "pkg")
        assertNotEquals(a, b)
        assertEquals(key, UltraRecoveryKey.open(a, "android", "pkg"))
        assertEquals(key, UltraRecoveryKey.open(b, "android", "pkg"))
    }

    @Test
    fun keyFormatRequires48PrintableAscii() {
        assertTrue(UltraRecoveryKey.isValidKeyFormat(key))
        assertFalse(UltraRecoveryKey.isValidKeyFormat(null))
        assertFalse(UltraRecoveryKey.isValidKeyFormat(""))
        assertFalse(UltraRecoveryKey.isValidKeyFormat(key.dropLast(1)))
        assertFalse(UltraRecoveryKey.isValidKeyFormat(key + "A"))
        assertFalse(UltraRecoveryKey.isValidKeyFormat(key.dropLast(1) + " "))
        assertFalse(UltraRecoveryKey.isValidKeyFormat("A".repeat(47) + "\u00e9"))
    }

    @Test
    fun openRejectsGarbageAndWrongHeader() {
        assertNull(UltraRecoveryKey.open(null, "android", "pkg"))
        assertNull(UltraRecoveryKey.open("", "android", "pkg"))
        assertNull(UltraRecoveryKey.open("not-base64!!!", "android", "pkg"))
        assertNull(UltraRecoveryKey.open("aGVsbG8=", "android", "pkg"))
        assertFalse(UltraRecoveryKey.looksLikeRecoveryPayload("aGVsbG8="))
        assertFalse(UltraRecoveryKey.looksLikeRecoveryPayload(null))
    }

    @Test
    fun openRejectsTruncatedPayload() {
        val sealed = UltraRecoveryKey.seal(key, "android", "pkg")!!
        assertNull(UltraRecoveryKey.open(sealed.take(sealed.length / 2), "android", "pkg"))
    }
}
