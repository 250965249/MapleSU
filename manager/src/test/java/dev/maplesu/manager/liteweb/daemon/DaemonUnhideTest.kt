package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.litehidden.ParasitePaths
import dev.maplesu.manager.litehidden.HostManifestCodec
import dev.maplesu.manager.litehidden.HostManifest
import dev.maplesu.manager.litehidden.HostBackupFile
import dev.maplesu.manager.liteweb.LiteHiddenPort
import dev.maplesu.manager.liteweb.LiteHiddenResult
import dev.maplesu.manager.liteweb.LiteWebRestoreStep
import dev.maplesu.manager.liteweb.LiteWebUnhideCodes
import dev.maplesu.manager.liteweb.LiteWebUnhidePort
import dev.maplesu.manager.liteweb.LiteWebUnhideSteps
import dev.maplesu.manager.liteweb.LiteWebUnhideTransaction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * daemon 侧「完整解除寄生」：四步顺序、失败即停、不回滚已完成步骤、停 daemon 必须最后一步。
 *
 * 这里用 fake root 脚本执行器，不碰真机 `/data/adb`，也不执行任何真实 shell。
 *
 * 另外锁住 2026-10-31 真机 D2 的修法：无清单历史目录可隔离；已有清单却损坏或缺原始库时
 * 保留恢复服务，完整备份必须覆盖清单全部记录。
 */
class DaemonUnhideTest {
    private val host = "com.example.host"
    private val other = "com.example.other"

    /** `host/<pkg>` 的一个目录事实（默认是「完整备份」）。 */
    private data class Dir(
        val name: String,
        val marker: Boolean = true,
        val manifestBytes: Long = 512,
        val manifestEntries: Int = 3,
        val origs: Int = 3,
    ) {
        val complete: Boolean get() = manifestBytes > 0 && manifestEntries >= 1 && origs >= manifestEntries

        val fact: String
            get() = "PARASITE_BK|$name|${if (marker) 1 else 0}|$manifestBytes|$manifestEntries|$origs"
    }

    private inner class FakeShell {
        val scripts = mutableListOf<String>()
        var dirs = listOf(Dir(host))
        var listFails = false
        var restoreOk = true
        var loaderGone = true
        var quarantineOk = true
        var identityGone = true
        var archiveMovesComplete = true
        var originalBackupOk = true
        var corruptOriginalHost: String? = null
        var restoredTargetsOk = true

        fun run(script: String): DaemonShellResult {
            scripts += script
            val target = dirs.firstOrNull { script.contains("/host/${it.name}/") ||
                script.contains("/host/${it.name}'") }?.name ?: host
            val originalsOk = originalBackupOk && target != corruptOriginalHost
            return when {
                script.contains("MAPLESU_RESTORE_ORIGINALS_OK") -> DaemonShellResult(
                    if (originalsOk) 0 else 1, if (originalsOk) "MAPLESU_RESTORE_ORIGINALS_OK" else "",
                )
                script.contains("MAPLESU_RESTORE_TARGETS_OK") -> DaemonShellResult(
                    if (restoredTargetsOk) 0 else 1, if (restoredTargetsOk) "MAPLESU_RESTORE_TARGETS_OK" else "",
                )
                script.contains("PARASITE_BK|") -> if (listFails) {
                    DaemonShellResult(1, "")
                } else {
                    DaemonShellResult(0, dirs.joinToString("\n") { it.fact })
                }
                script.contains("libdir.txt") ->
                    DaemonShellResult(0, "/data/app/~~x==/$target-1/lib/arm64\n")
                script.contains("label.txt") ->
                    DaemonShellResult(0, "u:object_r:apk_data_file:s0\n")
                script.contains("cat '") && script.contains("host.manifest") -> DaemonShellResult(0, HostManifestCodec.encode(
                    HostManifest(target, "/data/app/~~x==/$target-1/lib/arm64", "u:object_r:apk_data_file:s0",
                        ParasitePaths.LOADER_NAME, "b".repeat(64),
                        listOf(HostBackupFile("liba.so", "a".repeat(64), "c".repeat(64), "755", 1000, 1000))),
                ))
                script.contains("PARASITE_RESTORE_OK") -> if (restoreOk) {
                    DaemonShellResult(0, "PARASITE_RESTORED name=liba.so sha=${"a".repeat(64)}\nPARASITE_RESTORE_OK count=1")
                } else {
                    DaemonShellResult(45, "PARASITE_FAIL code=RESTORE_RENAME detail=liba.so")
                }
                script.contains("PARASITE_LOADER_GONE") -> if (loaderGone) {
                    DaemonShellResult(0, "PARASITE_LOADER_GONE")
                } else {
                    DaemonShellResult(60, "PARASITE_FAIL code=LOADER_DELETE_FAILED")
                }
                script.contains("PARASITE_QUARANTINED") -> if (quarantineOk) {
                    val restoredArchive = script.contains("host-quarantine-restored-")
                    val count = if (restoredArchive) dirs.count { it.complete } else dirs.count { !it.complete }
                    if (restoredArchive && archiveMovesComplete) dirs = dirs.filterNot { it.complete }
                    DaemonShellResult(
                        0,
                        "PARASITE_QUARANTINED n=$count;dir=" +
                            "${ParasitePaths.RECOVERY}/host-quarantine-20261101",
                    )
                } else {
                    DaemonShellResult(71, "PARASITE_FAIL code=QUARANTINE_MOVE detail=$host")
                }
                script.contains("MAPLESU_IDENTITY_GONE") -> if (identityGone) {
                    DaemonShellResult(0, "MAPLESU_IDENTITY_GONE")
                } else {
                    DaemonShellResult(86, "PARASITE_FAIL code=IDENTITY_DELETE_FAILED")
                }
                else -> DaemonShellResult(0, "")
            }
        }
    }

    private class FakeHidden(var value: Boolean = true) : LiteHiddenPort {
        var writes = mutableListOf<Boolean>()
        var failWrite = false
        override fun currentHidden(): Boolean? = value
        override fun setHidden(hidden: Boolean, level: String?): LiteHiddenResult {
            writes.add(hidden)
            if (failWrite) return LiteHiddenResult.Failed(LiteWebUnhideCodes.HIDDEN_STATE_OFF_FAILED, "write")
            value = hidden
            return LiteHiddenResult.Ok(hidden)
        }
    }

    private fun port(
        shell: FakeShell = FakeShell(),
        hidden: FakeHidden = FakeHidden(),
        revoke: (String) -> DaemonRevokeResult = { DaemonRevokeResult(true, detail = "sdk=ok") },
        selfStop: () -> Boolean = { true },
        stopCalls: MutableList<String> = mutableListOf(),
    ): DaemonParasiteUnhide = DaemonParasiteUnhide(
        shell = { script -> shell.run(script) },
        hiddenState = hidden,
        revokeSuAuth = { pkg -> stopCalls += "revoke:$pkg"; revoke(pkg) },
        selfStop = { stopCalls += "selfStop"; selfStop() },
        quarantineStamp = { "20261101" },
    )

    // ── 四步契约 ──────────────────────────────────────────────────────────

    @Test
    fun successfulRestoreArchivesActiveBackupAndVerifiesItLeftTheGuardTree() {
        val shell = FakeShell()
        val hidden = FakeHidden(false)
        val step = port(shell = shell, hidden = hidden).archiveRestoredBackups()
        assertTrue(step.toString(), step.ok)
        assertTrue(shell.dirs.isEmpty())
        assertTrue(shell.scripts.any { it.contains("host-quarantine-restored-20261101") })
    }

    @Test
    fun archiveFailureKeepsBackupAndDoesNotPretendSuccess() {
        val shell = FakeShell().apply { quarantineOk = false }
        val step = port(shell = shell, hidden = FakeHidden(false)).archiveRestoredBackups()
        assertFalse(step.ok)
        assertEquals(1, shell.dirs.size)
    }

    @Test
    fun archiveRefusesToMoveBackupsBeforeHiddenIsOff() {
        val shell = FakeShell()
        val step = port(shell = shell, hidden = FakeHidden(true)).archiveRestoredBackups()
        assertFalse(step.ok)
        assertTrue(shell.scripts.isEmpty())
    }

    @Test
    fun archiveSuccessMarkerMustAgreeWithActiveBackupReadback() {
        val shell = FakeShell().apply { archiveMovesComplete = false }
        val step = port(shell = shell, hidden = FakeHidden(false)).archiveRestoredBackups()
        assertFalse(step.ok)
        assertEquals(1, shell.dirs.size)
    }

    @Test
    fun missingOrCorruptOriginalBlocksAnyHostWriteAndKeepsRecovery() {
        val shell = FakeShell().apply { originalBackupOk = false }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()
        assertFalse(steps.last().ok)
        assertTrue(calls.isEmpty())
        assertFalse(shell.scripts.any { it.contains("PARASITE_RESTORE_OK") })
    }

    @Test
    fun incompleteRestorationNeverRevokesOrStopsRecovery() {
        val shell = FakeShell().apply { restoredTargetsOk = false }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()
        assertFalse(steps.last().ok)
        assertTrue(calls.isEmpty())
        assertEquals(1, shell.dirs.size)
    }

    @Test
    fun deactivateRunsFourStepsInOrderWithDaemonStopLast() {
        val shell = FakeShell()
        val hidden = FakeHidden()
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, hidden = hidden, stopCalls = calls).deactivate()

        // 只有一个完整备份、没有陈旧残留 → 不出现 advisory 步。
        assertEquals(LiteWebUnhideSteps.ORDER, steps.map { it.name })
        assertTrue(steps.joinToString { "${it.name}:${it.ok}:${it.error}" }, steps.all { it.ok })
        assertEquals("停 daemon 必须是最后一步且只发生一次", 1, calls.count { it == "selfStop" })
        assertEquals("selfStop", calls.last())
        assertEquals(listOf(false), hidden.writes)
        assertEquals(false, hidden.currentHidden())
        assertTrue("必须真的跑过宿主库还原脚本", shell.scripts.any { it.contains("PARASITE_RESTORE_OK") })
        assertTrue("必须真的删/复核 loader", shell.scripts.any { it.contains("PARASITE_LOADER_GONE") })
        assertTrue(
            "解除成功后必须清理身份材料（否则下一次激活前它一直留在 root 目录里）",
            shell.scripts.any { it.contains("MAPLESU_IDENTITY_GONE") },
        )
    }

    @Test
    fun revokeFailureStopsBeforeDaemonAndKeepsCompletedSteps() {
        val hidden = FakeHidden()
        val calls = mutableListOf<String>()
        val shell = FakeShell()
        val steps = port(
            shell = shell,
            hidden = hidden,
            revoke = { DaemonRevokeResult(false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, "still_listed") },
            stopCalls = calls,
        ).deactivate()

        assertEquals(
            listOf(LiteWebUnhideSteps.RESTORE_HOST_SO, LiteWebUnhideSteps.REMOVE_LOADER, LiteWebUnhideSteps.REVOKE_SU_AUTH),
            steps.map { it.name },
        )
        assertTrue("前两步已完成，不能回滚", steps[0].ok && steps[1].ok)
        assertFalse(steps[2].ok)
        assertEquals(LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, steps[2].error)
        assertFalse("boot retry must survive a failed revoke", shell.scripts.any { it.contains("rm -f '${ParasitePaths.START_SCRIPT}'") })
        assertFalse("撤销失败绝不能杀 daemon（否则用户连重试入口都没了）", calls.contains("selfStop"))
        assertEquals("隐藏位不能在停 daemon 之前被单独改掉", emptyList<Boolean>(), hidden.writes)
        assertFalse(
            "撤销失败必须保留身份材料（重试还要用它解 rootkey）",
            shell.scripts.any { it.contains("MAPLESU_IDENTITY_GONE") },
        )
    }

    @Test
    fun restoreFailureStopsImmediatelyAndDoesNotTouchLoader() {
        val shell = FakeShell().apply { restoreOk = false }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()

        assertEquals(listOf(LiteWebUnhideSteps.RESTORE_HOST_SO), steps.map { it.name })
        assertFalse(steps[0].ok)
        assertEquals(LiteWebUnhideCodes.RESTORE_HOST_SO_FAILED, steps[0].error)
        assertFalse(steps[0].error.isEmpty())
        assertFalse(calls.contains("revoke:$host"))
        assertFalse(calls.contains("selfStop"))
        assertFalse("还原失败时不能跑 loader 删除脚本", shell.scripts.any { it.contains("PARASITE_LOADER_GONE") })
    }

    @Test
    fun loaderStillPresentFailsAndKeepsDaemonAlive() {
        val shell = FakeShell().apply { loaderGone = false }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()

        assertEquals(
            listOf(LiteWebUnhideSteps.RESTORE_HOST_SO, LiteWebUnhideSteps.REMOVE_LOADER),
            steps.map { it.name },
        )
        assertTrue(steps[0].ok)
        assertFalse(steps[1].ok)
        assertEquals(LiteWebUnhideCodes.LOADER_DELETE_FAILED, steps[1].error)
        assertFalse(calls.contains("selfStop"))
    }

    @Test
    fun missingBackupIsIdempotentSuccess() {
        val shell = FakeShell().apply { dirs = emptyList() }
        val hidden = FakeHidden(value = false)
        val steps = port(shell = shell, hidden = hidden).deactivate()

        assertEquals(LiteWebUnhideSteps.ORDER, steps.map { it.name })
        assertTrue(steps.all { it.ok })
        assertEquals("no_backup", steps[0].detail)
        assertEquals(listOf(false), hidden.writes)
    }

    @Test
    fun backupListFailureFailsRestoreStep() {
        val shell = FakeShell().apply { listFails = true }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()

        assertEquals(listOf(LiteWebUnhideSteps.RESTORE_HOST_SO), steps.map { it.name })
        assertFalse(steps[0].ok)
        assertEquals(LiteWebUnhideCodes.RESTORE_HOST_SO_FAILED, steps[0].error)
        assertTrue(steps[0].detail.contains("backup_list_failed"))
        assertFalse(calls.contains("selfStop"))
    }

    // ── 多宿主恢复：每份清单只还原自己的目录 ────────────────────────────────

    @Test
    fun multipleCompleteBackupsRestoreAndRevokeEveryHostBeforeStopping() {
        val shell = FakeShell().apply { dirs = listOf(Dir(host), Dir(other)) }
        val calls = mutableListOf<String>()
        val unhide = port(shell = shell, stopCalls = calls)
        val steps = unhide.deactivate()

        assertEquals(LiteWebUnhideSteps.ORDER, steps.map { it.name })
        assertTrue(steps.toString(), steps.all { it.ok })
        assertEquals(listOf("revoke:$host", "revoke:$other", "selfStop"), calls)
        val restores = shell.scripts.filter { it.contains("PARASITE_RESTORE_OK") }
        assertEquals(2, restores.size)
        listOf(host, other).forEach { pkg ->
            assertTrue(restores.any { it.contains("D='") && it.contains("/host/$pkg'") &&
                it.contains("L='/data/app/~~x==/$pkg-1/lib/arm64'") })
        }
        assertTrue(unhide.archiveRestoredBackups().ok)
        assertTrue(shell.dirs.isEmpty())
    }

    @Test
    fun corruptSecondHostPreservesBothBackupsAndNeverStopsRecovery() {
        val shell = FakeShell().apply {
            dirs = listOf(Dir(host), Dir(other))
            corruptOriginalHost = other
        }
        val calls = mutableListOf<String>()
        val hidden = FakeHidden()
        val steps = port(shell = shell, hidden = hidden, stopCalls = calls).deactivate()
        assertFalse(steps.last().ok)
        assertEquals(LiteWebUnhideCodes.RESTORE_HOST_SO_FAILED, steps.last().error)
        assertTrue(calls.isEmpty())
        assertTrue(hidden.writes.isEmpty())
        assertEquals(2, shell.dirs.size)
    }

    @Test
    fun secondHostRevokeFailureCanRetryWithoutLosingRecovery() {
        val shell = FakeShell().apply { dirs = listOf(Dir(host), Dir(other)) }
        val hidden = FakeHidden()
        val calls = mutableListOf<String>()
        val failed = port(shell = shell, hidden = hidden, stopCalls = calls, revoke = { pkg ->
            if (pkg == other) DaemonRevokeResult(false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED)
            else DaemonRevokeResult(true)
        }).deactivate()
        assertFalse(failed.last().ok)
        assertEquals(LiteWebUnhideSteps.REVOKE_SU_AUTH, failed.last().name)
        assertFalse(calls.contains("selfStop"))
        assertTrue(hidden.writes.isEmpty())
        assertEquals(2, shell.dirs.size)
        calls.clear()
        val retry = port(shell = shell, hidden = hidden, stopCalls = calls)
        assertTrue(retry.deactivate().all { it.ok })
        assertEquals(listOf("revoke:$host", "revoke:$other", "selfStop"), calls)
        assertTrue(retry.archiveRestoredBackups().ok)
    }

    @Test
    fun oneCompletePlusOneStaleIsNotAmbiguous() {
        val shell = FakeShell().apply {
            dirs = listOf(Dir(host), Dir(other, marker = false, manifestBytes = 0, manifestEntries = 0, origs = 2))
        }
        val steps = port(shell = shell).deactivate()

        assertEquals(
            "advisory 步排在必须三步之后、停 daemon 之前（daemon 必须还活着才能做清理）",
            listOf(
                LiteWebUnhideSteps.RESTORE_HOST_SO,
                LiteWebUnhideSteps.REMOVE_LOADER,
                LiteWebUnhideSteps.REVOKE_SU_AUTH,
                LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS,
                LiteWebUnhideSteps.STOP_DAEMON,
            ),
            steps.map { it.name },
        )
        assertTrue(steps.joinToString { "${it.name}:${it.ok}:${it.error}" }, steps.all { it.ok })
        assertTrue("必须用唯一那个完整备份", steps[0].detail.contains("restored=1"))
    }

    // ── D2：陈旧残留不得阻塞解除 ──────────────────────────────────────────

    @Test
    fun zeroCompleteAndFourStaleDoesNotBlockUnhide() {
        // 真机现场：`host/` 下 4 个 10-30 遗留的半截目录（只有几个 .orig，无标记无清单）。
        val shell = FakeShell().apply {
            dirs = listOf(
                Dir(other, marker = false, manifestBytes = 0, manifestEntries = 0, origs = 2),
                Dir("a.b.c", marker = false, manifestBytes = 0, manifestEntries = 0, origs = 1),
                Dir("d.e.f", marker = false, manifestBytes = 0, manifestEntries = 0, origs = 1),
                Dir("g.h.i", marker = false, manifestBytes = 0, manifestEntries = 0, origs = 0),
            )
        }
        val hidden = FakeHidden()
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, hidden = hidden, stopCalls = calls).deactivate()

        assertEquals(
            "陈旧残留既不阻塞、也不能被当成恢复材料",
            listOf(
                LiteWebUnhideSteps.RESTORE_HOST_SO,
                LiteWebUnhideSteps.REMOVE_LOADER,
                LiteWebUnhideSteps.REVOKE_SU_AUTH,
                LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS,
                LiteWebUnhideSteps.STOP_DAEMON,
            ),
            steps.map { it.name },
        )
        assertTrue(steps.joinToString { "${it.name}:${it.ok}:${it.error}" }, steps.all { it.ok })
        assertEquals(LiteWebUnhideSteps.RESTORE_HOST_SO, steps[0].name)
        assertTrue("没有完整备份必须显式记 skipped：${steps[0].detail}", steps[0].detail.contains("skipped:no-complete-backup"))
        assertTrue(steps[0].detail.contains("stale=4"))
        assertFalse("没有完整备份就不是歧义", steps.any { it.error == LiteWebUnhideCodes.HOST_BACKUP_AMBIGUOUS })
        assertFalse("陈旧残留绝不能当恢复材料", shell.scripts.any { it.contains("PARASITE_RESTORE_OK") })
        assertEquals("解除仍然要停 daemon", "selfStop", calls.last())

        val quarantine = steps.first { it.name == LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS }
        assertTrue(quarantine.ok)
        assertTrue("隔离必须记数量与目录：${quarantine.detail}", quarantine.detail.contains("n=4"))
        assertTrue(quarantine.detail.contains("host-quarantine-20261101"))
        assertTrue(
            "隔离走 mv 改名，绝不 rm -rf（保留证据）",
            shell.scripts.any { it.contains("PARASITE_QUARANTINED") && it.contains("host-quarantine-20261101") },
        )
    }

    @Test
    fun corruptManifestBlocksUnhideAndPreservesRecovery() {
        val shell = FakeShell().apply {
            dirs = listOf(Dir(host, marker = true, manifestBytes = 4096, manifestEntries = 0, origs = 3))
        }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()

        assertEquals(1, steps.size)
        assertFalse(steps[0].ok)
        assertEquals(LiteWebUnhideSteps.RESTORE_HOST_SO, steps[0].name)
        assertEquals("original_backup_incomplete", steps[0].detail)
        assertFalse(shell.scripts.any { it.contains("PARASITE_RESTORE_OK") })
        assertTrue(calls.isEmpty())
    }

    @Test
    fun zeroOrigFilesWithManifestPreservesRecovery() {
        val shell = FakeShell().apply { dirs = listOf(Dir(host, manifestEntries = 3, origs = 0)) }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()

        assertEquals(1, steps.size)
        assertFalse(steps[0].ok)
        assertEquals("original_backup_incomplete", steps[0].detail)
        assertFalse("0 个 .orig 没有任何可写回的材料", shell.scripts.any { it.contains("PARASITE_RESTORE_OK") })
        assertTrue(calls.isEmpty())
    }

    @Test
    fun partiallyMissingOriginalsBlockBeforeHostMutation() {
        val shell = FakeShell().apply { dirs = listOf(Dir(host, manifestEntries = 3, origs = 2)) }
        val calls = mutableListOf<String>()
        val steps = port(shell = shell, stopCalls = calls).deactivate()
        assertEquals(1, steps.size)
        assertFalse(steps[0].ok)
        assertEquals("original_backup_incomplete", steps[0].detail)
        assertFalse(shell.scripts.any { it.contains("PARASITE_RESTORE_OK") })
        assertTrue(calls.isEmpty())
    }

    @Test
    fun quarantineFailureIsAdvisoryAndDoesNotFailUnhide() {
        val shell = FakeShell().apply {
            dirs = listOf(Dir("x.y.z", marker = false, manifestBytes = 0, manifestEntries = 0, origs = 1))
            quarantineOk = false
        }
        val hidden = FakeHidden()
        val steps = port(shell = shell, hidden = hidden).deactivate()

        val quarantine = steps.first { it.name == LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS }
        assertFalse("清理失败必须如实记 ok=false", quarantine.ok)
        assertEquals(LiteWebUnhideCodes.STALE_BACKUP_QUARANTINE_FAILED, quarantine.error)
        assertTrue("但停 daemon 仍要执行（用户已经解除成功）", hidden.currentHidden() == false)

        // 事务层：advisory 步失败不改写解除结论（否则又一次永久 409）。
        val result = LiteWebUnhideTransaction(LiteWebUnhidePort { steps }).run()
        assertTrue(
            "advisory 失败不能把解除结论改回 409：failedStep=${result.failedStep} code=${result.code}",
            result.ok,
        )
        assertEquals("", result.failedStep)
        assertEquals(5, result.steps.size)
    }

    @Test
    fun identityCleanupFailureDoesNotFakeUnhide() {
        val shell = FakeShell().apply { identityGone = false }
        val steps = port(shell = shell).deactivate()

        assertTrue("身份材料删不掉不影响解除结论（文件本身不是凭据）", steps.all { it.ok })
        assertTrue(shell.scripts.any { it.contains("MAPLESU_IDENTITY_GONE") })
    }

    // ── 隐藏位 / 自停 ────────────────────────────────────────────────────

    @Test
    fun hiddenStateWriteFailureFailsStopStepWithoutKillingDaemon() {
        val hidden = FakeHidden().apply { failWrite = true }
        val calls = mutableListOf<String>()
        val steps = port(hidden = hidden, stopCalls = calls).deactivate()

        assertEquals(LiteWebUnhideSteps.STOP_DAEMON, steps.last().name)
        assertFalse(steps.last().ok)
        assertEquals(LiteWebUnhideCodes.HIDDEN_STATE_OFF_FAILED, steps.last().error)
        assertFalse("隐藏位没写成功就不能退出 daemon", calls.contains("selfStop"))
    }

    @Test
    fun selfStopNotScheduledFailsTheStopStep() {
        val shell = FakeShell()
        val hidden = FakeHidden()
        val steps = port(shell = shell, hidden = hidden, selfStop = { false }).deactivate()

        assertEquals(LiteWebUnhideSteps.STOP_DAEMON, steps.last().name)
        assertFalse(steps.last().ok)
        assertEquals(LiteWebUnhideCodes.DAEMON_STOP_FAILED, steps.last().error)
        assertTrue(steps.last().detail.contains("exit_not_scheduled"))
        assertTrue("failed stop keeps the boot recovery gate active", hidden.value)
        assertFalse("没真的安排退出就不能清理身份材料", shell.scripts.any { it.contains("MAPLESU_IDENTITY_GONE") })
    }

    @Test
    fun hostBackupDirUsesParasitePaths() {
        // 备份根路径必须与 App 侧同源（否则 daemon 找错目录 = 永远"no_backup"却报成功）。
        val shell = FakeShell()
        port(shell = shell).deactivate()
        assertTrue(
            shell.scripts.any { it.contains(ParasitePaths.HOST_BACKUP_ROOT) },
        )
    }

    @Test
    fun selfStopScheduleArmsARealDelayedExit() {
        var halted: Int? = null
        assertTrue(DaemonSelfStop.schedule(delayMillis = 1L, halt = { code -> halted = code }))
        val deadline = System.currentTimeMillis() + 5_000L
        while (halted == null && System.currentTimeMillis() < deadline) Thread.sleep(10L)
        assertEquals(0, halted)
    }

    @Test
    fun advisoryStepIsNotInTheMandatoryOrder() {
        // ORDER 是「必须成功的四步」；advisory 步不在其内，事务才能不因清理失败而 409。
        assertFalse(LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS in LiteWebUnhideSteps.ORDER)
        assertTrue(LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS in LiteWebUnhideSteps.ADVISORY)
        assertNotEquals(0, LiteWebUnhideSteps.ORDER.size)
    }

    @Test
    fun mandatoryFailureStillFailsEvenWhenAdvisorySucceeded() {
        val steps = listOf(
            LiteWebRestoreStep(LiteWebUnhideSteps.RESTORE_HOST_SO, true),
            LiteWebRestoreStep(LiteWebUnhideSteps.CLEANUP_STALE_BACKUPS, true, detail = "n=2"),
            LiteWebRestoreStep(LiteWebUnhideSteps.REVOKE_SU_AUTH, false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, "x"),
        )
        val result = LiteWebUnhideTransaction(LiteWebUnhidePort { steps }).run()
        assertFalse(result.ok)
        assertEquals(LiteWebUnhideSteps.REVOKE_SU_AUTH, result.failedStep)
        assertTrue(result.retryable)
    }
}
