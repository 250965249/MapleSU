package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 01 §8.1 `MoveSetTest`：NEVER_MOVE、校验、路径可逆、执行顺序、跨挂载、动态项。 */
class MoveSetTest {
    @Test
    fun neverMoveContainsControlRoot() {
        assertTrue(MoveSet.NEVER_MOVE.contains(MoveSet.CONTROL_ROOT))
        assertTrue(MoveSet.NEVER_MOVE.contains(MoveSet.ADB_ROOT))
        assertTrue(MoveSet.isNeverMove(MoveSet.CONTROL_ROOT))
        assertTrue(MoveSet.isNeverMove("/data/adb/maplesu-workmode/modes/A/data"))
        assertFalse(MoveSet.isNeverMove("/data/adb/maplesu"))
        assertTrue(MoveSet.isNeverMove("/data/adb/modules"))
    }

    /** M5：installer 锁目录永不搬移，且它的父条目必须被识别为"要保留子树"。 */
    @Test
    fun installerLockSubtreeIsNeverMovedButItsParentStillMovable() {
        assertTrue(MoveSet.NEVER_MOVE.contains(MoveSet.INSTALLER_ROOT))
        assertTrue(MoveSet.isNeverMove(MoveSet.INSTALLER_ROOT))
        assertTrue(MoveSet.isNeverMove("${MoveSet.INSTALLER_ROOT}/lock/pid"))
        // 父条目本身仍可搬（只是要降级成合并搬移）。
        assertFalse(MoveSet.isNeverMove("/data/adb/maplesu"))
        assertEquals(
            listOf(MoveSet.INSTALLER_ROOT, MoveSet.HIDDEN_STATE, MoveSet.NORMAL_RECOVERY_TOKEN, MoveSet.RECOVERY_ROOT, "/data/adb/maplesu/ultra-identity"),
            MoveSet.preservedPathsUnder("/data/adb/maplesu"),
        )
        // 其它条目没有受保护后代 ⇒ 走常规整树搬移。
        assertTrue(MoveSet.preservedPathsUnder("/data/adb/modules").isEmpty())
        assertTrue(MoveSet.preservedPathsUnder("/data/adb/maplesu-su-policy").isEmpty())
        // ADB_ROOT 是所有条目的父目录，但它是精确匹配的受保护路径，不会把整表判成非法。
        assertTrue(MoveSet.validate(MoveSet.LITE_MOVE_SET, emptyMap()).isEmpty())
        assertTrue(MoveSet.validate(MoveSet.KSU_MOVE_SET, emptyMap()).isEmpty())
    }

    @Test
    fun ultraEnvironmentIdentityRemainsLiveAcrossBothModeSwitchDirections() {
        val path = "/data/adb/maplesu/ultra-identity"
        assertTrue(MoveSet.isNeverMove(path))
        assertTrue(MoveSet.isNeverMove("$path/identity.json"))
        assertTrue(MoveSet.isNeverMove("$path/pairing.apk"))
        assertTrue(MoveSet.preservedPathsUnder("/data/adb/maplesu").contains(path))
        for (mode in WorkMode.entries) {
            val plan = MoveSet.plan("identity", mode, WorkMode.entries.first { it != mode })
            assertTrue(plan.outbound.none { it.livePath == path })
            assertTrue(plan.inbound.none { it.livePath == path })
        }
    }

    @Test
    fun validateRejectsControlRoot() {
        val plan = listOf(
            MoveEntry(
                MoveSet.CONTROL_ROOT, MoveKind.TREE, MoveMount.SAME_AS_STORE,
                WorkMode.LITE, MoveEntry.REAL_DIR,
            ),
        )
        assertTrue(MoveSet.validate(plan, emptyMap()).any { it.startsWith(MoveSet.Errors.FORBIDDEN_PATH) })
    }

    @Test
    fun validateRejectsDuplicateLivePath() {
        val entry = MoveEntry("/data/adb/maplesu", MoveKind.TREE, MoveMount.SAME_AS_STORE, WorkMode.LITE, MoveEntry.REAL_DIR)
        val errors = MoveSet.validate(listOf(entry, entry), emptyMap())
        assertTrue(errors.any { it.startsWith(MoveSet.Errors.DUPLICATE_PATH) })
    }

    @Test
    fun validateRejectsOwnerMismatch() {
        val entry = MoveEntry(
            "/data/adb/modules", MoveKind.TREE, MoveMount.SAME_AS_STORE, WorkMode.LITE, MoveEntry.SYMLINK_TREE,
        )
        val errors = MoveSet.validate(listOf(entry), mapOf("/data/adb/modules" to WorkMode.KSU))
        assertTrue(errors.any { it.startsWith(MoveSet.Errors.OWNER_CONFLICT) })
    }

    @Test
    fun validateRejectsMetadataEntryWithoutCrossMountCopy() {
        val entry = MoveEntry(
            "/metadata/vold/ksu", MoveKind.TREE, MoveMount.SAME_AS_STORE, WorkMode.KSU, MoveEntry.ABSENT,
        )
        val errors = MoveSet.validate(listOf(entry), emptyMap())
        assertTrue(errors.any { it.startsWith(MoveSet.Errors.EXDEV_UNSUPPORTED) })
    }

    @Test
    fun standardMoveSetsValidateClean() {
        assertEquals(emptyList<String>(), MoveSet.validate(MoveSet.LITE_MOVE_SET, emptyMap()))
        assertEquals(emptyList<String>(), MoveSet.validate(MoveSet.KSU_MOVE_SET, emptyMap()))
    }

    @Test
    fun storePathRoundTrip() {
        for (mode in WorkMode.entries) {
            for (entry in MoveSet.moveSetFor(mode)) {
                val store = MoveSet.storePathFor(mode, entry.livePath)
                assertEquals(entry.livePath, MoveSet.livePathFor(store))
            }
        }
        assertEquals(
            "/data/adb/maplesu-workmode/modes/A/data/data/adb/maplesu",
            MoveSet.storePathFor(WorkMode.LITE, "/data/adb/maplesu"),
        )
    }

    @Test
    fun storePathRejectsTraversal() {
        for (bad in listOf(
            "/data/adb/maplesu-workmode/modes/A/data/../../etc/passwd",
            "/data/adb/maplesu-workmode/modes/A/data/data/adb/../../evil",
            "/sdcard/Download/whatever",
            "/data/adb/maplesu-workmode/modes/C/data/data/adb/x",
        )) {
            try {
                MoveSet.livePathFor(bad)
                throw AssertionError("accepted invalid store path: $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
    }

    @Test
    fun orderIsInverseForOutbound() {
        val legacy = listOf(MoveSet.ORDER_MODULES, MoveSet.ORDER_MODULES_UPDATE, MoveSet.ORDER_METAMODULE).map {
            MoveEntry(it, MoveKind.TREE, MoveMount.SAME_AS_STORE, WorkMode.KSU, MoveEntry.REAL_DIR)
        }
        val inbound = MoveSet.inboundOrder(legacy)
        val outbound = MoveSet.outboundOrder(legacy)
        assertEquals(inbound.reversed(), outbound)
        // 入：modules 实体先于 metamodule 指针。
        assertTrue(inbound.indexOfFirst { it.livePath == MoveSet.ORDER_MODULES } <
            inbound.indexOfFirst { it.livePath == MoveSet.ORDER_METAMODULE })
        assertTrue(inbound.indexOfFirst { it.livePath == MoveSet.ORDER_MODULES_UPDATE } <
            inbound.indexOfFirst { it.livePath == MoveSet.ORDER_METAMODULE })
        // 出：先移指针再移实体（逆序）。
        assertTrue(outbound.indexOfFirst { it.livePath == MoveSet.ORDER_METAMODULE } <
            outbound.indexOfFirst { it.livePath == MoveSet.ORDER_MODULES })
        assertTrue(outbound.indexOfFirst { it.livePath == MoveSet.ORDER_MODULES_UPDATE } <
            outbound.indexOfFirst { it.livePath == MoveSet.ORDER_MODULES })
    }

    @Test
    fun crossMountEntriesAreCopy() {
        val metadataEntries = MoveSet.KSU_MOVE_SET.filter { it.livePath.startsWith("/metadata/") }
        assertTrue(metadataEntries.isNotEmpty())
        assertTrue(metadataEntries.all { it.mount == MoveMount.CROSS_MOUNT_COPY })
        assertTrue(MoveSet.LITE_MOVE_SET.none { it.livePath.startsWith("/metadata/") })
    }

    @Test
    fun dynamicCredentialDirAppended() {
        val dynamic = MoveSet.dynamicEntries(
            credentialDirectories = listOf("/data/0123456789abcdef"),
            ultraDirectories = listOf("/data/fedcba9876543210"),
            registeredExternal = listOf("/data/adb/tricky_store"),
        )
        assertEquals(3, dynamic.size)
        assertTrue(dynamic.all { it.owner == WorkMode.LITE && it.expectedShape == MoveEntry.REAL_DIR })
        val plan = MoveSet.plan(
            switchId = "sw-1", from = WorkMode.LITE, to = WorkMode.KSU,
            dynamicFrom = dynamic,
        )
        assertTrue(plan.outbound.any { it.livePath == "/data/0123456789abcdef" })
        assertTrue(MoveSet.validate(plan.outbound, emptyMap()).isEmpty())
        assertTrue(MoveSet.validate(plan.inbound, emptyMap()).isEmpty())
    }

    @Test
    fun planUsesCorrectOwnersAndDirections() {
        val plan = MoveSet.plan(switchId = "sw-2", from = WorkMode.KSU, to = WorkMode.LITE)
        assertTrue(plan.outbound.all { it.owner == WorkMode.KSU })
        assertTrue(plan.inbound.all { it.owner == WorkMode.LITE })
        assertEquals("sw-2", plan.switchId)
        assertEquals(MoveSet.outboundOrder(MoveSet.KSU_MOVE_SET), plan.outbound)
        assertEquals(MoveSet.inboundOrder(MoveSet.LITE_MOVE_SET), plan.inbound)
    }
}
