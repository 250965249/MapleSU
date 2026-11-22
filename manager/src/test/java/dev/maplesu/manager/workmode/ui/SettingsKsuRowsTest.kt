package dev.maplesu.manager.workmode.ui

import dev.maplesu.manager.workmode.ModeCapabilities
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** W15 六项 KSU 设置行可见性。 */
class SettingsKsuRowsTest {

    @Test
    fun liteShowsNoKsuRows() {
        assertEquals(emptyList<KsuRowId>(), visibleKsuRows(ModeCapabilities.forMode(WorkMode.LITE)))
    }

    @Test
    fun unresolvedShowsNoKsuRows() {
        assertEquals(emptyList<KsuRowId>(), visibleKsuRows(ModeCapabilities.NONE))
    }

    @Test
    fun ksuShowsAllSixRowsInFixedOrder() {
        val rows = visibleKsuRows(ModeCapabilities.forMode(WorkMode.KSU))
        assertEquals(
            listOf(
                KsuRowId.KERNEL_UMOUNT,
                KsuRowId.SELINUX_HIDE,
                KsuRowId.SULOG,
                KsuRowId.ADB_ROOT,
                KsuRowId.SHELL_SU_ADB_ONLY,
                KsuRowId.UMOUNT_MODULES_DEFAULT,
            ),
            rows,
        )
        assertEquals(6, rows.size)
    }

    @Test
    fun umountDefaultFollowsKernelUmountCapability() {
        val withoutUmount = ModeCapabilities.forMode(WorkMode.KSU).copy(supportsKernelUmount = false)
        assertTrue(KsuRowId.UMOUNT_MODULES_DEFAULT !in visibleKsuRows(withoutUmount))
    }
}
