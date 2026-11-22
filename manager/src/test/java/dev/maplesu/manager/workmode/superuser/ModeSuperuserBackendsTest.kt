package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class ModeSuperuserBackendsTest {
    @Test fun ultraExportDoesNotRequireAnInactiveKsuKernel() = runBlocking {
        TestControl.create().use { control ->
            val ultra = FakeBackend(BackendId.A_ULTRA).apply { seed(Fixtures.identity()) }
            val inactiveKsu = FakeBackend(BackendId.B_KSU).apply { available = false }
            val sync = DefaultSuperuserSync(control.plane,
                modeSuperuserBackends(WorkMode.LITE, { ultra }, { inactiveKsu }), control.clock)
            val result = sync.exportBeforeSwitch(WorkMode.LITE, 0)
            assertTrue("Ultra export rejected its healthy source backend: $result", result is ExportResult.Ok)
            assertEquals(1, control.read().entries.size)
        }
    }

    @Test fun normalExportDoesNotInstantiateTheOtherModesRuntime() = runBlocking {
        TestControl.create().use { control ->
            val ksu = FakeBackend(BackendId.B_KSU).apply { seed(Fixtures.identity()) }
            val sync = DefaultSuperuserSync(control.plane, modeSuperuserBackends(WorkMode.KSU,
                { throw AssertionError("Normal must not load Direct/Ultra backend") }, { ksu }), control.clock)
            assertTrue(sync.exportBeforeSwitch(WorkMode.KSU, 0) is ExportResult.Ok)
        }
    }

    @Test fun unavailableSourceBackendStillBlocksWithoutReplacingSharedData() = runBlocking {
        TestControl.create().use { control ->
            val previous = control.write(Fixtures.shared(entries = listOf(Fixtures.intent())))
            val inactivePro = FakeBackend(BackendId.A_ULTRA).apply { available = false }
            val sync = DefaultSuperuserSync(control.plane, modeSuperuserBackends(WorkMode.LITE,
                { inactivePro }, { throw AssertionError("Inactive KSU must not be loaded") }), control.clock)
            assertEquals("SUPERUSER_BACKEND_UNAVAILABLE",
                (sync.exportBeforeSwitch(WorkMode.LITE, 0) as ExportResult.Blocked).code)
            assertEquals(previous, control.read())
        }
    }
}
