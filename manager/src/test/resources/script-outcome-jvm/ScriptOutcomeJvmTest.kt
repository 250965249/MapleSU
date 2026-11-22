package scriptoutcomefixture

import com.maplesu.core.ui.util.projectScriptInstall
import dev.maplesu.manager.modules.LiteScriptModuleBackend as Backend
import dev.maplesu.manager.runtime.ultra.UltraOutcome
import org.junit.Assert.*
import org.junit.Test

class ScriptOutcomeJvmTest {
    private fun verify(result: Backend.InstallResult, expected: UltraOutcome?) {
        Backend.next = result
        Backend.calls = 0
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        val actual = projectScriptInstall(stdout::add, stderr::add)
        assertEquals(result.code, actual.code)
        assertEquals(result.needsReboot, actual.showReboot)
        assertEquals(expected, actual.moduleOutcome)
        assertEquals("", actual.err)
        assertEquals(listOf("raw out\nsecond line", ""), stdout)
        assertEquals(listOf("FIRST_ERROR:75\nraw diagnostic", ""), stderr)
        assertEquals("A submitted installation is never replayed", 1, Backend.calls)
    }

    @Test fun unknownCommitKeepsTheOriginalCodeAndProjectsPending() =
        verify(Backend.InstallResult(75, false, commitUnknown = true), UltraOutcome.NEEDS_RECONCILIATION)

    @Test fun confirmedSuccessKeepsRebootAndLegacySuccessProjection() =
        verify(Backend.InstallResult(0, true, rootCommitted = true), null)

    @Test fun confirmedFailureKeepsItsActualExitCode() =
        verify(Backend.InstallResult(13, false), null)

    @Test fun exit75AloneDoesNotInventAnUnknownCommit() =
        verify(Backend.InstallResult(75, false), null)
}
