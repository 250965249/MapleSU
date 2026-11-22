package dev.maplesu.manager.runtime.authorization

import android.content.ContextWrapper
import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

class ManagerAuthorizationDefaultsAndroidTest {
    @Test fun firstUseEnablesServiceButRequiresExplicitApplicationGrant() = withStore { context ->
        val policy = fixturePolicy(context)
        assertTrue(policy.isEnabled)
        assertFalse(policy.hasCurrentGrant(Process.myUid()))
        val error = assertThrows(SecurityException::class.java) {
            policy.authorizeAndStart(Process.myUid()) { fail("Ungrant application was started") }
        }
        assertEquals("AUTH_NOT_GRANTED", error.message)
    }

    @Test fun reopeningRetainsExplicitGlobalDisableEvenWithAGrant() = withStore { context ->
        val policy = fixturePolicy(context)
        policy.setEnabled(false)
        policy.grant(Process.myUid())
        val reopened = fixturePolicy(context)
        assertFalse(reopened.isEnabled)
        assertTrue(reopened.hasCurrentGrant(Process.myUid()))
        val error = assertThrows(SecurityException::class.java) {
            reopened.authorizeAndStart(Process.myUid()) { fail("Disabled service started an application") }
        }
        assertEquals("AUTH_DISABLED", error.message)
    }

    private fun fixturePolicy(context: ContextWrapper): AuthorizationPolicy {
        val file = File(context.noBackupFilesDir, "authorizations.bin")
        val first = !file.exists()
        return AuthorizationPolicy(file.toPath(), AndroidApplicationIdentities(context)).also {
            if (first) it.setEnabled(true)
        }
    }

    private fun withStore(action: (ContextWrapper) -> Unit) {
        val real = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = Files.createTempDirectory(real.filesDir.toPath(), "manager-auth-defaults-").toFile()
        val context = object : ContextWrapper(real) {
            override fun getNoBackupFilesDir(): File = directory
        }
        try { action(context) } finally { assertTrue(directory.deleteRecursively()) }
    }
}
