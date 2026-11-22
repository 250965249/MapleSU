package dev.maplesu.manager.jailbreak

import android.content.Context
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * S13 / DEV-41: a request-less prepare must never replace a live jailbreak executor
 * with a normal-mode one, and it must fail closed when there is no executor at all.
 *
 * This lives in its own class on purpose: calling `NativeSuDirectory.prepare` inside
 * the full Attempt test destabilised that instrumentation (DEV-41), so the guard is
 * verified from a process that never ran an attempt.
 */
class NormalModeGuardAndroidTest {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun requestlessPrepareFailsClosedInsteadOfOpeningTheNormalPath() {
        val outcome = runCatching { dev.maplesu.manager.runtime.NativeSuDirectory.prepare(context) }
        val error = outcome.exceptionOrNull()
        val binder = outcome.getOrNull()
        val markers = File("/dev").list()?.filter { it.startsWith("dfm") } ?: emptyList()
        // Either a live endpoint is reused, or the refusal is explicit. What must not
        // happen is a silent normal-mode executor and leftover provider markers.
        assertTrue("prepare must reuse an endpoint or refuse explicitly, got error=$error binder=$binder",
            binder != null || (error != null && error.message.orEmpty().startsWith("SU_DIRECTORY_")))
        assertTrue("no provider marker may be left behind: $markers", markers.isEmpty())
    }
}
