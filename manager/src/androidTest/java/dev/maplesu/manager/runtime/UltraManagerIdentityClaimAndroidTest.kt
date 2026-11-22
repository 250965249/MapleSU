package dev.maplesu.manager.runtime

import android.os.Process
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import dev.maplesu.manager.runtime.ultra.UltraIdentityRecovery
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Selected after booting a candidate with the packaged manager claim carrier. */
class UltraManagerIdentityClaimAndroidTest {
    @Test fun keylessBridgeRecoversTheRunningKernelIdentityWithoutElevatingItsCaller() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("managerClaimKernel") == "true")
        val caller = Process.myUid()
        assertTrue(caller % 100_000 in 10_000..19_999)
        val keyless = UltraRuntimeClient { null }
        val recovered = requireNotNull(keyless.claimManagerIdentity()) { "Kernel identity reply absent" }
        assertTrue(UltraKernelCredential.isValid(recovered))
        assertTrue(UltraKernelCredential.of(recovered).sdkMetadataValid)
        assertTrue("Repeated kernel identity mismatch", recovered == keyless.claimManagerIdentity())
        assertEquals(0, UltraIdentityRecovery.uid(UltraRuntimeClient { recovered }))
        assertEquals(caller, Process.myUid())
    }
}
