package dev.maplesu.manager.modules

import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import org.junit.Assert.*
import org.junit.Test

class NativeModuleListFailureTest {
    private val unsafe = sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
        isAccessible = true
    }.get(null) as sun.misc.Unsafe

    private fun backend(): MapleSuModuleBackend {
        val client = unsafe.allocateInstance(UltraRuntimeClient::class.java) as UltraRuntimeClient
        UltraRuntimeClient::class.java.getDeclaredField("loadFailure").apply { isAccessible = true }
            .set(client, "HOST_BRIDGE_ABSENT")
        return (unsafe.allocateInstance(MapleSuModuleBackend::class.java) as MapleSuModuleBackend).also {
            MapleSuModuleBackend::class.java.getDeclaredField("client").apply { isAccessible = true }.set(it, client)
        }
    }

    @Test fun aRequiredNativeBackendFailureIsNotAnEmptyOrMissingList() {
        val failure = runCatching { backend().listItems(required = true) }.exceptionOrNull()
        assertNotNull("Required SDK failure was silently accepted", failure)
        assertTrue(failure!!.message.orEmpty().contains("MAPLESU_BRIDGE_UNAVAILABLE"))
    }

    @Test fun anOptionalNativeBackendStillSupportsScriptOnlyEnvironments() {
        assertNull(backend().listItems(required = false))
    }
}
