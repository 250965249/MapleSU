package dev.maplesu.manager.workmode.service

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

class ModeSwitchRootLaunchWiringTest {
    @Test fun readinessUsesTheOfficialPersistentBinderThroughItsContext() {
        val path = "src/main/java/dev/maplesu/manager/workmode/service/ModeSwitchRootSession.kt"
        val source = listOf(File(path), File("manager/$path")).first { it.isFile }.readText()
        assertTrue("The session must bind the persistent official daemon through its Context",
            Regex("InstallerServiceClient\\.withService\\(\\s*(?:this\\.)?context\\s*,\\s*persistent\\s*=\\s*true").containsMatchIn(source))
        assertTrue("SELinux-blocked abstract socket connects must not remain on the production path",
            !source.contains("socket.connect("))
    }

    @Test fun appNeverSetsSocketOptionsAfterTheRootDescriptorHandoff() {
        val base = "src/main/java/dev/maplesu/manager/workmode/service/"
        fun source(name: String) = listOf(File(base + name), File("manager/$base$name"))
            .first { it.isFile }.readText()
        val session = source("ModeSwitchRootSession.kt")
        assertTrue("The app domain cannot set socket options on the root-owned descriptor",
            !session.contains("setsockopt") && !session.contains("setTimeout("))
        assertTrue("The chosen timeout must reach the root service before its descriptor is returned",
            session.contains("openModeSwitchRoot(it, timeoutMillis, identity)"))
        val bridge = source("ModeSwitchRootBridge.kt")
        assertTrue(bridge.contains("Os.setsockoptTimeval(pair[1].fileDescriptor"))
    }
}
