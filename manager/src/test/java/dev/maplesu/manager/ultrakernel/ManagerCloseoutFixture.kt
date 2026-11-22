package dev.maplesu.manager.ultrakernel

import dev.maplesu.manager.workmode.service.ClientStatusCarrierTest
import org.junit.runner.JUnitCore

/** Central host runner only; no module loading, Android or device calls. */
object ManagerCloseoutFixture {
    @JvmStatic fun main(args: Array<String>) {
        val result = JUnitCore.runClasses(UltraInitBootReceiptTest::class.java, ClientStatusCarrierTest::class.java)
        result.failures.forEach { System.err.println(it.trace) }
        check(result.wasSuccessful()) { "MANAGER_FIXTURES_FAILED:${result.failureCount}" }
        println("Manager focused JUnit: ${result.runCount} tests")
    }
}
