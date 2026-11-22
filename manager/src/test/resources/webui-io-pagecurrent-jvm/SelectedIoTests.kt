package com.maplesu.core.ui.webui

import com.maplesu.core.ui.util.RootShellFixture
import org.junit.runner.Description
import org.junit.runner.JUnitCore
import org.junit.runner.Request
import org.junit.runner.manipulation.Filter
import kotlin.system.exitProcess

fun main() {
    val methods = setOf(
        "retiredPageRejectsRetainedHandlesBeforeDestroyWithoutAffectingAnotherPage",
        "retiredPageClosesAnInFlightInputWithoutReturningItsHandle",
        "retiredPageClosesAnInFlightOutputWithoutReturningItsHandle",
        "retiredPageRejectsItsInjectedShellFactoryBeforeDestroy",
        "retiredPageClosesAnInFlightInjectedShellWithoutReturningAFile",
    )
    val request = Request.aClass(WebUiIoLifecycleTest::class.java).filterWith(object : Filter() {
        override fun describe() = "New pageCurrent IO cases only"
        override fun shouldRun(description: Description): Boolean =
            if (description.isTest) description.methodName in methods
            else description.children.any { shouldRun(it) }
    })
    val result = JUnitCore().run(request)
    result.failures.forEach { println(it.trace) }
    println("selected=${methods.size} run=${result.runCount} failures=${result.failureCount} rootShellCalls=${RootShellFixture.calls.get()}")
    exitProcess(if (result.wasSuccessful() && result.runCount == methods.size && RootShellFixture.calls.get() == 0) 0 else 1)
}
