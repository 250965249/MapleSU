package com.maplesu.core.ui.webui

import org.junit.runner.JUnitCore
import org.junit.runner.Request

/** Replays named failures without repeating already green cases. */
fun main(names: Array<String>) {
    require(names.isNotEmpty())
    var failed = 0
    for (name in names) {
        val result = JUnitCore().run(Request.method(WebUiRetirementJvmTest::class.java, name))
        println("$name: runs=${result.runCount}, failures=${result.failureCount}")
        result.failures.forEach { println(it.trace) }
        failed += result.failureCount
    }
    check(failed == 0) { "$failed selected retirement regression(s) failed" }
}
