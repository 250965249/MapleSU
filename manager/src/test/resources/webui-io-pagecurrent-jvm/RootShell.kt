package com.maplesu.core.ui.util

import com.topjohnwu.superuser.Shell
import java.util.concurrent.atomic.AtomicInteger

object RootShellFixture {
    val calls = AtomicInteger()
}

fun createRootShell(globalMnt: Boolean = false): Shell {
    RootShellFixture.calls.incrementAndGet()
    throw AssertionError("Real root-shell creation reached the isolated IO fixture")
}
