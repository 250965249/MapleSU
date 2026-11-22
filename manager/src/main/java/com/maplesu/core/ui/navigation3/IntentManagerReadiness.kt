package com.maplesu.core.ui.navigation3

/** Checks a validated user request against the current Manager identity. */
internal suspend fun awaitIntentManager(
    awaitEnvironment: suspend () -> Boolean,
    isManager: () -> Boolean,
): Boolean = awaitEnvironment() && isManager()
