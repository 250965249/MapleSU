package com.maplesu.core.ui

import android.app.Application
import androidx.test.internal.runner.lifecycle.ApplicationLifecycleMonitorImpl
import androidx.test.runner.lifecycle.ApplicationLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.ApplicationStage
import androidx.test.runner.AndroidJUnitRunner
import com.maplesu.core.KernelSUApplication
import com.maplesu.core.ksuApp

/** Selected by the UI/theme presentation test properties; presentation tests never bootstrap root. */
class PresentationTestRunner : AndroidJUnitRunner() {
    override fun callApplicationOnCreate(app: Application) {
        // Preserve AndroidX lifecycle notifications while skipping production Application.onCreate.
        val monitor = ApplicationLifecycleMonitorRegistry.getInstance() as ApplicationLifecycleMonitorImpl
        monitor.signalLifecycleChange(app, ApplicationStage.PRE_ON_CREATE)
        ksuApp = app as KernelSUApplication
        monitor.signalLifecycleChange(app, ApplicationStage.CREATED)
    }
}
