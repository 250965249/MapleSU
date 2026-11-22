package com.maplesu.core.ui.webui

import com.maplesu.core.data.model.Module
import com.maplesu.core.data.repository.ModuleRepository
import dev.maplesu.manager.modules.ModuleEnvironmentWatch

internal suspend fun loadWebUiModules(repository: ModuleRepository): Result<List<Module>> {
    val waiting = ModuleEnvironmentWatch.facts().waitReason
    if (waiting != null && !ModuleEnvironmentWatch.awaitReady(waiting, 15_000L)) {
        return Result.failure(IllegalStateException("WEBUI_ENVIRONMENT_NOT_READY:${waiting.code}"))
    }
    return repository.getModules()
}
