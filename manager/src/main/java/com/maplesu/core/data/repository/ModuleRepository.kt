package com.maplesu.core.data.repository

import com.maplesu.core.data.model.Module
import com.maplesu.core.data.model.ModuleUpdateInfo

interface ModuleRepository {
    suspend fun getModules(): Result<List<Module>>
    suspend fun checkUpdate(module: Module): Result<ModuleUpdateInfo>
}
