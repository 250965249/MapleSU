package com.maplesu.core.ui.screen.module

import com.maplesu.core.R
import dev.maplesu.manager.ksu.KsuModuleListMapper
import dev.maplesu.manager.modules.JsonModuleListParser
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ModulePreinitTest {
    @Test
    fun ksudPreinitDiagnosticsSurviveTheListPipelineAndOnlyAppearInNormal() {
        val warnings = mapOf(
            "no_space" to R.string.module_preinit_no_space,
            "error" to R.string.module_preinit_error,
            "bootloop" to R.string.module_preinit_bootloop,
            "unsupported" to R.string.module_preinit_unsupported,
            "ok" to null,
            "" to null,
            "unknown" to null,
        )
        for ((state, warning) in warnings) {
            val json = KsuModuleListMapper.toUiJson("""[{"id":"fixture","preinit":"$state"}]""")
            val module = JsonModuleListParser.parse(json).single()
            assertEquals(state, module.preinit)
            assertEquals(warning, module.preinitWarning(WorkMode.KSU))
            assertNull(module.preinitWarning(WorkMode.LITE))
            assertNull(module.preinitWarning(null))
        }
    }
}
