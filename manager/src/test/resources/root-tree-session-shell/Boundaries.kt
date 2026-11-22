package dev.maplesu.manager.modules

/** Compile boundaries only; every generated command is executed by the shell fixture. */
data class ModuleScriptOutput(val code: Int, val out: String = "", val err: String = "") {
    val isSuccess: Boolean get() = code == 0
}

fun interface ModuleScriptRunner {
    fun run(script: String): ModuleScriptOutput
    fun readSnapshot(script: String): ModuleScriptOutput = run(script)
}

object ModuleTree { const val ROOT = "/data/adb/modules" }
