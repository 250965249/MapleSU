package dev.maplesu.manager.jailbreak

internal fun jailbreakErrorCode(code: String): String =
    if (code.startsWith("MAPLESU_")) "MAPLESU_" + code.substring(7) else code
