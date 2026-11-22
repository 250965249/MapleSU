package dev.maplesu.ghostlock.extract

import java.io.File

/** Produces a candidate document; the App still validates every required field. */
fun interface KernelImageExtractor {
    fun extract(input: ExtractInput.BootImageFile, workDir: File, onLog: (String) -> Unit): String
}
