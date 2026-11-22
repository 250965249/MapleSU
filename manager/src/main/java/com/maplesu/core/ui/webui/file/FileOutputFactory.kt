package com.maplesu.core.ui.webui.file

import com.topjohnwu.superuser.io.SuFile
import java.io.OutputStream

internal fun openBoundOutputStream(file: SuFile, append: Boolean): OutputStream {
    if (!append) return file.newOutputStream(false)
    val appendFile = object : SuFile(file.path) {
        init {
            setShell(file.shell)
        }

        // libsu 6.0.0 clears even append streams; retain its device handling and FIFO writer.
        override fun clear(): Boolean = if (isFile) true else super.clear()
    }
    return appendFile.newOutputStream(true)
}
