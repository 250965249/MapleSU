package com.topjohnwu.superuser.io

class SuFile(path: String) : java.io.File(path) { fun setShell(shell: com.topjohnwu.superuser.Shell) {} }
object SuFileInputStream {
    val opens = java.util.concurrent.atomic.AtomicInteger()
    val closes = java.util.concurrent.atomic.AtomicInteger()
    var openGate: (() -> Unit)? = null
    @JvmStatic fun open(file: SuFile): java.io.InputStream {
        opens.incrementAndGet()
        openGate?.invoke()
        return object : java.io.FilterInputStream(file.inputStream()) {
            override fun close() { closes.incrementAndGet(); super.close() }
        }
    }
}
