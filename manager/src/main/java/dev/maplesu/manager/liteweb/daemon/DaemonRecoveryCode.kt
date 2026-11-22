package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.recovery.RecoveryPaths
import java.io.File

/** Removing /data/app must not delete a lazy-loaded class or the APK serving WebUI resources. */
object DaemonRecoveryCode {
    fun ready(
        classpath: String = System.getenv("CLASSPATH")?.takeIf { it.isNotBlank() }
            ?: System.getProperty("java.class.path").orEmpty(),
        recoveryApk: String = RecoveryPaths.APK,
    ): Boolean = runCatching {
        val paths = classpath.split(File.pathSeparatorChar).filter { it.isNotBlank() }
        paths.size == 1 && File(paths.single()).canonicalFile == File(recoveryApk).canonicalFile && File(recoveryApk).isFile
    }.getOrDefault(false)
}
