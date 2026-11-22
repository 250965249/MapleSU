package dev.maplesu.manager.liteweb.daemon

import java.io.File

/** UID 0 and nohup do not remove an inherited Android app cgroup. PM can still kill it. */
class DaemonProcessIsolation(
    private val membership: () -> String? = { File("/proc/self/cgroup").readText() },
    private val pid: () -> Int? = DaemonSelfStop::selfPid,
    private val move: (String, Int) -> Boolean = { path, process ->
        runCatching { File(path).writeText("$process\n"); true }.getOrDefault(false)
    },
) {
    fun ensure(): Boolean {
        var groups = runCatching(membership).getOrNull() ?: return false
        when (appOwned(groups)) {
            false -> return true
            null -> return false
            true -> Unit
        }
        val process = pid()?.takeIf { it > 1 } ?: return false
        for (target in ROOT_GROUPS) {
            runCatching { move(target, process) }
            groups = runCatching(membership).getOrNull() ?: return false
            if (appOwned(groups) == false) return true
        }
        return false
    }

    companion object {
        // Existing Android controller roots only. Never create groups or move another PID.
        private val ROOT_GROUPS = listOf(
            "/sys/fs/cgroup/cgroup.procs",
            "/sys/fs/cgroup/system/cgroup.procs",
            "/sys/fs/cgroup/system/uid_0/cgroup.procs",
            "/dev/memcg/apps/cgroup.procs",
            "/dev/memcg/cgroup.procs",
            "/dev/cpuctl/cgroup.procs",
            "/dev/cpuset/cgroup.procs",
            "/dev/stune/cgroup.procs",
            "/acct/cgroup.procs",
        )

        internal fun appOwned(text: String): Boolean? {
            val lines = text.lineSequence().filter(String::isNotBlank).toList()
            if (lines.isEmpty() || lines.any { !it.matches(Regex("[0-9]+:[^:]*:/[^\\r\\n]*")) }) return null
            return lines.any { line ->
                Regex("(?:^|/)uid_([0-9]+)(?=/|$)").findAll(line.substringAfter(':').substringAfter(':'))
                    .any { it.groupValues[1].toLongOrNull()?.let { uid -> uid >= 10_000 } != false }
            }
        }

        fun ensureIndependent(): Boolean = DaemonProcessIsolation().ensure()
    }
}
