package dev.maplesu.manager.installer

import android.content.Context
import android.os.Looper
import android.util.Log
import com.topjohnwu.superuser.Shell
import dev.maplesu.manager.runtime.RootManagement
import dev.maplesu.manager.runtime.SuRootCandidates
import java.io.Closeable

internal data class InstallerBootTarget(
    val slotSuffix: String,
    val availablePartitions: Set<String> = setOf("boot"),
) {
    companion object {
        fun discoveryCommand(slot: String): String = InstallPartition.ALLOWED.joinToString("\n") { partition ->
            val path = InstallerSnapshotParser.partitionPath(partition.wire, slot)
            "if test -b $path; then echo ${partition.wire}; fi"
        }

        fun fromOutput(slot: String, output: String): InstallerBootTarget {
            val present = output.lineSequence().map(String::trim)
                .filter { it in InstallPartition.ALLOWED_WIRE }.toSet()
            check("boot" in present) { "INSTALLER_BLOCK_DEVICE_REQUIRED" }
            return InstallerBootTarget(slot, present)
        }
    }
}

/** Separate installation authority: verified MapleSU runtime, KSU native channel, or explicit su. */
internal class InstallerRootSession private constructor(
    private val shell: Shell,
    /** Which transport actually opened this session (EXPLICIT_SU when the legacy fallback ran). */
    val source: RootSource,
    /** Collected on-device kernel proof; evidence only, never a reason to refuse a write. */
    val kernelProof: KsuKernelProof = KsuKernelProof(0, 0),
) : Closeable {
    private var closed = false

    companion object {
        private const val TAG = "MapleSU/Installer"

        /**
         * Opens an installation shell: verify the runtime, then each explicit SU candidate.
         *
         * <p>User directive 2026-11-01: the on-device kernel proof is *collected* but never
         * refuses a write. A missing/unusable proof (the production stub reports version=0) only
         * means the KSU native channel is preferred but not proven; the session then falls back to
         * the MapleSU runtime channel and finally to an explicit `su` grant, because the user
         * already tapped "flash".
         *
         * @throws IllegalStateException INSTALLER_ROOT_REQUIRED when no transport is root at all
         */
        fun open(context: Context,
                 source: RootSource = RootSource.LITE_RUNTIME,
                 allowExplicitSuFallback: Boolean = true): InstallerRootSession {
            check(Looper.myLooper() != Looper.getMainLooper()) { "INSTALLER_BACKGROUND_THREAD_REQUIRED" }
            var actual = source
            val proof = if (source == RootSource.KSU_NATIVE) KernelProof.inService() else KsuKernelProof(0, 0)
            fun verified(open: () -> Shell): Shell? {
                val shell = runCatching(open).getOrNull() ?: return null
                return try {
                    check(shell.isRoot && shell.isAlive) { "INSTALLER_ROOT_REQUIRED" }
                    val uid = shell.newJob().add("id -u").to(ArrayList<String>(), ArrayList<String>()).exec()
                    check(uid.isSuccess) { "INSTALLER_ROOT_REQUIRED" }
                    InstallerSnapshotParser.requireRoot(uid.out.joinToString("\n").trim())
                    shell
                } catch (_: Exception) {
                    runCatching { shell.close() }
                    null
                }
            }
            fun explicitSu(): Shell {
                for (candidate in SuRootCandidates.all(context.applicationContext)) {
                    check(!Thread.currentThread().isInterrupted) { "INSTALLER_ROOT_INTERRUPTED" }
                    verified {
                        Shell.Builder.create().setContext(context.applicationContext).setTimeout(15)
                            .build(*candidate.argv.toTypedArray())
                    }?.let { return it }
                }
                error("INSTALLER_ROOT_REQUIRED")
            }
            fun runtime(): Shell? = verified { RootManagement.openShell(context.applicationContext) }
            val shell = when (source) {
                RootSource.KSU_NATIVE -> {
                    if (!proof.usable) {
                        // Evidence only: record the fact and keep going (no refusal).
                        Log.w(TAG, "KSU kernel proof unavailable (version=${proof.version} " +
                            "uapi=${proof.uapi}); falling back to another root transport")
                    }
                    val channel = InstallerRootSourceRegistry.channelOrNull()
                    val ksu = channel?.let { verified { it.openShell(context.applicationContext) } }
                    if (ksu != null) ksu else {
                        val lite = runtime()
                        if (lite != null) {
                            actual = RootSource.LITE_RUNTIME
                            lite
                        } else {
                            actual = RootSource.EXPLICIT_SU
                            explicitSu()
                        }
                    }
                }
                RootSource.LITE_RUNTIME -> runtime() ?: run {
                    check(allowExplicitSuFallback) { "SWITCH_ROOT_UNAVAILABLE" }
                    // This fallback authorizes installation only; it never marks MapleSU runtime ready.
                    actual = RootSource.EXPLICIT_SU
                    explicitSu()
                }
                RootSource.EXPLICIT_SU -> {
                    check(allowExplicitSuFallback) { "SWITCH_ROOT_UNAVAILABLE:EXPLICIT_SU_NOT_ALLOWED" }
                    explicitSu()
                }
            }
            try {
                check(shell.isRoot) { "INSTALLER_ROOT_REQUIRED" }
                return InstallerRootSession(shell, actual, proof).also {
                    InstallerSnapshotParser.requireRoot(it.read("id -u"))
                }
            } catch (error: Exception) {
                shell.close()
                throw error
            }
        }

        /**
         * Convenience for Mode-switch callers. `allowExplicitSuFallback` only affects the
         * `LITE_RUNTIME` transport; the `KSU_NATIVE` branch always degrades to another transport
         * instead of refusing (kernel proof is evidence, not a gate).
         */
        fun openForModeSwitch(context: Context, source: RootSource): InstallerRootSession =
            open(context, source, RootSourcePolicy.allowExplicitSuFallback(
                InstallerModeGate.WriteScope.MODE_SWITCH))
    }

    @Synchronized
    fun discoverBootTarget(): InstallerBootTarget {
        InstallerSnapshotParser.requireRoot(read("id -u"))
        val slot = InstallerSnapshotParser.slot(read("getprop ro.boot.slot_suffix"))
        return InstallerBootTarget.fromOutput(slot, read(InstallerBootTarget.discoveryCommand(slot)))
    }

    @Synchronized
    internal fun execute(command: String): Shell.Result {
        check(!closed && shell.isAlive && shell.isRoot) { "INSTALLER_SESSION_CLOSED" }
        return shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
    }

    @Synchronized
    fun snapshotCurrentBoot(): InstallerSnapshot {
        InstallerSnapshotParser.requireRoot(read("id -u"))
        val slot = InstallerSnapshotParser.slot(read("getprop ro.boot.slot_suffix"))
        val kernel = read("uname -r")
        val firmware = read("getprop ro.build.display.id")
        // Recorded as evidence only (2026-11-01): SELinux state never blocks a partition write.
        val selinux = read("getenforce").ifBlank { "Unknown" }
        val partitions = linkedMapOf<String, BootPartitionSnapshot>()
        for (name in InstallerSnapshotParser.partitionNames) {
            val path = InstallerSnapshotParser.partitionPath(name, slot)
            // Some supported layouts have no init_boot. boot and vbmeta remain mandatory here.
            val exists = shell.newJob().add("test -b $path").exec().isSuccess
            if (!exists && name == "init_boot") continue
            check(exists) { "INSTALLER_BLOCK_DEVICE_REQUIRED" }
            partitions[name] = InstallerSnapshotParser.partition(name, slot,
                read("readlink -f $path"), read("blockdev --getsize64 $path"), read("sha256sum $path"))
        }
        // Re-read identities and digests after the whole observation, catching concurrent changes.
        for ((name, original) in partitions) {
            val path = original.path
            val after = InstallerSnapshotParser.partition(name, slot,
                read("readlink -f $path"), read("blockdev --getsize64 $path"), read("sha256sum $path"))
            check(original == after) { "INSTALLER_PARTITION_CHANGED" }
        }
        check(read("getprop ro.boot.slot_suffix") == slot && read("uname -r") == kernel &&
            read("getprop ro.build.display.id") == firmware && read("getenforce") == selinux) {
            "INSTALLER_DEVICE_CHANGED"
        }
        return InstallerSnapshot(kernel, firmware, slot, selinux, partitions)
    }

    private fun read(command: String): String {
        check(!closed && shell.isAlive && shell.isRoot) { "INSTALLER_SESSION_CLOSED" }
        val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
        check(result.isSuccess) { "INSTALLER_READ_FAILED: $command" }
        return result.out.joinToString("\n").trim()
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            closed = true
            shell.close()
        }
    }
}
