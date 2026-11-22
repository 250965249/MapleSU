package dev.maplesu.manager.jailbreak

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/**
 * The pre-entry baseline the App hands to the kernel helper (step-4 D2, design §2.1).
 *
 * <p>**Why this file has to exist.** The module is dispatched *after* dfroot already
 * wrote `0` into `/sys/fs/selinux/enforce`, so the value it can read (and passes on as
 * `--entry-enforcing`) is an inherited `0`, not the device's entry state. The helper
 * therefore cannot learn the restore target from the kernel side, and the App cannot
 * read selinuxfs either (an ordinary App gets `EACCES`, recorded in R3 as
 * `enforcingBefore=-1`). What the App *can* do is state a **target plus its
 * provenance**, which is exactly what the consumer's
 * `RestoreOrigin{Observed,Baseline,Unknown,Provider}` has done on the lease route since
 * step-2 (`kBaselineEnforcing = '1'`).
 *
 * <p>**The format is frozen** (one line, space separated, fixed key order, ≤ 192 bytes,
 * optional trailing newline):
 *
 * ```
 * schema=maplesu.hook.env.v1 boot=<boot_id> attempt=<attemptId> expected=<0|1|-1> source=<observed|baseline|unknown>
 * ```
 *
 * <p>**Residual risk (design §2.1.4, accepted).** The file carries no authentication:
 * the App owns the directory and could ask for `expected=0 source=observed`, leaving the
 * device permissive until the next boot. It gains no capability it did not already have
 * (it controls the staged `<CE>/bs` the module execs), and it cannot reach
 * `DAEMON_READY` that way because F1 requires `restoreEnforcing == 1`. The window is
 * transient - no policy is written, no boot state changes - so a reboot clears it.
 *
 * <p>**Pure decision, host-testable.** [decide] and [line] contain no Android call, so
 * `HookEnvDecideTest`/`HookEnvFileTest` pin the exact bytes before the one device run.
 */
object HookEnv {
    const val FILE = "maplesu-hook-env"
    const val SCHEMA = "maplesu.hook.env.v1"

    /** The maximum the helper accepts (`MAPLESU_HOOK_ENV_MAX`). */
    const val MAX_BYTES = 192

    const val SOURCE_OBSERVED = "observed"
    const val SOURCE_BASELINE = "baseline"
    const val SOURCE_UNKNOWN = "unknown"

    data class Decision(val expected: Int, val source: String)

    /**
     * The whole decision, and it is deliberately this small:
     *
     *  - a real reading wins (`observed`) - it is the only case where this device's own
     *    value is known;
     *  - otherwise the documented baseline applies, *except* on a device that booted
     *    permissive: there the baseline is `0`, because "restore" must never move a
     *    device away from the state it booted in (the same rule the consumer applies).
     */
    fun decide(observed: Int, bootProperty: String?): Decision = when {
        observed == 0 || observed == 1 -> Decision(observed, SOURCE_OBSERVED)
        bootProperty.equals("permissive", ignoreCase = true) ->
            Decision(0, SOURCE_BASELINE)
        else -> Decision(1, SOURCE_BASELINE)
    }

    /** `ro.boot.selinux`, or null when the hidden-API reflection is refused (R-D5). */
    fun bootProperty(name: String): String? = runCatching {
        val clazz = Class.forName("android.os.SystemProperties")
        val get = clazz.getMethod("get", String::class.java)
        (get.invoke(null, name) as? String)?.takeIf { it.isNotEmpty() }
    }.getOrNull()

    /** The frozen line, without the trailing newline (so tests can compare exactly). */
    fun line(attemptId: String, bootId: String, decision: Decision): String =
        "schema=$SCHEMA boot=$bootId attempt=$attemptId " +
            "expected=${decision.expected} source=${decision.source}"

    /**
     * Writes the env for one attempt. Atomic (staging file + rename) and `0600`, because
     * the helper's `fstat` rejects anything else: it requires `(mode & 0077) == 0`,
     * `st_nlink == 1`, `st_uid == <attempt directory owner>` and a size in `(0,192]`.
     *
     * @return false when the file could not be written; the caller must fail closed -
     *         an attempt without an env has no target, and a target guessed by the
     *         helper could leave the device permissive.
     */
    @JvmStatic
    fun write(directory: File, attemptId: String, bootId: String, observed: Int): Boolean {
        val decision = decide(observed, bootProperty("ro.boot.selinux"))
        val text = line(attemptId, bootId, decision) + "\n"
        if (text.toByteArray(Charsets.UTF_8).size > MAX_BYTES) return false
        val target = File(directory, FILE)
        val staging = File(directory, "$FILE.new")
        return runCatching {
            if (!directory.isDirectory && !directory.mkdirs()) return false
            staging.writeText(text, Charsets.UTF_8)
            runCatching {
                Files.setPosixFilePermissions(staging.toPath(),
                    PosixFilePermissions.fromString("rw-------"))
            }
            Files.move(staging.toPath(), target.toPath(),
                StandardCopyOption.REPLACE_EXISTING)
            runCatching {
                Files.setPosixFilePermissions(target.toPath(),
                    PosixFilePermissions.fromString("rw-------"))
            }
            true
        }.getOrElse {
            runCatching { staging.delete() }
            false
        }
    }

    /** The staged file's permissions the helper will check (`(mode & 0077) == 0`). */
    fun permissionsOk(file: File): Boolean = runCatching {
        val permissions: Set<PosixFilePermission> =
            Files.getPosixFilePermissions(file.toPath())
        val forbidden = setOf(PosixFilePermission.GROUP_READ,
            PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE,
            PosixFilePermission.OTHERS_EXECUTE)
        permissions.none { it in forbidden }
    }.getOrDefault(false)
}
