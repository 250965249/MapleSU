package dev.maplesu.manager.jailbreak

import android.os.Build
import android.system.ErrnoException
import android.system.Os
import com.maplesu.core.ui.util.resolveDeviceName
import java.io.File
import java.io.IOException

/**
 * Ordinary App reads only; no SU, installer, provider or ADB dependency.
 *
 * The model name is resolved the same way the rest of the manager does it
 * (`resolveDeviceName`, vendor market-name property first). It is an observation
 * used for display and attempt logs; it never decides admission or profile
 * selection - the exact `uname -r` does that.
 */
object JailbreakDeviceProbe {
    fun collect(): JailbreakTarget = JailbreakTarget(
        androidRelease = Build.VERSION.RELEASE,
        sdk = Build.VERSION.SDK_INT,
        kernelRelease = try { Os.uname().release } catch (_: ErrnoException) { "unknown" },
        abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty(),
        manufacturer = Build.MANUFACTURER,
        soc = Build.SOC_MODEL,
        fingerprint = Build.FINGERPRINT,
        // The measured-target table binds the exact build, which includes the
        // security patch; omitting it here made a measured device read as
        // TARGET_NOT_VERIFIED in the real UI as well.
        securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
        bootId = read("/proc/sys/kernel/random/boot_id"),
        selinuxState = when (read("/sys/fs/selinux/enforce")) {
            "1" -> "Enforcing"
            "0" -> "Permissive"
            else -> "unknown"
        },
        model = runCatching { resolveDeviceName() }.getOrNull().orEmpty()
            .ifBlank { Build.MODEL.orEmpty() },
        device = Build.DEVICE.orEmpty(),
    )

    private fun read(path: String): String = try {
        File(path).readText().trim().ifBlank { "unknown" }
    } catch (_: IOException) {
        "unknown"
    } catch (_: SecurityException) {
        "unknown"
    }
}
