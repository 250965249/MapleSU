package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Measurement only: what does THIS kernel allow a Root user-space process to mount,
 * and is an overlay-based projection viable at all?
 *
 * This probe is the evidence behind the product decision that MapleSU has **no** mount
 * consumer: an earlier measurement taken inside `unshare -m` had to be repeated in the
 * initial namespace, because that is where a ksud-style userspace mount would run. Each
 * probe unmounts what it mounted in the same step; nothing is left mounted, no policy is
 * changed, and no result is asserted as a success (P1/P2/P3 are recorded verbatim).
 *
 * Opt-in: `-e verifyMapleSuBoot true`
 */
class OverlayProbeAndroidTest {

    @Test(timeout = 180_000) fun overlayOutsideNamespaceIsProbed() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val base = "/data/local/tmp/maplesu-overlay-probe"
        fun run(vararg commands: String): List<String> =
            MapleSuRuntime.openShell(context).use { shell ->
                val result = shell.newJob().add(*commands)
                    .to(ArrayList<String>(), ArrayList<String>()).exec()
                result.out + result.err.map { "ERR:$it" }
            }
        val out = run(
            "echo DOMAIN:$(cat /proc/self/attr/current | tr -d '\\0')",
            "echo UID:$(/system/bin/id -u):$(/system/bin/id -Z 2>/dev/null | head -1)",
            // Is KernelSU actually present (possibly hiding its kernel module)?
            "echo ADB_ROOT:$(/system/bin/ls /data/adb 2>&1 | tr '\\n' ',')",
            "echo KSU_BIN:$(/system/bin/ls /data/adb/ksu/bin 2>&1 | tr '\\n' ',')",
            "echo KSUD_VERSION:$(/data/adb/ksu/bin/ksud --version 2>&1 | head -1)",
            "echo MODULES:$(/system/bin/ls /data/adb/modules 2>&1 | tr '\\n' ',')",
            "echo MODULES_MOUNTED:$(/system/bin/grep -c ' /system ' /proc/mounts)",
            "rm -rf $base || true",
            "mkdir -p $base/lower $base/upper $base/work $base/merged $base/bindtarget || true",
            "printf probe > $base/lower/file || true",
            // 1) plain overlay, initial namespace (no unshare)
            "mount -t overlay overlay -o lowerdir=$base/lower,upperdir=$base/upper,workdir=$base/work $base/merged 2>$base/e1 && echo P1:ok || echo P1:fail:$(cat $base/e1 | tr '\\n' ' ')",
            "umount $base/merged 2>/dev/null || true",
            // 2) overlay with explicit userxattr (unprivileged-overlay variant)
            "mount -t overlay overlay -o userxattr,lowerdir=$base/lower,upperdir=$base/upper,workdir=$base/work $base/merged 2>$base/e2 && echo P2:ok || echo P2:fail:$(cat $base/e2 | tr '\\n' ' ')",
            "umount $base/merged 2>/dev/null || true",
            // 3) bind as control: known to work
            "mount --bind $base/lower/file $base/bindtarget 2>$base/e3 && echo P3:ok || echo P3:fail:$(cat $base/e3 | tr '\\n' ' ')",
            "umount $base/bindtarget 2>/dev/null || true",
            // cleanup
            "rm -rf $base || true",
            "echo PROBE_DONE")
        val text = out.joinToString("\n")
        println("MAPLESU_MOUNT_PROBE\n$text")
        assertTrue("probe must run to completion; output=$text", text.contains("PROBE_DONE"))
        // P1/P2/P3 are recorded, not asserted: this probe measures what the kernel allows.
        // Their results are already in the report; gating on them would make the suite
        // fail on a device property rather than on a code defect.
        // P1/P2 are recorded, not asserted: this test exists to measure, and a failing
        // overlay must not be reported as a pass.
    }
}
