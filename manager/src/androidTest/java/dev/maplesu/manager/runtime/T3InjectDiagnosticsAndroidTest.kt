package dev.maplesu.manager.runtime

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * T3 diagnostics for PATH injection: the exact native verdicts, the domain the injection
 * runs in, and the process set it addresses.
 *
 * <p>Not an assertion test - it records facts. The interesting cases are a target that is
 * already running (the normal case) and a target that was just started (the race that
 * produced "no process" and "injection rejected" in earlier runs).
 */
class T3InjectDiagnosticsAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val target = "io.github.a13e300.ksuwebui"

    private fun shell(command: String): String =
        instrumentation.uiAutomation.executeShellCommand(command).use {
            ParcelFileDescriptor.AutoCloseInputStream(it).bufferedReader().readText()
        }

    private fun launch() = shell("monkey -p $target -c android.intent.category.LAUNCHER 1")

    @Test fun injectionVerdicts() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(target, 0).uid
        val original = DirectPolicy.hasGrantStrict(context, uid)
        DirectPolicy.grant(context, uid)
        SuPublication.publish(context)
        val directory = SuPublication.suDirectory(context)
        try {
            // The security context the injection actually runs in: the runtime is a child of
            // the manager, admits itself to uid 0, and keeps whatever domain it inherited.
            val identity = DirectRoot.run(context, "id; /system/bin/cat /proc/self/attr/current").output
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE t3_domain [${identity.trim()}]")
            // Whether this root identity may read another process at all: the capability
            // decides /proc/<pid>/maps and /proc/<pid>/mem, and the yama scope decides ptrace.
            val capabilities = DirectRoot.run(context,
                "/system/bin/grep -E 'Cap(Eff|Prm|Bnd)|NoNewPrivs' /proc/self/status; " +
                    "/system/bin/cat /proc/sys/kernel/yama/ptrace_scope 2>&1").output
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE t3_caps [${capabilities.trim()}]")

            shell("am force-stop $target")
            Thread.sleep(400)
            launch()
            Thread.sleep(2_500)
            val processes = DirectRoot.run(context,
                "/system/bin/ps -A -o PID,PPID,NAME | /system/bin/grep -E '$target'").output
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE t3_processes [${processes.trim()}]")
            val mapsProbe = DirectRoot.run(context,
                "P=\$(/system/bin/ps -A -o PID,NAME | /system/bin/grep -E ' $target\$' | " +
                    "/system/bin/head -1 | /system/bin/awk '{print \$1}'); " +
                    "/system/bin/echo pid=\$P; /system/bin/ls -l /proc/\$P/maps 2>&1; " +
                    "/system/bin/head -2 /proc/\$P/maps 2>&1; " +
                    "/system/bin/ls -l /proc/\$P/mem 2>&1").output
            android.util.Log.i("MapleSU", "MAPLESU_EVIDENCE t3_maps [${mapsProbe.trim()}]")
            val running = SuPathWiring.injectPath(context, target, 0)
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE t3_inject case=running ok=${running.ok} code=${running.code} " +
                    "reason=${running.reason} detail=${running.detail}")

            // The race: ask for the process while it is still being created.
            shell("am force-stop $target")
            Thread.sleep(400)
            launch()
            Thread.sleep(150)
            val starting = SuPathWiring.injectPath(context, target, 1_500)
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE t3_inject case=starting ok=${starting.ok} code=${starting.code} " +
                    "reason=${starting.reason} detail=${starting.detail}")

            // A second injection into the same live process must not be rejected - the
            // manager runs this on every start.
            val again = SuPathWiring.injectPath(context, target, 0)
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE t3_inject case=repeat ok=${again.ok} code=${again.code} " +
                    "detail=${again.detail}")

            // The failure the device actually showed: the pid still exists while the process
            // is on its way out. The native side addresses that with a per-pid retry across
            // all three offset strategies; this records what the kernel says if it still
            // cannot be reached.
            shell("am force-stop $target")
            val dying = SuPathWiring.injectPath(context, target, 0)
            android.util.Log.i("MapleSU",
                "MAPLESU_EVIDENCE t3_inject case=dying ok=${dying.ok} code=${dying.code} " +
                    "reason=${dying.reason} detail=${dying.detail}")
        } finally {
            if (original == true) DirectPolicy.grant(context, uid) else DirectPolicy.revoke(context, uid)
        }
    }
}
