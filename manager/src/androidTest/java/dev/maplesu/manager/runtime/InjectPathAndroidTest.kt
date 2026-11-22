package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The library-free mechanism: an application with no native code at all gets the published
 * directory prepended to its running process's PATH.
 *
 * <p>The old assertion read `/proc/<pid>/environ`, which is the environment captured at
 * `exec`: a later `setenv` - exactly what the injection performs - can never appear there,
 * so that assertion failed even when the injection worked. This application reports no
 * PATH of its own, so the native verdict is what is recorded here; the end-to-end proof
 * that an injected PATH changes what the application sees lives in
 * `T3InjectProbeAndroidTest`, whose target prints its own `getenv("PATH")` and a bare `su`.
 */
class InjectPathAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val target = "io.github.a13e300.ksuwebui"

    @Test fun injectionWiresAnApplicationWithoutLibraries() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val uid = context.packageManager.getApplicationInfo(target, 0).uid
        val policy = DirectPolicy
        val original = policy.hasGrantStrict(context, uid)
        policy.grant(context, uid)
        SuPublication.publish(context)
        val directory = SuPublication.suDirectory(context)
        val injected = SuPathWiring.injectPath(context, target)
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE inject_path uid=$uid ok=${injected.ok} code=${injected.code} " +
                "detail=${injected.detail} directory=$directory")
        try {
            assertTrue("injection failed: ${injected.detail}", injected.ok)
        } finally {
            if (original == true) policy.grant(context, uid) else policy.revoke(context, uid)
        }
    }
}
