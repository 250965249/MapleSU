package dev.maplesu.manager.modules

import androidx.test.platform.app.InstrumentationRegistry
import dev.maplesu.manager.runtime.MapleSuRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Closes a stated unknown in the compatibility contract (§8.1): whether the
 * existing MapleSU Root execution domain can actually read the live policy, apply
 * rules in memory, and serialize a candidate.
 *
 * Deliberately read-only with respect to the kernel: it never calls `apply`, so
 * `/sys/fs/selinux/load` is never written and the live policy is unchanged. The
 * only file it writes is a candidate image inside MapleSU's own private directory.
 *
 * The rule used is a bare new `type` declaration. It grants nothing and changes no
 * access decision, so even a candidate image containing it is inert.
 */
class PolicyLoaderAndroidTest {

    @Test(timeout = 120_000) fun loaderReadsLivePolicyAndSerializesCandidate() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue("Requires the paired MapleSU boot runtime", MapleSuRuntime.refresh(context))
        val tool = ModuleToolDeployment.policyPath()
        val rules = File(context.filesDir, "maplesu-policy-probe.rules")
        val candidate = File(context.filesDir, "maplesu-policy-probe.candidate")
        rules.writeText("type maplesu_policy_probe_t;\n")
        candidate.delete()

        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        data class Run(val code: Int, val out: List<String>, val err: List<String>)
        fun root(command: String): Run = MapleSuRuntime.openShell(context).use { shell ->
            val result = shell.newJob().add(command).to(ArrayList<String>(), ArrayList<String>()).exec()
            Run(result.code, result.out, result.err)
        }

        try {
            val present = root("test -x ${quote(tool)}")
            assertEquals("the policy loader must be deployed executable at $tool; stderr=${present.err}",
                0, present.code)
            println("MAPLESU_POLICY_EVIDENCE tool=$tool present=true")

            // No arguments must be a usage error, not a silent success.
            val usage = root("${quote(tool)}")
            assertEquals("a bare invocation must fail with the usage code", 1, usage.code)
            println("MAPLESU_POLICY_EVIDENCE usageExit=${usage.code} stderr=${quote(usage.err.joinToString(" | "))}")

            // Read the live policy and apply the declaration in memory only.
            val check = root("${quote(tool)} check --rules ${quote(rules.absolutePath)}")
            println("MAPLESU_POLICY_EVIDENCE checkExit=${check.code} " +
                "stdout=${quote(check.out.joinToString(" | "))} stderr=${quote(check.err.joinToString(" | "))}")
            assertEquals("check must accept a bare type declaration; stderr=${check.err.joinToString(" | ")}",
                0, check.code)
            val checkText = check.out.joinToString("\n")
            assertTrue("check must report committed:false; got $checkText", checkText.contains("\"committed\":false"))
            assertTrue("check must report a result event; got $checkText", checkText.contains("\"event\":\"result\""))

            // Serialize a candidate image into MapleSU's private directory.
            val save = root("${quote(tool)} save --policy /sys/fs/selinux/policy " +
                "--rules ${quote(rules.absolutePath)} --output ${quote(candidate.absolutePath)}")
            println("MAPLESU_POLICY_EVIDENCE saveExit=${save.code} " +
                "stderr=${quote(save.err.joinToString(" | "))}")
            assertEquals("save must serialize a candidate; stderr=${save.err.joinToString(" | ")}", 0, save.code)
            // Root owns the file, so stat it through the same shell rather than File.
            val size = root("/system/bin/stat -c %s ${quote(candidate.absolutePath)}")
            assertEquals("candidate must exist", 0, size.code)
            val bytes = size.out.joinToString("").trim().toIntOrNull() ?: 0
            assertTrue("candidate image must be non-empty", bytes > 0)
            println("MAPLESU_POLICY_EVIDENCE candidateBytes=$bytes liveWriteAttempted=false")
        } finally {
            candidate.delete()
            rules.delete()
        }
    }
}
