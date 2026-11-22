package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import dev.maplesu.manager.runtime.authorization.ManagerAuthorizations
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters

/**
 * T1 field repair: undo the damage the retired library implant did, then prove the repaired
 * applications still start and that the delivered client still admits root.
 *
 * <p><b>Temporary.</b> This is a one-shot device repair harness, not a regression test. It
 * runs in four ordered passes: repair MT, observe MT, repair the fixture, then one
 * controlled re-wire of the fixture.
 *
 * <p>Every device read and write goes through [DirectRoot] (one short-lived root process per
 * call, nothing resident). `UiAutomation.executeShellCommand` returns empty output in this
 * environment, so it is deliberately not used anywhere here.
 *
 * <p>Why more than one library: the implant appends a side library to whichever JNI library
 * it patches and records `DT_NEEDED` entries for it. MT's `libmt1.so` collected 41 of them
 * (222,632 -> 13,638,497 bytes), `libmt3.so` two (35,552 -> 657,201) and
 * `libffmpegJNI.so` one (1,235,192 -> 1,509,553). Deleting the side libraries while any of
 * those still carries `DT_NEEDED` for them would leave a dangling dependency and the next
 * `dlopen` of the patched library fails, so every modified library is restored from the same
 * `base.apk` the installed copy came from.
 *
 * <p>Side libraries are identified structurally, not by name: they are the only root-owned
 * regular files in the library directory (the implant creates them root-owned; the
 * application's own libraries are always `system:system` = 1000). The delivered client `su`
 * belongs to the application's uid (10472 for MT, 10480 for the fixture), so it can never be
 * selected. No mount is created, SELinux policy is never touched, and nothing stays resident.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class MtLibRepairAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val target = "bin.mt.plus"
    private val fixture = "dev.maplesu.wiredtarget"

    /** One library as `base.apk` ships it. */
    private data class Shipped(val name: String, val size: Long, val sha256: String)

    /** MT's install directory once the implant damage is undone. */
    private val mtLibraries = listOf(
        Shipped("libmt1.so", 222_632,
            "fa1c87acb9c2ff8cb82c008d6ada9215173a1eade5b5006303689ad128991391"),
        Shipped("libmt3.so", 35_552,
            "2ce2131f897f4a26064383c0e7e4f095b07b49ae80d6ff12e2605f16e8200dd3"),
        Shipped("libffmpegJNI.so", 1_235_192,
            "8a4a5a08835f6155ff8edc25ad560958ea0d1056052cd966a9c763ba09fcdfb8"),
    )

    /** The same damage on the fixture. */
    private val fixtureLibraries = listOf(
        Shipped("libwiredtarget.so", 5_368,
            "cffa5a4ea6383300cba8d1fee4086edf2b2d8c58c94663a9d49ebdaeb4b1d690"),
    )

    /** One short-lived root process; the exit code is checked by the callers that care. */
    private fun root(command: String): String = DirectRoot.run(context, command).output

    private fun packagePath(name: String): String =
        root("/system/bin/pm path $name").lineSequence()
            .firstOrNull { it.startsWith("package:") }
            ?.removePrefix("package:")
            ?.trim()
            ?: error("no package path for $name")

    private fun libDirectory(name: String): String =
        packagePath(name).substringBeforeLast('/') + "/lib/arm64"

    private fun stat(path: String): String =
        root("/system/bin/stat -c 'size=%s mtime=%Y uid=%u gid=%g mode=%a' '$path'")
            .trim().lines().lastOrNull().orEmpty().trim()

    private fun sizeOf(path: String): Long =
        stat(path).removePrefix("size=").substringBefore(' ').toLongOrNull() ?: -1L

    private fun sha256(path: String): String =
        root("/system/bin/sha256sum '$path'").trim().lines().lastOrNull().orEmpty().trim().substringBefore(' ')

    private fun rootOwnedCount(lib: String): Int =
        root("/system/bin/find '$lib' -maxdepth 1 -type f -user 0 | /system/bin/wc -l")
            .trim().lines().lastOrNull().orEmpty().trim().toIntOrNull() ?: -1

    private fun entryCount(lib: String): Int =
        root("/system/bin/ls -1 '$lib' | /system/bin/wc -l")
            .trim().lines().lastOrNull().orEmpty().trim().toIntOrNull() ?: -1

    private fun running(name: String): Boolean =
        root("/system/bin/ps -A -o NAME | /system/bin/grep -c '^$name$'")
            .trim().lines().lastOrNull().orEmpty().trim().toIntOrNull().let { (it ?: 0) > 0 }

    private fun launch(name: String) {
        root("/system/bin/am start -n ${component(name)}")
    }

    private fun component(name: String): String =
        root("/system/bin/cmd package resolve-activity --brief $name | /system/bin/tail -1")
            .trim().lines().lastOrNull().orEmpty().trim()

    /** Runs the fixture's own probe and returns the PROBE line it logged. */
    private fun probe(component: String, waitMs: Long): String {
        root("/system/bin/logcat -c")
        root("/system/bin/am force-stop ${component.substringBefore('/')}")
        Thread.sleep(1_200)
        root("/system/bin/am start -n $component --es scenario probe")
        Thread.sleep(waitMs)
        return root("/system/bin/logcat -d -s WIREDTARGET")
            .lineSequence().lastOrNull { it.contains("PROBE") }.orEmpty().trim()
    }

    private fun crashes(): String =
        root("/system/bin/logcat -d | /system/bin/grep -E 'Fatal signal|FATAL EXCEPTION' | /system/bin/tail -3")
            .trim()

    private fun awaitLog(marker: String, timeoutMs: Long = 25_000): String {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMs
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val line = root("/system/bin/logcat -d -s MapleSU")
                .lineSequence().lastOrNull { it.contains(marker) }
            if (line != null) return line
            Thread.sleep(400)
        }
        return ""
    }

    /**
     * The whole restore, as one root script. Every step echoes into [log], which is made
     * world-readable afterwards so the evidence can be pulled without root.
     */
    private fun repairScript(
        apk: String,
        lib: String,
        libraries: List<Shipped>,
        workdir: String,
        log: String,
    ): String {
        val lines = mutableListOf<String>()
        lines += "exec 3>&1 1>$log 2>&1"
        lines += "echo \"=== T1 library repair ===\""
        lines += "date"
        lines += "echo \"lib=$lib\""
        lines += "echo \"apk=$apk\""
        lines += "echo \"--- phase 1: before ---\""
        lines += "ls -lZ '$lib'"
        libraries.forEach { lines += "stat -c 'before size=%s mtime=%Y uid=%u gid=%g mode=%a' '$lib/${it.name}'" }
        libraries.forEach { lines += "sha256sum '$lib/${it.name}'" }
        lines += "echo 'root_owned_before:'"
        lines += "find '$lib' -maxdepth 1 -type f -user 0 | wc -l"
        lines += "echo 'entries_before:'"
        lines += "ls -1 '$lib' | wc -l"
        lines += "echo \"--- phase 2: extract the shipped libraries from base.apk ---\""
        lines += "rm -rf $workdir"
        lines += "mkdir -p $workdir"
        libraries.forEach {
            lines += "unzip -o -j '$apk' 'lib/arm64-v8a/${it.name}' -d $workdir && echo extract_ok_${it.name} || echo extract_FAIL_${it.name}"
        }
        lines += "stat -c 'extracted size=%s %n' $workdir/*.so"
        lines += "sha256sum $workdir/*.so"
        lines += "echo \"--- phase 3: back up the current files (an existing backup is never overwritten) ---\""
        lines += "mkdir -p $workdir/backup"
        libraries.forEach {
            lines += "if [ -f $workdir/backup/${it.name} ]; then echo backup_exists_${it.name}; " +
                "else cp -f '$lib/${it.name}' $workdir/backup/${it.name} && echo backup_ok_${it.name} " +
                "|| echo backup_FAIL_${it.name}; fi"
        }
        lines += "stat -c 'backup size=%s %n' $workdir/backup/*.so"
        lines += "sha256sum $workdir/backup/*.so"
        lines += "echo \"--- phase 4: restore the shipped library over the damaged one ---\""
        libraries.forEach {
            lines += "cp -f $workdir/${it.name} '$lib/${it.name}' && echo cp_ok_${it.name} || echo cp_FAIL_${it.name}"
            lines += "chown 1000:1000 '$lib/${it.name}' && echo chown_ok_${it.name} || echo chown_FAIL_${it.name}"
            lines += "chmod 0755 '$lib/${it.name}' && echo chmod_ok_${it.name} || echo chmod_FAIL_${it.name}"
            lines += "chcon u:object_r:apk_data_file:s0 '$lib/${it.name}' && echo chcon_ok_${it.name} || echo chcon_FAIL_${it.name}"
        }
        lines += "echo \"--- phase 5: delete the root-owned side libraries, printing every path ---\""
        lines += "find '$lib' -maxdepth 1 -type f -user 0 ! -name su -print -delete"
        lines += "echo \"--- phase 6: after ---\""
        lines += "ls -lZ '$lib'"
        libraries.forEach { lines += "stat -c 'after size=%s mtime=%Y uid=%u gid=%g mode=%a' '$lib/${it.name}'" }
        lines += "stat -c 'client su size=%s mtime=%Y uid=%u gid=%g mode=%a' '$lib/su'"
        libraries.forEach { lines += "sha256sum '$lib/${it.name}'" }
        lines += "echo 'root_owned_after:'"
        lines += "find '$lib' -maxdepth 1 -type f -user 0 | wc -l"
        lines += "echo 'entries_after:'"
        lines += "ls -1 '$lib' | wc -l"
        lines += "echo \"--- phase 7: reference hashes straight out of base.apk ---\""
        libraries.forEach { lines += "unzip -p '$apk' lib/arm64-v8a/${it.name} | sha256sum" }
        lines += "echo \"=== repair script done ===\""
        lines += "exec 1>&3 2>&3"
        lines += "chmod 0644 $log"
        lines += "chown 2000:2000 $log"
        lines += "cat $log"
        return lines.joinToString("\n")
    }

    /** Step 1: stop MT, restore the three shipped libraries, delete the 47 side libraries. */
    @Test fun step1RepairsMtLibraries() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val apk = packagePath(target)
        val lib = libDirectory(target)
        val log = "/data/local/tmp/mt_repair_transcript.txt"

        val wasRunning = running(target)
        root("/system/bin/am force-stop $target")
        Thread.sleep(1_500)
        val stopped = !running(target)

        val repair = DirectRoot.run(context,
            repairScript(apk, lib, mtLibraries, "/data/local/tmp/mtfix", log))
        val transcript = runCatching { root("/system/bin/cat $log") }.getOrDefault("")

        val sizes = mtLibraries.associate { it.name to sizeOf("$lib/${it.name}") }
        val installed = mtLibraries.associate { it.name to sha256("$lib/${it.name}") }
        val rootOwned = rootOwnedCount(lib)
        val entries = entryCount(lib)
        val su = stat("$lib/su")

        launch(target)
        Thread.sleep(5_000)
        val runningAfter = running(target)
        val sizeAfterLaunch = sizeOf("$lib/libmt1.so")

        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE mt_repair rc=${repair.code} wasRunning=$wasRunning stopped=$stopped " +
                "sizes=$sizes sha=$installed rootOwned=$rootOwned entries=$entries su=[$su] " +
                "launched=$runningAfter sizeAfterLaunch=$sizeAfterLaunch log=$log")

        assertEquals("the repair script did not exit cleanly: ${repair.output.takeLast(400)}", 0, repair.code)
        assertTrue("an extract/backup/copy/owner/label step failed", !transcript.contains("_FAIL"))
        mtLibraries.forEach {
            assertEquals("${it.name} is not the shipped ${it.size} bytes", it.size, sizes[it.name])
            assertEquals("${it.name} is not byte-identical to base.apk", it.sha256, installed[it.name])
        }
        assertEquals("implant residue is still in the library directory", 0, rootOwned)
        assertTrue("the delivered client su is gone or no longer uid 10472: $su",
            su.contains("uid=10472") && su.contains("mode=700"))
        assertTrue("MT did not start after the repair", runningAfter)
        assertEquals("MT started but libmt1.so was modified again", sizes["libmt1.so"], sizeAfterLaunch)
        // 11 shipped libraries plus the delivered client, nothing else.
        assertEquals("the library directory holds more than its own libraries", 12, entries)
    }

    /**
     * Step 2: observation only, no repair and no re-wire. Records whether the repaired MT
     * still resolves a bare `su`, which it is expected not to: the `DT_NEEDED` entry that
     * put the client directory on `PATH` is exactly what the restore removed.
     */
    @Test fun step2ObservesMtAfterRepair() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val lib = libDirectory(target)
        val uid = context.packageManager.getApplicationInfo(target, 0).uid
        val suDirectory = SuPublication.suDirectory(context)
        if (!running(target)) {
            launch(target)
            Thread.sleep(5_000)
        }
        val pid = root("/system/bin/ps -A -o PID,NAME | /system/bin/grep ' bin.mt.plus' | /system/bin/head -1")
            .trim().lines().lastOrNull().orEmpty().trim().split(' ').firstOrNull().orEmpty()
        val path = if (pid.isNotEmpty())
            root("/system/bin/tr '\\0' '\\n' < /proc/$pid/environ | /system/bin/grep '^PATH='").trim()
        else ""
        val sideMapped = if (pid.isNotEmpty())
            root("/system/bin/grep -c '_su_env' /proc/$pid/maps").trim()
        else ""
        val suAnswers = if (pid.isNotEmpty())
            root("'$lib/su' -c 'id -u' 2>&1 | /system/bin/head -2").trim()
        else ""
        val granted = DirectPolicy.hasGrantStrict(context, uid)

        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE mt_after_repair granted=$granted running=${running(target)} " +
                "libmt1=${sizeOf("$lib/libmt1.so")} sides=${rootOwnedCount(lib)} pid=$pid " +
                "pathHasSu=${path.contains(suDirectory + ":")} sideMapped=$sideMapped " +
                "suAsRoot=[${suAnswers.take(120)}] path=[${path.take(220)}]")

        assertTrue("MT is not running after the repair", running(target))
        assertEquals("MT still carries implant residue", 0, rootOwnedCount(lib))
        assertEquals("libmt1.so changed after the repair", 222_632L, sizeOf("$lib/libmt1.so"))
        assertEquals("a side library is still mapped into MT", "0", sideMapped.trim())
    }

    /** Step 3: the same repair on the fixture, then its self-reporting probe. */
    @Test fun step3RepairsFixture() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val apk = packagePath(fixture)
        val lib = libDirectory(fixture)
        val log = "/data/local/tmp/fixture_repair_transcript.txt"
        val before = sizeOf("$lib/libwiredtarget.so")
        val sidesBefore = rootOwnedCount(lib)

        root("/system/bin/am force-stop $fixture")
        Thread.sleep(1_200)
        val repair = DirectRoot.run(context,
            repairScript(apk, lib, fixtureLibraries, "/data/local/tmp/fxfix", log))
        val transcript = runCatching { root("/system/bin/cat $log") }.getOrDefault("")
        val restored = sizeOf("$lib/libwiredtarget.so")
        val restoredSha = sha256("$lib/libwiredtarget.so")
        val sidesAfter = rootOwnedCount(lib)
        val su = stat("$lib/su")

        val line = probe("$fixture/dev.maplesu.wiredtarget.Main", 6_000)
        val crash = crashes()

        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE mt_fixture_repair rc=${repair.code} before=$before sidesBefore=$sidesBefore " +
                "restored=$restored sha=$restoredSha sidesAfter=$sidesAfter su=[$su] " +
                "probe=[$line] crash=[${crash.take(200)}] log=$log")

        assertEquals("the fixture repair did not exit cleanly", 0, repair.code)
        assertTrue("an extract/backup/copy step failed", !transcript.contains("_FAIL"))
        assertEquals("libwiredtarget.so is not the shipped 5,368 bytes", 5_368L, restored)
        assertEquals("libwiredtarget.so is not byte-identical to base.apk",
            fixtureLibraries.first().sha256, restoredSha)
        assertEquals("the fixture still carries implant residue", 0, sidesAfter)
        assertTrue("the fixture's own delivered client was disturbed: $su", su.contains("uid=10480"))
        assertTrue("the fixture crashed again after the repair: $crash", crash.isEmpty())
        assertTrue("the probe reports native=ok, so the repaired library's code runs: $line",
            line.contains("native=ok"))
        assertTrue("the delivered client no longer admits root: $line",
            line.contains("delivered=[rc=0 out=0]"))
    }

    /**
     * Step 4: exactly one controlled re-wire of the (now clean) fixture, then the probe
     * again. This answers the open question: is a single implant safe, or does even one
     * corrupt the target?
     */
    @Test fun step4SingleRewireOfFixture() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifySuPolicyMutations") == "true")
        val lib = libDirectory(fixture)
        val uid = context.packageManager.getApplicationInfo(fixture, 0).uid
        // The fixture has to be clean before it is wired, otherwise the measurement is void.
        assertEquals("refusing to wire a fixture that is not clean", 0, rootOwnedCount(lib))
        assertEquals("refusing to wire a fixture whose library is not shipped", 5_368L,
            sizeOf("$lib/libwiredtarget.so"))
        val before = sizeOf("$lib/libwiredtarget.so")

        if (!running(fixture)) {
            root("/system/bin/am start -n $fixture/dev.maplesu.wiredtarget.Main --es scenario probe")
            Thread.sleep(3_000)
        }
        // Wiring needs an enabled policy and a current grant; both are restored at the end.
        val policy = ManagerAuthorizations.policy(context)
        val originalEnabled = policy.isEnabled
        val originalGrant = policy.hasCurrentGrant(uid)
        var wire: SuPathWiring.Result
        try {
            if (originalEnabled != true) policy.setEnabled(true)
            if (DirectPolicy.hasGrantStrict(context, uid) != true) {
                Natives.getAppProfile(fixture, uid)?.copy(allowSu = true)
                    ?.let { ManagerAuthorizations.saveProfile(context, it) }
                Thread.sleep(2_000)
            }
            wire = SuPathWiring.wire(context, fixture)
        } finally {
            if (originalEnabled != true) policy.setEnabled(originalEnabled)
        }

        val after = sizeOf("$lib/libwiredtarget.so")
        val sides = rootOwnedCount(lib)
        val wired = awaitLog("SU_PATH_WIRED package=$fixture", 8_000)

        val line = probe("$fixture/dev.maplesu.wiredtarget.Main", 7_000)
        val crash = crashes()
        val sidesAfterRestart = rootOwnedCount(lib)
        val afterRestart = sizeOf("$lib/libwiredtarget.so")

        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE mt_fixture_rewire granted=${originalGrant} wire=${wire.ok}/${wire.detail} " +
                "libBefore=$before libAfter=$after sides=$sides wired=[${wired.trim()}] " +
                "probe=[$line] crash=[${crash.take(200)}] afterRestart=$afterRestart " +
                "sidesAfterRestart=$sidesAfterRestart")

        assertTrue("the fixture is not authorised: no grant for uid $uid",
            DirectPolicy.hasGrantStrict(context, uid) == true)
        assertTrue("re-wiring failed: ${wire.detail}", wire.ok)
        assertEquals("one implant must add exactly one side library", 1, sides)
        assertTrue("a single implant must grow the patched library: $before -> $after", after > before)
        assertTrue("the fixture crashed after a single implant: $crash", crash.isEmpty())
        assertTrue("the delivered client stopped working: $line", line.contains("delivered=[rc=0 out=0]"))
        assertTrue("a bare su does not resolve after one implant: $line", line.contains("bare=[rc=0 out=0]"))
        assertEquals("a restart must not add a second side library", sides, sidesAfterRestart)
        assertEquals("a restart must not implant again", after, afterRestart)
    }
}
