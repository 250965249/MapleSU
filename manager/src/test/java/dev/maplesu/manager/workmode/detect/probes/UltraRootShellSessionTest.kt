package dev.maplesu.manager.workmode.detect.probes

import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraRootShellSessionTest {
    @Test fun selinuxIsReadInTheSameUidVerifiedBatchWithoutAnotherSdkCall() = UltraSnapshotFixture().use { fixture ->
        fixture.selinux = "Permissive"
        val session = fixture.openRaw()!!
        assertEquals(RootCommandResult(true, listOf("Permissive")), session.runner.run("/system/bin/getenforce"))
        assertEquals(1, fixture.calls)
        fixture.selinuxExit = 13
        assertFalse(fixture.openRaw()!!.runner.run("/system/bin/getenforce").ok)
        assertEquals(2, fixture.calls)
    }

    @Test fun realRootIdentityIsRequiredBeforeOpening() = UltraSnapshotFixture().use { fixture ->
        for (uid in listOf("2000", "10481", "", "0\n2000", "0\n")) {
            fixture.uid = uid
            assertNull(fixture.open())
        }
        fixture.uid = "0"
        fixture.uidExit = 1
        assertNull(fixture.open())
        fixture.uidExit = 0
        assertNotNull(fixture.open())
    }

    @Test fun unknownEnvironmentNeverCallsSdk() {
        var called = false
        assertNull(UltraRootShellSession.open({ false }, RootShellRunner {
            called = true; RootCommandResult(true, emptyList())
        }))
        assertFalse(called)
    }

    @Test fun sdkFailureOrMalformedSnapshotIsUnknownNotMissingFile() = UltraSnapshotFixture().use { fixture ->
        var captured: RootCommandResult? = null
        fixture.transform = { it.also { captured = it } }
        assertNotNull(fixture.open())
        val valid = requireNotNull(captured)
        val tag = fixture.tag
        val lines = valid.out
        val wrongStatus = lines.map { if (it.startsWith("$tag:ITEM:1:")) "$tag:ITEM:1:256:0" else it }
        val wrongIdentity = lines.mapIndexed { index, line -> if (index == 2) "MjAwMAo=" else line }
        fun commandStatus(status: String): List<String> {
            val begin = lines.indexOfFirst { it.startsWith("$tag:ITEM:1:") } + 1
            val end = lines.indexOf("$tag:ITEM_END:1")
            val payload = Base64.getDecoder().decode(lines.subList(begin, end).joinToString(""))
                .toString(Charsets.UTF_8).substringBeforeLast("$tag:RC:") + "$tag:RC:$status"
            val encoded = Base64.getEncoder().encodeToString(payload.toByteArray())
            return lines.take(begin) + encoded.chunked(76) + lines.drop(end)
        }
        val missingItem = lines.toMutableList().also {
            val start = it.indexOfFirst { line -> line.startsWith("$tag:ITEM:1:") }
            val end = it.indexOf("$tag:ITEM_END:1")
            it.subList(start, end + 1).clear()
        }
        val corruptions = listOf(
            valid.copy(ok = false),
            valid.copy(out = lines.filterNot { it == "$tag:END" }),
            valid.copy(out = lines + "$tag:END"),
            valid.copy(out = lines.map { it.replace("$tag:BEGIN", "WRONG_NONCE:BEGIN") }),
            valid.copy(out = lines.map { it.replace("$tag:ITEM:1:", "$tag:ITEM:99:") }),
            valid.copy(out = lines.map { it.replace("$tag:ITEM:1:", "") }),
            valid.copy(out = wrongStatus),
            valid.copy(out = wrongStatus.map { it.replace(":256:0", ":-1:0") }),
            valid.copy(out = wrongStatus.map { it.replace(":256:0", ":0:13") }),
            valid.copy(out = wrongStatus.map { it.replace(":256:0", ":garbage:0") }),
            valid.copy(out = commandStatus("-1")),
            valid.copy(out = commandStatus("256")),
            valid.copy(out = commandStatus("garbage")),
            valid.copy(out = commandStatus("")),
            valid.copy(out = wrongIdentity),
            valid.copy(out = lines.mapIndexed { index, line -> if (index == 2) "MAo" else line }),
            valid.copy(out = missingItem),
            valid.copy(out = lines.map { if (it.startsWith("$tag:ITEM:1:")) "$tag:SKIP:1" else it }),
        )
        corruptions.forEachIndexed { index, answer ->
            assertNull("corruption=$index", UltraRootShellSession.open(
                { true }, RootShellRunner { answer }, { tag },
            ))
        }
    }

    @Test fun commandExitCodeIsSeparateFromSuccessfulSdkEnvelope() = UltraSnapshotFixture().use { fixture ->
        fixture.file("ksu/.kmi-writable", "")
        val opened = fixture.openRaw()!!
        assertFalse(opened.runner.run("test -x '/data/adb/ksud'").ok)
        assertTrue(opened.runner.run("test -e '/data/adb/ksu/.kmi-writable'").ok)
        assertEquals(1, fixture.calls)
    }

    @Test fun unchangedEvidenceReaderPreservesOrderAndExactControlText() = UltraSnapshotFixture().use { fixture ->
        val text = "{\n  \"literal\": \"${fixture.tag}:ITEM_END:1\"\n}\n\n"
        fixture.file("maplesu-workmode/control/modes.json", text)
        fixture.file("maplesu-workmode/control/installed.json", "")
        val reader = fixture.open()!!
        assertEquals(text.dropLast(1), reader.readControlFile("modes.json"))
        assertEquals("", reader.readControlFile("installed.json"))
        assertNull(reader.readControlFile("switch.json"))
        val trace = fixture.trace()
        assertTrue(trace[1].endsWith("/control/modes.json"))
        assertTrue(trace[2].endsWith("/control/installed.json"))
        assertTrue(trace[3].endsWith("/control/switch.json"))
        assertEquals(1, fixture.calls)
    }

    @Test fun sdkLossAfterOpeningRemainsUnknownAndDoesNotRetryAnotherBackend() = UltraSnapshotFixture().use { fixture ->
        fixture.file("ksu/.kmi-writable", "")
        val opened = fixture.open()!!
        fixture.running = false
        assertNull(opened.exists("/data/adb/ksu/.kmi-writable"))
        assertEquals(1, fixture.calls)
        fixture.running = true
        fixture.transform = { fixture.running = false; it }
        assertNull(fixture.open())
        assertEquals(2, fixture.calls)
    }
}
