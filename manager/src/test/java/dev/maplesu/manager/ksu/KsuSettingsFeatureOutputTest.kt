package dev.maplesu.manager.ksu

import org.junit.Assert.*
import org.junit.Test

class KsuSettingsFeatureOutputTest {
    private fun feature(output: String): KsuSettingsFeature = KsuSettingsFeatureImpl(KsuCommandBackend(
        daemonPathProvider = { "/data/adb/ksud" },
        runner = KsuShellRunner { _, _ -> KsuShellResult(0, output.lines(), emptyList()) },
        probe = object : KsuPathProbe { override fun exists(path: String) = true },
    ))

    @Test fun readsTheCurrentPinnedKsudEnabledOutput() {
        val output = "Feature: selinux_hide (4)\nDescription: SELinux policy hide\nValue: 1\nStatus: enabled"
        assertEquals(1L, feature(output).value(KsuFeature.SELINUX_HIDE))
    }
    @Test fun readsTheCurrentPinnedKsudDisabledOutput() {
        val output = "Feature: selinux_hide (4)\nDescription: SELinux policy hide\nValue: 0\nStatus: disabled"
        assertEquals(0L, feature(output).value(KsuFeature.SELINUX_HIDE))
    }
    @Test fun readsThePersistedValueWithTheSameFormat() {
        assertEquals(1L, feature("Feature: selinux_hide (4)\nValue: 1\nStatus: enabled")
            .persistValue(KsuFeature.SELINUX_HIDE))
    }
    @Test fun preservesTheBareNumericOutputContract() {
        assertEquals(1L, feature("1\n").value(KsuFeature.SELINUX_HIDE))
    }
    @Test fun anUnsetConfigIsUnknown() {
        assertNull(feature("Feature: selinux_hide (4)\nNot set in config").persistValue(KsuFeature.SELINUX_HIDE))
    }
    @Test fun unsupportedOutputIsUnknown() {
        assertNull(feature("Feature 'selinux_hide' is not supported by kernel").value(KsuFeature.SELINUX_HIDE))
    }
    @Test fun malformedOutputIsUnknown() {
        assertNull(feature("Feature: selinux_hide (4)\nValue: invalid").value(KsuFeature.SELINUX_HIDE))
    }
}
