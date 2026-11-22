package dev.maplesu.manager.litehidden

import org.junit.Assert.*
import org.junit.Test

class NormalRecoveryBootTest {
    @Test fun previousOwnedBootScriptCanBeUpgradedOrRemoved() {
        val legacy = "367c7117130341c29b875e80242d5a2c1b38b44014a684b7ab7c5aa08f392dbb"
        val install = NormalRecoveryBoot.installScript()
        assertTrue(install.contains(legacy))
        assertTrue(NormalRecoveryBoot.removeScript().contains(legacy))
        assertTrue(install.indexOf("fi\n") < install.indexOf("cat >"))
        assertTrue(install.contains("[ ! -L \"\$P.tmp\" ]"))
        assertTrue(install.contains("--await-ready"))
    }
}
