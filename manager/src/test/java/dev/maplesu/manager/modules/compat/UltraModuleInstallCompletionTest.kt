package dev.maplesu.manager.modules.compat

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UltraModuleInstallCompletionTest {
    private fun receipt(operation: String = "install_module", succeeded: Boolean = false,
                        data: JSONObject? = null, completed: Boolean = true): NativeReceipt =
        NativeReceipt.parse(JSONObject().put("backend", "maplesu_ultra").put("operation", operation)
            .put("ok", succeeded).put("sdkError", if (succeeded) "OK" else "RESTORE_FAILED")
            .put("sdkErrorCode", if (succeeded) 0 else -1001).put("operationCompleted", completed)
            .put("data", data).toString())!!

    @Test fun onlyPrivateCommitOrSameOperationLegacySuccessProvesInstallation() {
        assertTrue(confirmedUltraModuleInstall(receipt(data = JSONObject().put("installCommitted", true)), "install_module"))
        assertTrue(confirmedUltraModuleInstall(receipt(succeeded = true), "install_module"))
        assertFalse(confirmedUltraModuleInstall(receipt(), "install_module"))
        assertFalse(confirmedUltraModuleInstall(receipt("uninstall_module", data = JSONObject().put("installCommitted", true)), "install_module"))
    }

    @Test fun explicitFalseNullAndMalformedCommitNeverFallBackToSuccess() {
        for (value in listOf(false, JSONObject.NULL, "true", 1)) {
            assertFalse(confirmedUltraModuleInstall(receipt(succeeded = true,
                data = JSONObject().put("installCommitted", value)), "install_module"))
        }
    }
}
