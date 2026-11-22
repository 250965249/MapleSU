package dev.maplesu.manager.runtime

import dev.maplesu.manager.runtime.ultra.NativeReceipt
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge

/** Module-only compatibility facts. The local SDK version describes userspace, never a KSU driver. */
internal object ModuleTaskEnvironment {
    fun captureNonSdk(hook: Boolean): Array<String> {
        val receipt = NativeReceipt.parse(NativeBridge.getSdkVersion())
        check(receipt?.succeeded == true) { "MODULE_USERSPACE_VERSION_UNAVAILABLE:${receipt?.sdkError}:${receipt?.sdkErrorCode}" }
        return nonSdk(checkNotNull(receipt.int("major")), checkNotNull(receipt.int("minor")),
            checkNotNull(receipt.int("patch")), hook)
    }

    internal fun nonSdk(major: Int, minor: Int, patch: Int, hook: Boolean): Array<String> {
        require(major >= 0 && minor >= 0 && patch >= 0)
        return buildList {
            add("KSU=true")
            add("KSU_VER=MapleSU $major.$minor.$patch")
            add("KSU_VER_CODE=${major.toLong() * 10000 + minor.toLong() * 100 + patch}")
            add("KSU_KERNEL_VER_CODE=0")
            add("KSU_UAPI_VER=0")
            add("MAPLESU_KSU_COMPAT=1")
            add("KSU_FACT_SOURCE=${if (hook) "hook" else "legacy"}")
            if (hook) {
                // The current boot/attempt Gate proves this temporary Hook session.
                add("KSU_RUNTIME_MODE=late-load")
                add("KSU_LATE_LOAD=1")
                add("MAPLESU_RUNTIME_MODE=hotload")
            } else {
                // Credential and pre-existing Root transports expose no installation-mode fact.
                add("MAPLESU_RUNTIME_MODE=unknown")
            }
        }.toTypedArray()
    }

    /** ProcessBuilder owns this map; the Manager's inherited environment stays untouched. */
    fun replace(environment: MutableMap<String, String>, facts: Array<String>) {
        environment.keys.removeAll { it == "KSU" || it.startsWith("KSU_") ||
            it == "MAPLESU_RUNTIME_MODE" || it == "MAPLESU_KSU_COMPAT" }
        facts.forEach { fact -> environment[fact.substringBefore('=')] = fact.substringAfter('=') }
    }
}
