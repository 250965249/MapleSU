package dev.maplesu.manager.jailbreak.ghostsam

/** Declares only RAW_ROOT_LEASE. Refuses to set/accept any Ultra kernel-SU field. */
object CapabilityGate {
    val allowed: Set<String> = setOf("RAW_ROOT_LEASE")
    private val ULTRA_FIELDS = listOf("ultraState", "ultraKeyPresent", "ultraKernelRootVerified", "IRootManagementService")

    fun assertNoUltra(facts: Map<String, Any?>) {
        for (name in ULTRA_FIELDS) {
            val v = facts[name]
            if (v != null && v != false && v != "NONE" && v != "ABSENT") throw LeaseWireException("CAPABILITY_OUT_OF_SCOPE:$name")
        }
    }
}
