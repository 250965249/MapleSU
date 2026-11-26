package dev.maplesu.manager.jailbreak.ghostsam

/**
 * Builds the consumer argv / shell command. Canonical (lease_contract.c) mode keeps the
 * nonce in argv; V2 runtime mode (nonce via stdin, t19 P2) omits argv[nonce].
 * All args are single-quote wrapped and rejected on NUL/newline/quote.
 */
object CommandBuilder {
    private val NONCE = Regex("^[0-9a-f]{64}$")
    private val BOOT = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val ENDPOINT_SUFFIX = Regex("^[a-z0-9-]+$")

    fun endpoint(value: String): Boolean =
        value.startsWith("maplesu-jb-") && value.length > 11 && value.length <= 100 &&
            ENDPOINT_SUFFIX.matches(value.removePrefix("maplesu-jb-"))

    fun nonce(value: String): Boolean = NONCE.matches(value)

    fun bootId(value: String): Boolean = BOOT.matches(value)

    fun uid(value: String): Boolean {
        if (value.isEmpty() || !value.all { it in '0'..'9' }) return false
        val n = value.toLongOrNull() ?: return false
        return n >= 10000 && n <= 2147483647L
    }

    private fun safe(value: String): String {
        if (value.contains('\u0000') || value.contains('\n') || value.contains('\r') || value.contains('\''))
            throw LeaseWireException("ARG_INVALID")
        return value
    }

    fun buildArgv(consumerPath: String, endpoint: String, nonceHex: String, uid: Int,
                  bootId: String, provider: String, enforce: String? = null,
                  includeNonce: Boolean = true): List<String> {
        if (!endpoint(endpoint)) throw LeaseWireException("ARG_ENDPOINT_INVALID")
        if (!nonce(nonceHex)) throw LeaseWireException("ARG_NONCE_INVALID")
        if (!uid(uid.toString())) throw LeaseWireException("ARG_UID_INVALID")
        if (!bootId(bootId)) throw LeaseWireException("ARG_BOOT_ID_INVALID")
        if (provider != "ghostlock" && provider != "dirtyfrag") throw LeaseWireException("ARG_PROVIDER_INVALID")
        val argv = mutableListOf(safe(consumerPath), safe(endpoint))
        if (includeNonce) argv += safe(nonceHex)
        argv += uid.toString(); argv += safe(bootId); argv += provider
        if (enforce != null) argv += safe(enforce)
        return argv
    }

    fun buildCommand(consumerPath: String, endpoint: String, nonceHex: String, uid: Int,
                     bootId: String, provider: String, enforce: String? = null,
                     includeNonce: Boolean = true, fdArgs: Boolean = false): String {
        if (fdArgs) {
            // V2 contract form: all lease params travel via the consumer's stdin TLV; argv only selects it.
            val argv = mutableListOf(safe(consumerPath), "--fd-args")
            if (enforce != null) argv += safe(enforce)
            return "exec " + argv.joinToString(" ") { "'" + it + "'" }
        }
        val argv = buildArgv(consumerPath, endpoint, nonceHex, uid, bootId, provider, enforce, includeNonce)
        return "exec " + argv.joinToString(" ") { "'" + it + "'" }
    }
}
