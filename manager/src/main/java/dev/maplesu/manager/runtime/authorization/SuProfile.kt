package dev.maplesu.manager.runtime.authorization

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.Base64

/** Complete fixed-KSU business profile. Rules remain in the existing ksud rule store. */
@Serializable
data class SuProfile(
    val name: String,
    val currentUid: Int,
    val allowSu: Boolean,
    val rootUseDefault: Boolean,
    val rootTemplate: String?,
    val uid: Int,
    val gid: Int,
    val groups: List<Int>,
    val capabilities: List<Int>,
    val context: String,
    val namespace: Int,
    val nonRootUseDefault: Boolean,
    val umountModules: Boolean,
    val flags: Long,
    val version: Int = VERSION,
) {
    fun validated(): SuProfile {
        require(version == VERSION) { "PROFILE_VERSION_UNSUPPORTED" }
        require(ManagerSuperuserPolicy.validUserDomain(currentUid)) { "PROFILE_IDENTITY_INVALID" }
        require(name.isNotBlank() && bounded(name, 256) && rootTemplate?.let { bounded(it, 256) } != false) {
            "PROFILE_NAME_INVALID"
        }
        require(uid >= 0 && gid >= 0 && groups.size <= 32 && groups.all { it >= 0 }) { "PROFILE_IDS_INVALID" }
        require(capabilities.size <= 64 && capabilities.all { it in 0..63 } && capabilities.distinct().size == capabilities.size) {
            "PROFILE_CAPABILITIES_INVALID"
        }
        require(bounded(context, 64) && namespace in 0..2 && flags and 1L.inv() == 0L) { "PROFILE_FIELDS_INVALID" }
        return this
    }

    internal fun frozen(): SuProfile = copy(groups = groups.toList(), capabilities = capabilities.toList()).validated()

    companion object {
        const val VERSION = 1
        private fun bounded(value: String, limit: Int) = '\u0000' !in value && value.toByteArray(Charsets.UTF_8).size < limit
        @JvmStatic fun legacy(name: String, uid: Int, allow: Boolean): SuProfile = SuProfile(
            name, uid, allow, true, null, 0, 0, emptyList(), emptyList(), "", 0, true, true, 1,
        ).validated()
    }
}

/** Installation identity is always captured root-side, never granted by the Manager's JSON. */
data class StoredSuProfile(val identity: ApplicationIdentity, val profile: SuProfile) {
    init {
        profile.validated()
        require(identity.uid == profile.currentUid && profile.name in identity.members) { "PROFILE_IDENTITY_MISMATCH" }
    }
}

object SuperuserProfileWire {
    private const val MAX_BYTES = 16 * 1024
    private val json = Json { encodeDefaults = true; explicitNulls = true }
    @JvmStatic fun encode(profile: SuProfile): String {
        val bytes = json.encodeToString(SuProfile.serializer(), profile.frozen()).toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_BYTES) { "PROFILE_TOO_LARGE" }
        return Base64.getEncoder().encodeToString(bytes)
    }
    @JvmStatic fun decode(encoded: String): SuProfile {
        require(encoded.length <= ((MAX_BYTES + 2) / 3) * 4) { "PROFILE_TOO_LARGE" }
        val bytes = Base64.getDecoder().decode(encoded)
        require(bytes.size <= MAX_BYTES) { "PROFILE_TOO_LARGE" }
        return json.decodeFromString(SuProfile.serializer(), String(bytes, Charsets.UTF_8)).frozen()
    }
}
