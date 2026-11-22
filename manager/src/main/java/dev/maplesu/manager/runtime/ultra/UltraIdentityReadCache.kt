package dev.maplesu.manager.runtime.ultra

/** One in-flight read, scoped to credential and boot; writes explicitly bypass cached observations. */
internal class UltraIdentityReadCache(private val now: () -> Long, private val ttlMillis: Long) {
    private data class Entry(val key: String, val boot: String, val at: Long, val identity: InstalledIdentity)
    private var entry: Entry? = null

    @Synchronized
    fun read(key: String?, boot: String?, force: Boolean = false, load: () -> InstalledIdentity): InstalledIdentity {
        val cached = entry
        val age = cached?.let { now() - it.at }
        if (!force && key != null && boot != null && cached?.key == key && cached.boot == boot &&
            age != null && age in 0 until ttlMillis) return cached.identity
        val identity = load()
        entry = if (key != null && boot != null && identity.source == Source.Readback) Entry(key, boot, now(), identity) else null
        return identity
    }

    @Synchronized
    fun invalidate() { entry = null }
}
