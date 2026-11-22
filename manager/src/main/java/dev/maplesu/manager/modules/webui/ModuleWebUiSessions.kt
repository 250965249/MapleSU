package dev.maplesu.manager.modules.webui

/** Process-local committed mutation delivery; no catalog/list refresh is a producer. */
internal object ModuleWebUiSessions {
    data class OwnerScope(val fullUid: Int, val epoch: Long, val hostInstance: String)
    private data class Subscription(val moduleId: String, val owner: OwnerScope?, val onRetired: () -> Unit)
    private val lock = Any()
    private val revisions = HashMap<String, Long>()
    private val listeners = HashMap<String, LinkedHashMap<Any, Subscription>>()
    private val ownerListeners = HashMap<OwnerScope, LinkedHashMap<Any, Subscription>>()
    private var observedOwner: OwnerScope? = null

    fun revision(moduleId: String): Long = synchronized(lock) { revisions[moduleId] ?: 0L }

    fun subscribe(moduleId: String, expectedRevision: Long, onRetired: () -> Unit): AutoCloseable? =
        subscribe(moduleId, expectedRevision, null, onRetired)

    fun subscribe(moduleId: String, expectedRevision: Long, owner: OwnerScope?,
                  onRetired: () -> Unit): AutoCloseable? {
        val token = Any()
        val subscription = Subscription(moduleId, owner, onRetired)
        synchronized(lock) {
            if ((revisions[moduleId] ?: 0L) != expectedRevision) return null
            if (owner != null && observedOwner != owner) return null
            listeners.getOrPut(moduleId) { LinkedHashMap() }[token] = subscription
            if (owner != null) ownerListeners.getOrPut(owner) { LinkedHashMap() }[token] = subscription
        }
        return AutoCloseable {
            synchronized(lock) { remove(token, subscription) }
        }
    }

    private fun remove(token: Any, subscription: Subscription) {
        listeners[subscription.moduleId]?.let {
            it.remove(token)
            if (it.isEmpty()) listeners.remove(subscription.moduleId)
        }
        subscription.owner?.let { owner ->
            ownerListeners[owner]?.let {
                it.remove(token)
                if (it.isEmpty()) ownerListeners.remove(owner)
            }
        }
    }

    /** Only an observed, authenticated tuple changes this scope; missing facts do not revoke it. */
    fun observedOwner(owner: OwnerScope) {
        val retired = synchronized(lock) {
            val previous = observedOwner
            if (previous == owner) return
            observedOwner = owner
            val entries = previous?.let { ownerListeners.remove(it) }?.entries?.toList().orEmpty()
            entries.forEach { remove(it.key, it.value) }
            entries.map { it.value.onRetired }
        }
        retired.forEach { callback -> runCatching { callback() } }
    }

    fun committed(moduleId: String) {
        val retired = synchronized(lock) {
            revisions[moduleId] = (revisions[moduleId] ?: 0L) + 1L
            val entries = listeners.remove(moduleId)?.entries?.toList().orEmpty()
            entries.forEach { remove(it.key, it.value) }
            entries.map { it.value.onRetired }
        }
        retired.forEach { callback -> runCatching { callback() } }
    }
}
