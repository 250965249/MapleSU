package dev.maplesu.manager.modules

/** Coalesces a rejected start or preparation until the next actual Activity resume. */
internal class LiteModuleBootDispatch {
    private var pending = false
    private var nextToken = 0L
    private var starting: Long? = null
    private var active: Long? = null

    @Synchronized
    fun begin(allowed: Boolean, fromForeground: Boolean): Long? {
        if (!allowed) {
            pending = false
            return null
        }
        if (starting != null || active != null || pending != fromForeground) return null
        return (++nextToken).also {
            starting = it
            active = it
            pending = false
        }
    }

    @Synchronized
    fun finish(token: Long, submitted: Boolean, deferred: Boolean, allowed: Boolean) {
        if (starting != token) return
        starting = null
        if (!submitted) {
            if (active == token) active = null
            pending = deferred && allowed
        }
    }

    @Synchronized
    fun complete(token: Long?, retryPreparation: Boolean, allowed: Boolean) {
        if (token == null || active != token) return
        active = null
        pending = retryPreparation && allowed
    }
}
