package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Bundle

/**
 * Which entry points exist for applications that want Root.
 *
 * <p>The architecture is one authorization core with two entries. The
 * cooperative entry binds the restricted Root Binder. Traditional Hook clients
 * execute the standard su path through the SDK's UID-scoped redirect; they add no
 * global file or mount. Credential-backed runtimes retain their own client path.
 *
 * The switch stops future traditional setup without changing authorization or
 * the broker. An already active SDK redirect or credential-backed client remains
 * reported for this boot. Legacy Hook overlays are removed in either mode.
 */
object SuEntryMode {
    enum class Mode(val wire: String) {
        /** Broker only: no public su file, no standard-path overlay. */
        COOPERATIVE_MINIMAL("cooperative"),

        /** Broker plus the runtime-specific traditional su entry. */
        TRADITIONAL_COMPAT("traditional"),
    }

    private const val PREFS = "su_entry_mode"
    private const val KEY = "mode"

    @Volatile private var cached: Mode? = null

    fun read(context: Context): Mode {
        cached?.let { return it }
        val stored = context.applicationContext
            .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, null)
        // A missing or unreadable value keeps the entry that existing apps can use;
        // silently dropping the traditional client would break every caller that
        // only knows how to exec su.
        val mode = Mode.entries.firstOrNull { it.wire == stored } ?: Mode.TRADITIONAL_COMPAT
        cached = mode
        return mode
    }

    /** Management-only: callers are the Manager process or its instrumentation, never a client. */
    fun write(context: Context, mode: Mode) {
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, mode.wire).commit()
        cached = mode
    }

    /** Independent, queryable report of which entries exist and what they cost. */
    fun describe(context: Context): Bundle {
        val mode = read(context)
        val status = RuntimeDeployment.status()
        return Bundle().apply {
            putString("mode", mode.wire)
            putBoolean("publisherEnabled", mode == Mode.TRADITIONAL_COMPAT)
            putString("clientPath", status.clientPath)
            putString("standardPath", status.standardPath)
            putBoolean("brokerReady", status.brokerReady)
            putString("deploymentError", status.error)
            if (mode == Mode.COOPERATIVE_MINIMAL && (status.clientPath != null || status.standardPath != null)) {
                // Accurate rather than convenient: the flag stops publication, it
                // does not disable an already active traditional entry.
                putString("stalePublication",
                    "a traditional client from an earlier publication is still present in this boot cycle")
            }
        }
    }

    /** Test hook: drops the process cache so the next read reconsults storage. */
    internal fun invalidate() { cached = null }
}
