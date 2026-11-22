package dev.maplesu.manager.runtime.authorization

import android.content.Context
import android.os.SystemClock

/**
 * Authorization queries without a resident executor.
 *
 * <p>Every call starts one short-lived root process that runs [AuthorizationTool] against
 * the same store the resident endpoint used, and exits. The Manager therefore never has
 * to keep a root service alive just to list applications, read the switch, or check a
 * single grant - which is what previously kept `:root:0` running from the first UI frame.
 *
 * <p>The tool is a separate `app_process` with the Manager APK on its class path, so the
 * store logic and the install-identity checks are the same code, not a copy.
 */
object DirectPolicy {
    /** Returns the payload of the tool's `OK` line, or null when the operation failed. */
    private fun run(context: Context, vararg arguments: String): String? {
        return when (val reply = SuperuserControl.runTool(context, *arguments)) {
            is RootToolOutcome.Ok -> reply.payload
            is RootToolOutcome.Failed -> {
                // Diagnostics only: the tool never prints credential material. The named
                // seccomp code is what makes a killed child distinguishable from a
                // missing transport in a bug report.
                android.util.Log.w(
                    "MapleSU",
                    "SU_POLICY_TOOL_FAILED code=${reply.code}",
                )
                null
            }
        }
    }

    /**
     * A whole screen asks about every application. Querying per row would start one root
     * process per row, so the reads share a short-lived snapshot instead.
     */
    private class Snapshot(val enabled: Boolean, val uids: Set<Int>, val at: Long)

    @Volatile private var snapshot: Snapshot? = null

    private fun snapshot(context: Context, maxAgeMs: Long = 2_000): Snapshot? {
        val cached = snapshot
        if (cached != null && SystemClock.elapsedRealtime() - cached.at <= maxAgeMs) return cached
        val current = SuperuserControl.snapshot(context) ?: return null
        return Snapshot(current.enabled, current.grants.keys, SystemClock.elapsedRealtime())
            .also { snapshot = it }
    }

    internal fun invalidate() { snapshot = null }

    fun isEnabled(context: Context): Boolean? = snapshot(context)?.enabled

    fun setEnabled(context: Context, enabled: Boolean): Boolean? =
        enabled.takeIf { SuperuserControl.setEnabled(context, enabled).succeeded }

    fun grantCount(context: Context): Int? = snapshot(context)?.uids?.size

    /**
     * List/profile reads: served from the shared snapshot. One screen asks about every
     * installed application, and a one-shot root process per row made the superuser list
     * take tens of seconds - the regression this cache exists to prevent.
     *
     * <p>When the snapshot cannot be produced, this answers `null` instead of falling back
     * to a per-application process: an unknown answer must not turn a list load into one
     * root process per row.
     */
    fun hasGrant(context: Context, uid: Int): Boolean? =
        snapshot(context)?.let { uid in it.uids }

    /**
     * Security decisions (delivery, wiring): always ask. A grant or revoke written through
     * another path must be visible immediately here, and this runs once per operation.
     */
    fun hasGrantStrict(context: Context, uid: Int): Boolean? =
        run(context, "has", uid.toString())?.toBooleanStrictOrNull()

    /** Granted uids from the shared snapshot; display and reconciliation only. */
    fun grantedUids(context: Context): Set<Int>? = snapshot(context)?.uids

    fun grant(context: Context, uid: Int): Boolean =
        SuperuserControl.grant(context, uid).succeeded

    fun revoke(context: Context, uid: Int): Boolean =
        SuperuserControl.revoke(context, uid).succeeded
}
