package dev.maplesu.manager.runtime

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Root authorization state for jailbreak mode.
 *
 * The review asks for the original policy surface (approve / deny / revoke / master
 * switch) with a real third-party SU path. In jailbreak mode the resident executor
 * has no writable storage of its own (the shell domain cannot write any app or
 * staging directory - measured), so the state lives in the Manager's
 * device-protected storage and the executor only ever runs what this class has
 * already allowed. The file is app-private, single-writer and rewritten atomically.
 */
object JailbreakGrantStore {
    private const val FILE = "jailbreak-grants.json"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_GRANTS = "grants"

    fun isEnabled(context: Context): Boolean = read(context).getBoolean(KEY_ENABLED)

    fun setEnabled(context: Context, enabled: Boolean): Boolean {
        val document = read(context)
        document.put(KEY_ENABLED, enabled)
        write(context, document)
        return true
    }

    fun hasGrant(context: Context, uid: Int): Boolean = grants(context).contains(uid)

    fun grant(context: Context, uid: Int): Boolean {
        if (uid <= 0) return false
        val document = read(context)
        val list = document.getJSONArray(KEY_GRANTS)
        if (!contains(list, uid)) list.put(uid)
        document.put(KEY_GRANTS, list)
        write(context, document)
        return true
    }

    fun revoke(context: Context, uid: Int): Boolean {
        val document = read(context)
        val list = document.getJSONArray(KEY_GRANTS)
        val kept = JSONArray()
        for (index in 0 until list.length()) {
            val value = list.optInt(index, -1)
            if (value != uid && value > 0) kept.put(value)
        }
        document.put(KEY_GRANTS, kept)
        write(context, document)
        return true
    }

    fun grantCount(context: Context): Int = grants(context).size

    /**
     * The uids this legacy store still names. Used **only** by the one-shot import
     * (design §3.1): no decision path reads this file any more, so a grant written here
     * after the import has no effect and cannot become a fifth authority.
     */
    fun grantedUids(context: Context): Set<Int> = grants(context)

    /** A request is allowed only when the master switch is on and the uid holds a grant. */
    fun admits(context: Context, uid: Int): Boolean = isEnabled(context) && hasGrant(context, uid)

    private fun grants(context: Context): Set<Int> {
        val list = read(context).getJSONArray(KEY_GRANTS)
        val result = LinkedHashSet<Int>()
        for (index in 0 until list.length()) {
            val value = list.optInt(index, -1)
            if (value > 0) result.add(value)
        }
        return result
    }

    private fun contains(list: JSONArray, uid: Int): Boolean {
        for (index in 0 until list.length()) {
            if (list.optInt(index, -1) == uid) return true
        }
        return false
    }

    private fun read(context: Context): JSONObject = try {
        val file = file(context)
        if (file.isFile) JSONObject(file.readText()) else defaults()
    } catch (error: Throwable) {
        // A corrupt record must not silently grant anything: fall back to "off".
        defaults().put(KEY_ENABLED, false)
    }

    private fun defaults(): JSONObject = JSONObject()
        .put(KEY_ENABLED, true)
        .put(KEY_GRANTS, JSONArray())

    private fun write(context: Context, document: JSONObject) {
        val target = file(context)
        val temporary = File(target.parentFile, target.name + ".tmp")
        temporary.writeText(document.toString())
        if (!temporary.renameTo(target)) {
            target.delete()
            temporary.renameTo(target)
        }
    }

    private fun file(context: Context): File =
        File(context.createDeviceProtectedStorageContext().dataDir ?: context.filesDir, FILE)
}
