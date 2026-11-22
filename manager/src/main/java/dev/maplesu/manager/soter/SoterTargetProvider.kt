package dev.maplesu.manager.soter

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle

/**
 * Root-only hand-off of the bound `ISoterService` binder to the module daemon.
 *
 * The daemon is a uid-0 `app_process` with no application identity, so it cannot bind the
 * service itself; the manager binds it with a real app identity and publishes the binder
 * here. A `ContentProvider.call` Bundle is a legitimate way to move a Binder across
 * processes (unlike a unix socket, which cannot carry one).
 *
 * Access control: only uid 0 may read the binder. Every other caller gets null, so the
 * exported provider leaks nothing to ordinary apps.
 */
class SoterTargetProvider : ContentProvider() {

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        if (Binder.getCallingUid() != 0) return null
        if (method != METHOD_TARGET) return null
        val binder = SoterLane.targetBinder() ?: return null
        return Bundle().apply { putBinder(KEY_TARGET, binder) }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    companion object {
        const val AUTHORITY = "dev.maplesu.manager.soter"
        const val METHOD_TARGET = "target"
        const val KEY_TARGET = "target"
    }
}
