package dev.maplesu.manager.runtime

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.IBinder

/** Debug-only, non-exported publication directory; ordinary clients still use peekService. */
class BinderAdmissionDirectoryProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        check(Binder.getCallingUid() == 0) { "BINDER_ADMISSION_DIRECTORY_ROOT_ONLY" }
        return synchronized(lock) {
            when (method) {
                "publish" -> {
                    val root = requireNotNull(extras?.getBinder("root"))
                    check(endpoint == null) { "BINDER_ADMISSION_DIRECTORY_ALREADY_PUBLISHED" }
                    val death = IBinder.DeathRecipient {
                        synchronized(lock) {
                            if (endpoint == root) { endpoint = null; recipient = null }
                        }
                    }
                    root.linkToDeath(death, 0)
                    endpoint = root
                    recipient = death
                }
                "clear" -> {
                    check(endpoint == extras?.getBinder("root")) { "BINDER_ADMISSION_DIRECTORY_OWNER" }
                    recipient?.let { endpoint?.unlinkToDeath(it, 0) }
                    endpoint = null
                    recipient = null
                }
                else -> error("BINDER_ADMISSION_DIRECTORY_METHOD")
            }
            Bundle().apply {
                putInt("directoryUid", android.os.Process.myUid())
                putInt("directoryPid", android.os.Process.myPid())
                putBoolean("published", endpoint != null)
            }
        }
    }

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = error("No directory rows")
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = error("No directory rows")
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = error("No directory rows")

    companion object {
        const val AUTHORITY = "dev.maplesu.manager.debug.binder_directory"
        private val lock = Any()
        @Volatile internal var endpoint: IBinder? = null
            private set
        private var recipient: IBinder.DeathRecipient? = null
    }
}
