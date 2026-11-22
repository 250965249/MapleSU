package dev.maplesu.manager.runtime

import android.content.AttributionSource
import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import android.os.Process
import org.lsposed.hiddenapibypass.HiddenApiBypass

/** A real Root-owned external reference to the directory that publishes this Root endpoint. */
internal class BinderAdmissionDirectoryLease(context: Context, private val root: IBinder) : AutoCloseable {
    private val token = Binder()
    private val user = context.applicationInfo.uid / 100000
    private val activity: Any
    private val provider: Any
    private val activityApi = Class.forName("android.app.IActivityManager")
    private val providerApi = Class.forName("android.content.IContentProvider")
    private val attribution = AttributionSource.Builder(Process.myUid()).setPackageName(context.packageName).build()
    val directory: Bundle

    init {
        check(Process.myUid() == 0) { "BINDER_ADMISSION_DIRECTORY_ROOT_REQUIRED" }
        HiddenApiBypass.addHiddenApiExemptions("Landroid/app/ActivityManager;", "Landroid/app/IActivityManager;",
            "Landroid/app/ContentProviderHolder;", "Landroid/content/IContentProvider;")
        activity = Class.forName("android.app.ActivityManager").getDeclaredMethod("getService").invoke(null)!!
        val holder = activityApi.getMethod("getContentProviderExternal", String::class.java,
            Int::class.javaPrimitiveType, IBinder::class.java, String::class.java)
            .invoke(activity, BinderAdmissionDirectoryProvider.AUTHORITY, user, token, "maplesu-binder-directory")
            ?: error("BINDER_ADMISSION_DIRECTORY_MISSING")
        provider = holder.javaClass.getField("provider").get(holder)
            ?: error("BINDER_ADMISSION_DIRECTORY_PROVIDER_MISSING")
        try {
            directory = call("publish")
            check(directory.getBoolean("published") && directory.getInt("directoryUid") == context.applicationInfo.uid) {
                "BINDER_ADMISSION_DIRECTORY_IDENTITY"
            }
        } catch (error: Exception) {
            runCatching { removeReference() }
            throw error
        }
    }

    private fun call(method: String): Bundle = providerApi.getMethod("call", AttributionSource::class.java,
        String::class.java, String::class.java, String::class.java, Bundle::class.java)
        .invoke(provider, attribution, BinderAdmissionDirectoryProvider.AUTHORITY, method, null,
            Bundle().apply { putBinder("root", root) }) as Bundle

    private fun removeReference() {
        activityApi.getMethod("removeContentProviderExternalAsUser", String::class.java, IBinder::class.java,
            Int::class.javaPrimitiveType).invoke(activity, BinderAdmissionDirectoryProvider.AUTHORITY, token, user)
    }

    override fun close() {
        try { call("clear") } finally { removeReference() }
    }
}
