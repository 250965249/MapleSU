package com.maplesu.core.ui

import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.UserManager
import android.util.Log
import com.topjohnwu.superuser.ipc.RootService
import com.maplesu.core.IKsuInterface
import dev.maplesu.manager.runtime.ManagerCallerVerifier
import rikka.parcelablelist.ParcelableListSlice

/**
 * @author weishu
 * @date 2023/4/18.
 */

class KsuService : RootService() {

    private lateinit var callerVerifier: ManagerCallerVerifier

    override fun onCreate() {
        super.onCreate()
        callerVerifier = ManagerCallerVerifier(this)
    }

    companion object {
        private const val TAG = "KsuService"
    }

    override fun onBind(intent: Intent): IBinder {
        return Stub()
    }

    /**
     * The caller unbinds as soon as its query finishes, and this service exists only to
     * answer that query.
     *
     * <p>libsu keeps the remote process alive after the last binder reference unless the
     * service asks to stop, which left `:root:0` running while the application sat idle -
     * an idle root executor that the non-resident requirements forbid. Stopping here ties
     * the process lifetime to the operation.
     */
    override fun onUnbind(intent: Intent): Boolean {
        stopSelf()
        return super.onUnbind(intent)
    }

    private fun getAllUserIds(): IntArray {
        val um = getSystemService(USER_SERVICE) as UserManager
        // getAliveUsers() was added in API 31
        try {
            val method = um.javaClass.getMethod("getAliveUsers")
            val users = method.invoke(um) as List<*>
            return extractUserIds(users)
        } catch (e: Exception) {
            Log.e(TAG, "getAliveUsers reflection failed", e)
        }

        return intArrayOf(0)
    }

    private fun extractUserIds(users: List<*>?): IntArray {
        if (users.isNullOrEmpty()) return intArrayOf(0)

        return try {
            users.map { user ->
                user!!.javaClass.getField("id").getInt(user)
            }.toIntArray()
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting ID from UserInfo", e)
            intArrayOf(0)
        }
    }

    private fun getInstalledPackagesAll(flags: Int): ArrayList<PackageInfo> {
        val packages = ArrayList<PackageInfo>()
        for (userId in getAllUserIds()) {
            Log.i(TAG, "getInstalledPackagesAll: $userId")
            packages.addAll(getInstalledPackagesAsUser(flags, userId))
        }
        return packages
    }

    @Suppress("UNCHECKED_CAST")
    private fun getInstalledPackagesAsUser(flags: Int, userId: Int): List<PackageInfo> {
        return try {
            val pm: PackageManager = packageManager
            val method = pm.javaClass.getDeclaredMethod(
                "getInstalledPackagesAsUser",
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType
            )
            method.invoke(pm, flags, userId) as List<PackageInfo>
        } catch (e: Throwable) {
            Log.e(TAG, "err", e)
            ArrayList()
        }
    }

    private inner class Stub : IKsuInterface.Stub() {
        override fun getPackages(flags: Int): ParcelableListSlice<PackageInfo> = callerVerifier.withCallingManager {
            val list = getInstalledPackagesAll(flags)
            Log.i(TAG, "getPackages: ${list.size}")
            ParcelableListSlice(list)
        }

        override fun getUserIds(): IntArray = callerVerifier.withCallingManager {
            val ids = getAllUserIds()
            Log.i(TAG, "getUserIds: ${ids.contentToString()}")
            ids
        }
    }
}
