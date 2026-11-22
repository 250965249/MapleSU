package com.maplesu.core.data.repository

import com.maplesu.core.data.model.WEBVIEW_ZYGOTE_UID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope

/** Display-only snapshot; profile details and writes still validate the current installation. */
internal class UltraAppListSnapshot private constructor(private val packages: Set<String>, private val uids: Set<Int>?) {
    val size: Int get() = packages.size

    fun isGranted(packageName: String, uid: Int): Boolean =
        uid != WEBVIEW_ZYGOTE_UID && (uids?.contains(uid) ?: (packageName in packages))

    companion object {
        suspend fun <T> withPackages(
            packages: () -> T,
            refresh: () -> Boolean,
            grantedPackages: () -> Set<String>,
            grantedUids: (() -> Set<Int>)? = null,
        ): Pair<T, UltraAppListSnapshot> = coroutineScope {
            val applications = async(Dispatchers.IO) { packages() }
            val grants = async(Dispatchers.IO) { read(refresh, grantedPackages, grantedUids) }
            applications.await() to grants.await()
        }

        fun read(refresh: () -> Boolean, grantedPackages: () -> Set<String>, grantedUids: (() -> Set<Int>)? = null): UltraAppListSnapshot {
            check(refresh()) { "ULTRA_AUTH_REFRESH_FAILED" }
            return UltraAppListSnapshot(grantedPackages().toSet(), grantedUids?.invoke()?.toSet())
        }
    }
}
