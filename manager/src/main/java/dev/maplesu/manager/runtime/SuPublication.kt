package dev.maplesu.manager.runtime

import android.content.Context
import android.util.Log
import dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities
import dev.maplesu.manager.runtime.authorization.DirectPolicy
import java.io.File

/**
 * Shared client deployment, aligned with the upstream kit.
 *
 * <p>Upstream installs one `su` into a hidden directory named from the first 16 characters
 * of the credential (`/data/<name>/su`), labels the directory and the file `system_file`,
 * and then implants that directory into a target's PATH. This does the same, so the deployed
 * client has the same path shape and label, and is not readable by other applications.
 *
 * <p>Three properties keep it from leaking anything:
 *  - the client file is `0711`: every application may execute it, none may read it, and it
 *    carries no credential at all (it forwards to the caller's own 0700 image);
 *  - the granted uid list is `0644` but holds only uids, never paths;
 *  - the `u/` directory that maps a uid to its library directory is `0711`, so an
 *    application can open its own entry by name but cannot list which applications are
 *    granted.
 *
 * <p>No long-lived process is involved: publishing is one short-lived root operation.
 */
object SuPublication {
    private const val NAME_LENGTH = 16
    private const val AUTHORIZED_NAME = "authorized"
    private const val MAP_NAME = "u"

    /** `/data/<16 hex characters>` - the same shape upstream uses for its hidden directory. */
    fun directory(context: Context): String {
        val name = credentialName(context) ?: return "/data/maplesu-su"
        return "/data/$name"
    }

    fun suPath(context: Context): String = "${directory(context)}/su"
    fun suDirectory(context: Context): String = directory(context) + "/"
    private fun authorizedPath(context: Context): String = "${directory(context)}/$AUTHORIZED_NAME"
    private fun mapDirectory(context: Context): String = "${directory(context)}/$MAP_NAME"

    private fun credentialName(context: Context): String? {
        val credential = runCatching { MapleSuCredentialStore(context.applicationContext).load() }.getOrNull()
            ?: return null
        return try {
            val text = StringBuilder()
            for (index in 0 until NAME_LENGTH / 2) {
                text.append("%02x".format(credential[index]))
            }
            text.toString()
        } finally {
        }
    }

    private const val RECORD = "published-directory"

    /** Directory published before this one, which must not survive a credential change. */
    fun previousDirectory(context: Context): String? {
        val record = File(context.applicationContext.filesDir, RECORD)
        if (!record.isFile) return null
        return record.readText().trim().ifEmpty { null }
    }

    fun publish(context: Context): Boolean {
        val application = context.applicationContext
        val source = File(application.applicationInfo.nativeLibraryDir, "libmaplesu_su.so")
        if (!source.isFile) return false
        val directory = directory(application)
        val authorized = DirectPolicy.grantedUids(application).orEmpty().sorted().joinToString("\n")
        val staging = File(application.cacheDir, "publish-${System.nanoTime()}.img")
        val list = File(application.cacheDir, "authorized-${System.nanoTime()}.txt")
        val links = File(application.cacheDir, "links-${System.nanoTime()}.sh")
        return try {
            // The shared client carries NO credential: it is world-executable and
            // world-unreadable, so it could neither hold a key nor read one back out of
            // itself. It forwards to the calling application's own 0700 image, which is
            // where the credential lives and where nothing else can read it.
            staging.outputStream().use { output ->
                source.inputStream().use { it.copyTo(output) }
            }
            list.writeText(if (authorized.isEmpty()) "" else "$authorized\n")
            // The client has to learn where the calling application keeps its own image, and
            // it cannot ask: listing /data/app is denied to applications, and a freshly
            // executed helper has no application library in its own maps. One symlink per
            // granted uid answers exactly that, and because the directory is 0711 an
            // application can open its own entry but cannot enumerate the others.
            val entries = DirectPolicy.grantedUids(application).orEmpty().sorted().mapNotNull { uid ->
                val name = AndroidApplicationIdentities(application).read(uid)?.packageName
                    ?: return@mapNotNull null
                val info = runCatching { application.packageManager.getApplicationInfo(name, 0) }
                    .getOrNull() ?: return@mapNotNull null
                uid to info.nativeLibraryDir
            }
            links.writeText(entries.joinToString("\n") { (uid, target) ->
                "/system/bin/ln -sfn '$target' '${mapDirectory(application)}/$uid'"
            })
            val script = """
                set -eu
                /system/bin/mkdir -p $directory
                /system/bin/chown 0:0 $directory
                /system/bin/chmod 0755 $directory
                /system/bin/chcon u:object_r:system_file:s0 $directory
                /system/bin/cp -f '${staging.absolutePath}' '$directory/su'
                /system/bin/chown 0:0 '$directory/su'
                /system/bin/chmod 0711 '$directory/su'
                /system/bin/chcon u:object_r:system_file:s0 '$directory/su'
                # Atomic replace: the client may read the list while it is rewritten, and a
                # truncated read would deny a legitimately granted caller.
                /system/bin/cp -f '${list.absolutePath}' '$directory/authorized.new'
                /system/bin/mv -f '$directory/authorized.new' '${authorizedPath(application)}'
                /system/bin/chown 0:0 '${authorizedPath(application)}'
                /system/bin/chmod 0644 '${authorizedPath(application)}'
                /system/bin/chcon u:object_r:system_file:s0 '${authorizedPath(application)}'
                /system/bin/mkdir -p '${mapDirectory(application)}'
                /system/bin/chown 0:0 '${mapDirectory(application)}'
                /system/bin/chmod 0711 '${mapDirectory(application)}'
                /system/bin/chcon u:object_r:system_file:s0 '${mapDirectory(application)}'
                /system/bin/rm -f '${mapDirectory(application)}'/*
                /system/bin/sh '${links.absolutePath}'
                /system/bin/rm -f '${staging.absolutePath}' '${list.absolutePath}' '${links.absolutePath}'
            """.trimIndent()
            val result = DirectRoot.run(application, script)
            if (result.code == 0) {
                // A new credential means a new directory name; the previous one still holds a
                // valid credential and stays on the PATH baked into already-wired libraries.
                val record = File(application.filesDir, RECORD)
                val previous = record.takeIf { it.isFile }?.readText()?.trim()
                if (!previous.isNullOrEmpty() && previous != directory) {
                    DirectRoot.run(application, "/system/bin/rm -rf '$previous'")
                    Log.i("MapleSU", "SU_PUBLISH_CLEANUP removed=$previous")
                }
                record.writeText(directory)
                Log.i("MapleSU", "SU_PUBLISHED path=$directory/su uids=[$authorized]")
                true
            } else {
                Log.w("MapleSU", "SU_PUBLISH_FAILED code=${result.code} out=${result.output.take(200)}")
                false
            }
        } finally {
            staging.delete()
            list.delete()
            links.delete()
        }
    }

    fun withdraw(context: Context): Boolean =
        DirectRoot.run(context, "/system/bin/rm -rf '${directory(context)}'").code == 0
}
