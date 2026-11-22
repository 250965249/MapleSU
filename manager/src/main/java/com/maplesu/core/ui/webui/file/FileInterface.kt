package com.maplesu.core.ui.webui.file

import android.util.Log
import android.webkit.JavascriptInterface
import com.topjohnwu.superuser.io.SuFile
import org.json.JSONArray

class FileInterface(private val path: String, private val owner: KsuIO) {
    private val suFile: SuFile get() = owner.file(path)

    private inline fun <T> operation(action: () -> T): Result<T> = runCatching {
        check(owner.isOpen()) { "WebUI page closed" }
        action()
    }

    @JavascriptInterface
    fun exists(): Boolean = operation { suFile.exists() }.getOrDefault(false)

    @JavascriptInterface
    fun isFile(): Boolean = operation { suFile.isFile }.getOrDefault(false)

    @JavascriptInterface
    fun isDirectory(): Boolean = operation { suFile.isDirectory }.getOrDefault(false)

    @JavascriptInterface
    fun canRead(): Boolean = operation { suFile.canRead() }.getOrDefault(false)

    @JavascriptInterface
    fun canWrite(): Boolean = operation { suFile.canWrite() }.getOrDefault(false)

    @JavascriptInterface
    fun canExecute(): Boolean = operation { suFile.canExecute() }.getOrDefault(false)

    @JavascriptInterface
    fun createNewFile(): Boolean = operation { suFile.createNewFile() }.getOrDefault(false)

    @JavascriptInterface
    fun delete(): Boolean = operation { suFile.delete() }.getOrDefault(false)

    @JavascriptInterface
    fun deleteRecursive(): Boolean = operation { suFile.deleteRecursive() }.getOrDefault(false)

    @JavascriptInterface
    fun mkdir(): Boolean = operation { suFile.mkdir() }.getOrDefault(false)

    @JavascriptInterface
    fun mkdirs(): Boolean = operation { suFile.mkdirs() }.getOrDefault(false)

    @JavascriptInterface
    fun renameTo(destPath: String): Boolean = operation {
        suFile.renameTo(owner.file(destPath))
    }.getOrDefault(false)

    @JavascriptInterface
    fun list(): String = operation {
        val names = suFile.list() ?: emptyArray()
        JSONArray(names.toList()).toString()
    }.getOrElse { "[]" }

    @JavascriptInterface
    fun listFiles(): String = operation {
        val paths = suFile.listFiles()?.map { it.absolutePath } ?: emptyList()
        JSONArray(paths).toString()
    }.getOrElse { "[]" }

    @JavascriptInterface
    fun length(): Long = operation { suFile.length() }.getOrDefault(-1L)

    @JavascriptInterface
    fun lastModified(): Long = operation { suFile.lastModified() }.getOrDefault(-1L)

    @JavascriptInterface
    fun setLastModified(time: Long): Boolean = operation { suFile.setLastModified(time) }.getOrDefault(false)

    @JavascriptInterface
    fun getAbsolutePath(): String = operation { suFile.absolutePath }.getOrDefault(path)

    @JavascriptInterface
    fun getCanonicalPath(): String = operation { suFile.canonicalPath }.getOrDefault(path)

    @JavascriptInterface
    fun getParent(): String? = operation { suFile.parent }.getOrNull()

    @JavascriptInterface
    fun getPath(): String = path

    @JavascriptInterface
    fun getName(): String = operation { suFile.name }.getOrDefault("")

    @JavascriptInterface
    fun isHidden(): Boolean = operation { suFile.isHidden }.getOrDefault(false)

    @JavascriptInterface
    fun isBlock(): Boolean = operation { suFile.isBlock }.getOrDefault(false)

    @JavascriptInterface
    fun isCharacter(): Boolean = operation { suFile.isCharacter }.getOrDefault(false)

    @JavascriptInterface
    fun isSymlink(): Boolean = operation { suFile.isSymlink }.getOrDefault(false)

    @JavascriptInterface
    fun createNewSymlink(target: String): Boolean = operation {
        suFile.createNewSymlink(target)
    }.getOrDefault(false)

    @JavascriptInterface
    fun createNewLink(existing: String): Boolean = operation {
        suFile.createNewLink(existing)
    }.getOrDefault(false)

    @JavascriptInterface
    fun clear(): Boolean = operation { suFile.clear() }.getOrDefault(false)

    @JavascriptInterface
    fun setReadOnly(): Boolean = operation { suFile.setReadOnly() }.getOrDefault(false)

    @JavascriptInterface
    fun setReadable(readable: Boolean, ownerOnly: Boolean): Boolean =
        operation { suFile.setReadable(readable, ownerOnly) }.getOrDefault(false)

    @JavascriptInterface
    fun setWritable(writable: Boolean, ownerOnly: Boolean): Boolean =
        operation { suFile.setWritable(writable, ownerOnly) }.getOrDefault(false)

    @JavascriptInterface
    fun setExecutable(executable: Boolean, ownerOnly: Boolean): Boolean =
        operation { suFile.setExecutable(executable, ownerOnly) }.getOrDefault(false)

    @JavascriptInterface
    fun getFreeSpace(): Long = operation { suFile.freeSpace }.getOrDefault(-1L)

    @JavascriptInterface
    fun getTotalSpace(): Long = operation { suFile.totalSpace }.getOrDefault(-1L)

    @JavascriptInterface
    fun getUsableSpace(): Long = operation { suFile.usableSpace }.getOrDefault(-1L)

    @JavascriptInterface
    fun newInputStream(): String {
        return operation {
            owner.openInput { suFile.newInputStream() }
        }.onFailure { Log.e(TAG, "newInputStream failed", it) }.getOrElse { "" }
    }

    @JavascriptInterface
    fun newOutputStream(append: Boolean): String {
        return operation {
            owner.openOutput { openBoundOutputStream(suFile, append) }
        }.onFailure { Log.e(TAG, "newOutputStream failed", it) }.getOrElse { "" }
    }

    @JavascriptInterface
    fun newOutputStream(): String = newOutputStream(false)

    override fun toString(): String = path
}
