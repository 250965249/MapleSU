package dev.maplesu.manager.runtime

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Log
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MapleSuCredentialStore(context: Context) {
    private val applicationContext = context.applicationContext
    private val file = AtomicFile(File(applicationContext.noBackupFilesDir, CREDENTIAL_FILE))

    private val legacyFile = AtomicFile(File(applicationContext.noBackupFilesDir, LEGACY_CREDENTIAL_FILE))
    private val alias = "${applicationContext.packageName}.maplesu.credential.v1"
    private val legacyAlias = applicationContext.packageName + dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_ALIAS_SUFFIX
    private val associatedData = "$alias:48:47+NUL".toByteArray(Charsets.US_ASCII)

    fun load(): ByteArray? = synchronized(lock) { read() }

    /** Preparing a candidate must retain the same credential across App restarts and the first reboot. */
    fun getOrCreate(): ByteArray = synchronized(lock) {
        read()?.let { return@synchronized it }
        val random = SecureRandom()
        val credential = ByteArray(48) { alphabet[random.nextInt(alphabet.size)] }
        try {
            save(credential)
            credential.copyOf()
        } finally {
            credential.fill(0)
        }
    }

    /** Pair only after the supplied credential has produced an independently checked UID-0 shell. */
    fun pair(credential: ByteArray) = synchronized(lock) {
        requireValidMapleSuCredential(credential)
        val copy = credential.copyOf()
        try {
            MapleSuCommandExecutor(applicationContext).openShell(copy).use { shell ->
                check(shell.isAlive && shell.isRoot) { "MAPLESU_PAIRING_FAILED" }
            }
            save(copy)
            MapleSuRuntime.invalidate()
        } finally {
            copy.fill(0)
        }
    }

    private fun read(): ByteArray? {
        val source = when {
            exists(file) -> file
            exists(legacyFile) -> legacyFile
            else -> return null
        }
        val encoded = source.openRead().use { input ->
            val bytes = ByteArray(4 + 12 + 48 + 16)
            var offset = 0
            while (offset < bytes.size) {
                val count = input.read(bytes, offset, bytes.size - offset)
                if (count < 0) throw IOException("MAPLESU_CREDENTIAL_STORE_INVALID")
                offset += count
            }
            if (input.read() != -1) throw IOException("MAPLESU_CREDENTIAL_STORE_INVALID")
            bytes
        }
        val storedAlias = when {
            encoded.copyOfRange(0, 4).contentEquals(magic) -> alias
            encoded.copyOfRange(0, 4).contentEquals(legacyMagic) -> legacyAlias
            else -> throw IOException("MAPLESU_CREDENTIAL_STORE_INVALID")
        }
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(storedAlias, null) as? SecretKey
            ?: throw IOException("MAPLESU_CREDENTIAL_KEY_MISSING")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encoded, 4, 12))
        cipher.updateAAD("$storedAlias:48:47+NUL".toByteArray(Charsets.US_ASCII))
        val credential = cipher.doFinal(encoded, 16, encoded.size - 16)
        try {
            requireValidMapleSuCredential(credential)
            if (source === legacyFile || storedAlias == legacyAlias) migrate(credential)
            return credential.copyOf()
        } finally {
            credential.fill(0)
        }
    }

    private fun exists(target: AtomicFile) =
        target.baseFile.exists() || File(target.baseFile.path + ".bak").exists()

    private fun migrate(credential: ByteArray) {
        try {
            save(credential)
            legacyFile.delete()
        } catch (error: Exception) {
            Log.w("MapleSUCredential", "Credential migration deferred", error)
        }
    }

    private fun save(credential: ByteArray) {
        requireValidMapleSuCredential(credential)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = keyStore.getKey(alias, null) as? SecretKey ?: KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build())
        }.generateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(associatedData)
        check(cipher.iv.size == 12) { "MAPLESU_CREDENTIAL_IV_INVALID" }
        val encrypted = cipher.doFinal(credential)
        val encoded = ByteBuffer.allocate(magic.size + cipher.iv.size + encrypted.size)
            .put(magic).put(cipher.iv).put(encrypted).array()
        val output = file.startWrite()
        try {
            output.write(encoded)
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }

    companion object {
        private const val CREDENTIAL_FILE = "maplesu-credential.bin"
        private const val LEGACY_CREDENTIAL_FILE = dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE
        private val lock = Any()
        private val magic = byteArrayOf('M'.code.toByte(), 'S'.code.toByte(), 'K'.code.toByte(), 2)
        private val legacyMagic = byteArrayOf('M'.code.toByte(), 'S'.code.toByte(), 'K'.code.toByte(), 1)
        private val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            .toByteArray(Charsets.US_ASCII)
    }
}

internal fun requireValidMapleSuCredential(credential: ByteArray) {
    require(credential.size == 48 && credential.all {
        it in 'A'.code.toByte()..'Z'.code.toByte() ||
            it in 'a'.code.toByte()..'z'.code.toByte() ||
            it in '0'.code.toByte()..'9'.code.toByte()
    }) { "Invalid MapleSU credential format" }
}
