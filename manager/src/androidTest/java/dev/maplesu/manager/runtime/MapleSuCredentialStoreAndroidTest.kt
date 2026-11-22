package dev.maplesu.manager.runtime

import android.content.Context
import android.content.ContextWrapper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

class MapleSuCredentialStoreAndroidTest {
    private lateinit var directory: File
    private lateinit var context: Context

    @Before fun setUp() {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        directory = File(target.cacheDir, "credential-store-${UUID.randomUUID()}").apply { mkdirs() }
        val storePackageName = "${target.packageName}.credentialtest.${UUID.randomUUID()}"
        context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getNoBackupFilesDir(): File = directory
            override fun getPackageName(): String = storePackageName
        }
    }

    @After fun tearDown() {
        directory.deleteRecursively()
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry("${context.packageName}.maplesu.credential.v1")
            deleteEntry(context.packageName + dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_ALIAS_SUFFIX)
        }
    }

    @Test fun credentialSurvivesReopeningWithoutPlaintextStorage() {
        val credential = MapleSuCredentialStore(context).getOrCreate()
        try {
            requireValidMapleSuCredential(credential)
            val reopened = MapleSuCredentialStore(context).getOrCreate()
            try { assertArrayEquals(credential, reopened) } finally { reopened.fill(0) }
            val disk = File(directory, "maplesu-credential.bin").readBytes()
            assertArrayEquals(byteArrayOf(77, 83, 75, 2), disk.copyOfRange(0, 4))
            assertTrue(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .containsAlias("${context.packageName}.maplesu.credential.v1"))
            val secret = credential.toString(Charsets.US_ASCII)
            assertFalse(disk.toString(Charsets.ISO_8859_1).contains(secret))
        } finally { credential.fill(0) }
    }

    @Test fun corruptStoreDoesNotSilentlyReplaceTheBootCredential() {
        MapleSuCredentialStore(context).getOrCreate().fill(0)
        val file = File(directory, "maplesu-credential.bin")
        val damaged = file.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        file.writeBytes(damaged)
        assertThrows(Exception::class.java) { MapleSuCredentialStore(context).getOrCreate() }
        assertArrayEquals(damaged, file.readBytes())
    }

    @Test fun legacyNamedStoreMigratesWithoutChangingTheBootCredential() {
        assertLegacyMigrated(dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE)
    }

    @Test fun legacyEnvelopeAtCurrentPathMigratesWithoutChangingTheBootCredential() {
        assertLegacyMigrated("maplesu-credential.bin")
    }

    @Test fun missingLegacyKeyDoesNotReplaceTheBootCredential() {
        val credential = "A".repeat(48).toByteArray(Charsets.US_ASCII)
        val stored = writeLegacy(dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE, credential)
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry(context.packageName + dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_ALIAS_SUFFIX)
        }
        assertThrows(Exception::class.java) { MapleSuCredentialStore(context).getOrCreate() }
        assertArrayEquals(stored, File(directory, dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE).readBytes())
        assertFalse(File(directory, "maplesu-credential.bin").exists())
    }

    @Test fun corruptLegacyStoreDoesNotGenerateAReplacementCredential() {
        val credential = "A".repeat(48).toByteArray(Charsets.US_ASCII)
        val stored = writeLegacy("maplesu-credential.bin", credential)
            .also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        File(directory, "maplesu-credential.bin").writeBytes(stored)
        assertThrows(Exception::class.java) { MapleSuCredentialStore(context).getOrCreate() }
        assertArrayEquals(stored, File(directory, "maplesu-credential.bin").readBytes())
    }

    private fun assertLegacyMigrated(name: String) {
        val credential = "A".repeat(48).toByteArray(Charsets.US_ASCII)
        writeLegacy(name, credential)
        val store = MapleSuCredentialStore(context)
        assertArrayEquals(credential, store.load())
        assertArrayEquals(byteArrayOf(77, 83, 75, 2),
            File(directory, "maplesu-credential.bin").readBytes().copyOfRange(0, 4))
        assertFalse(File(directory, dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_FILE).exists())
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry(context.packageName + dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_ALIAS_SUFFIX)
        }
        assertArrayEquals(credential, MapleSuCredentialStore(context).load())
    }

    private fun writeLegacy(name: String, credential: ByteArray): ByteArray {
        val alias = context.packageName + dev.maplesu.manager.compat.StoredInputs.CREDENTIAL_ALIAS_SUFFIX
        val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build())
        }.generateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD("$alias:48:47+NUL".toByteArray(Charsets.US_ASCII))
        val encrypted = cipher.doFinal(credential)
        val stored = ByteBuffer.allocate(4 + cipher.iv.size + encrypted.size)
            .put(byteArrayOf(77, 83, 75, 1)).put(cipher.iv).put(encrypted).array()
        File(directory, name).writeBytes(stored)
        return stored
    }
}
