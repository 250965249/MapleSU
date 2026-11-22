package dev.maplesu.manager.modules

import dev.maplesu.manager.ModuleArchiveInspector
import java.security.MessageDigest
import java.util.Locale
import java.util.Random
import org.junit.Assert.assertEquals
import org.junit.Test

class ModuleDigestTest {
    private val type = LiteScriptModuleBackend::class.java
    private val backend = (sun.misc.Unsafe::class.java.getDeclaredField("theUnsafe").apply {
        isAccessible = true
    }.get(null) as sun.misc.Unsafe).allocateInstance(type)

    @Test fun metadataDigestRetainsLeadingZerosSignedBytesAndLocaleIndependence() {
        val method = type.getDeclaredMethod("sha256", ByteArray::class.java).apply { isAccessible = true }
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("ar-EG"))
            val random = Random(510)
            val samples = listOf(byteArrayOf(), ByteArray(256) { it.toByte() }) +
                (0 until 128).map { ByteArray(it * 7).also(random::nextBytes) }
            samples.forEach { bytes ->
                assertEquals(reference(bytes), method.invoke(backend, bytes))
            }
        } finally { Locale.setDefault(previous) }
    }

    @Test fun moduleIdentityRemainsByteForByteCompatible() {
        val report = ModuleArchiveInspector.installedKsu("digest_fixture",
            "name=Digest fixture\nversionCode=1\n", "1:300", setOf("module.prop"), emptySet(), false)
        val method = type.getDeclaredMethod("moduleKey", report.javaClass).apply { isAccessible = true }
        val expected = reference("${report.type}\n${report.id}\n${report.sha256}".toByteArray())
        repeat(20) { assertEquals(expected, method.invoke(backend, report)) }
        val started = System.nanoTime()
        repeat(2_000) { assertEquals(expected, method.invoke(backend, report)) }
        println("MODULE_IDENTITY_2000_MS=${(System.nanoTime() - started) / 1_000_000}")
    }

    private fun reference(bytes: ByteArray): String = buildString(64) {
        MessageDigest.getInstance("SHA-256").digest(bytes).forEach {
            append(Character.forDigit((it.toInt() ushr 4) and 15, 16))
            append(Character.forDigit(it.toInt() and 15, 16))
        }
    }
}
