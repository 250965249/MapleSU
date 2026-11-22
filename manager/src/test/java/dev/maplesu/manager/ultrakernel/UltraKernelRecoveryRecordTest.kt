package dev.maplesu.manager.ultrakernel

import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class UltraKernelRecoveryRecordTest {
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun plan(vararg records: UltraKernelPlan.PatchRecord): UltraKernelPlan = UltraKernelPlan.fromSpec(
        UltraKernelSpec.parse("#kernel=6.6.1-test\n" + records.joinToString("\n") {
            "${it.offset}|${hex(it.original)}|${hex(it.replacement)}"
        }))

    private fun patch(offset: Int, original: ByteArray, vararg replacement: Int) =
        UltraKernelPlan.PatchRecord("test", offset.toLong(), original, replacement.map { it.toByte() }.toByteArray())

    private fun record(plan: UltraKernelPlan, bytes: Int = 64, sdk: Int = 9, runtime: Int = 2) =
        UltraKernelRecoveryRecord.fromPlan(plan, bytes, sdk, runtime)

    private fun apply(source: ByteArray, plan: UltraKernelPlan) = source.copyOf().also { current ->
        for (patch in plan.records) patch.replacement.copyInto(current, patch.offset.toInt())
    }

    private fun reject(code: String, action: () -> Unit) {
        try { action(); fail("expected $code") }
        catch (error: IllegalArgumentException) {
            assertTrue(error.message.orEmpty(), error.message.orEmpty().startsWith(code))
        }
    }

    private fun resign(bytes: ByteArray): ByteArray = bytes.also {
        MessageDigest.getInstance("SHA-256").run {
            update(it, 0, it.size - 32); digest().copyInto(it, it.size - 32)
        }
    }

    private fun changedInt(bytes: ByteArray, offset: Int, value: Int) = resign(bytes.copyOf().also {
        ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putInt(offset, value)
    })

    @Test
    fun `overlapping writes use pristine originals and last writer then roundtrip`() {
        val source = ByteArray(64) { it.toByte() }
        val plan = plan(patch(8, source.copyOfRange(8, 12), 91, 92, 93, 94),
            patch(10, source.copyOfRange(10, 14), 81, 82, 83, 84),
            patch(14, source.copyOfRange(14, 16), 71, 72),
            patch(32, source.copyOfRange(32, 34), 61, 62))
        val current = apply(source, plan)
        val unchanged = current.copyOf()
        val record = record(plan)
        assertEquals(2, record.rangeCount)
        assertEquals(10, record.originalBytes)
        val encoded = record.encode()
        val decoded = UltraKernelRecoveryRecord.decode(encoded)
        assertArrayEquals(encoded, decoded.encode())
        assertArrayEquals(source, decoded.restore(current))
        assertArrayEquals(unchanged, current)
        assertEquals(9, decoded.producerSdkAbi)
        assertEquals(2, decoded.producerRuntimeAbi)
    }

    @Test
    fun `conflicting originals reject even when the conflict is outside a write`() {
        val plan = plan(patch(8, byteArrayOf(1, 2, 3, 4), 5),
            patch(10, byteArrayOf(9, 4), 6))
        reject("ULTRA_KERNEL_RECOVERY_ORIGINAL_CONFLICT") { record(plan) }
    }

    @Test
    fun `every written byte needs an exact preimage including replacement expansion`() {
        reject("ULTRA_KERNEL_RECOVERY_PREIMAGE_INCOMPLETE") {
            record(plan(patch(8, byteArrayOf(1), 5, 6)))
        }
        val source = ByteArray(64)
        source[8] = 1; source[9] = 2
        val complete = plan(patch(8, byteArrayOf(1), 5, 6), patch(9, byteArrayOf(2), 7))
        assertArrayEquals(source, record(complete).restore(apply(source, complete)))
    }

    @Test
    fun `restore verifies every range and never modifies input on mismatch`() {
        val source = ByteArray(64)
        val plan = plan(patch(8, byteArrayOf(0, 0), 4, 5), patch(32, byteArrayOf(0, 0), 6, 7))
        val record = record(plan)
        for (at in listOf(8, 9, 32, 33)) {
            val current = apply(source, plan).also { it[at] = (it[at] + 1).toByte() }
            val before = current.copyOf()
            reject("ULTRA_KERNEL_RECOVERY_CURRENT_MISMATCH") { record.restore(current) }
            assertArrayEquals(before, current)
        }
        reject("ULTRA_KERNEL_RECOVERY_CURRENT_LENGTH") { record.restore(ByteArray(63)) }
        reject("ULTRA_KERNEL_RECOVERY_CURRENT_LENGTH") { record.restore(ByteArray(65)) }
    }

    @Test
    fun `changes outside owned writes are preserved without a kernel fingerprint gate`() {
        val source = ByteArray(64)
        val plan = plan(patch(8, byteArrayOf(0), 4))
        val current = apply(source, plan).also { it[50] = 9 }
        val restored = record(plan).restore(current)
        assertEquals(0, restored[8].toInt())
        assertEquals(9, restored[50].toInt())
    }

    @Test
    fun `old record restores before rebuilding for a different producer version`() {
        val source = ByteArray(64)
        val first = plan(patch(8, byteArrayOf(0, 0), 4, 5))
        val old = UltraKernelRecoveryRecord.decode(record(first, sdk = 5, runtime = 1).encode())
        val firstCurrent = apply(source, first)
        val recovered = old.restore(firstCurrent)
        assertArrayEquals(source, recovered)
        val futureProducer = changedInt(changedInt(old.encode(), 24, Int.MAX_VALUE), 28, Int.MAX_VALUE)
        assertArrayEquals(source, UltraKernelRecoveryRecord.decode(futureProducer).restore(firstCurrent))
        val next = plan(patch(8, byteArrayOf(0, 0), 6, 7), patch(24, byteArrayOf(0), 8))
        val newer = UltraKernelRecoveryRecord.decode(record(next, sdk = 20, runtime = 7).encode())
        assertArrayEquals(source, newer.restore(apply(recovered, next)))
        assertArrayEquals(source, old.restore(firstCurrent))
    }

    @Test
    fun `record owns snapshots independently of input plan and encoded buffer`() {
        val source = ByteArray(64)
        val plan = plan(patch(8, byteArrayOf(0, 0), 4, 5))
        val current = apply(source, plan)
        val record = record(plan)
        plan.records[0].original.fill(99); plan.records[0].replacement.fill(99)
        val encoded = record.encode()
        val decoded = UltraKernelRecoveryRecord.decode(encoded)
        encoded.fill(0)
        assertArrayEquals(source, record.restore(current))
        assertArrayEquals(source, decoded.restore(current))
    }

    @Test
    fun `every truncation and appended data reject without changing supplied record`() {
        val encoded = record(plan(patch(8, byteArrayOf(0, 0), 4, 5))).encode()
        val original = encoded.copyOf()
        for (length in 0 until encoded.size) reject("ULTRA_KERNEL_RECOVERY_") {
            UltraKernelRecoveryRecord.decode(encoded.copyOf(length))
        }
        reject("ULTRA_KERNEL_RECOVERY_") { UltraKernelRecoveryRecord.decode(encoded + byteArrayOf(0)) }
        assertArrayEquals(original, encoded)
    }

    @Test
    fun `every single byte corruption fails complete record self check`() {
        val encoded = record(plan(patch(8, byteArrayOf(0, 0), 4, 5))).encode()
        for (at in encoded.indices) {
            val changed = encoded.copyOf().also { it[at] = (it[at].toInt() xor 1).toByte() }
            reject("ULTRA_KERNEL_RECOVERY_CHECKSUM") { UltraKernelRecoveryRecord.decode(changed) }
        }
    }

    @Test
    fun `valid checksum does not admit unknown format malformed lengths counts or actions`() {
        val encoded = record(plan(patch(8, byteArrayOf(0, 0), 4, 5))).encode()
        for ((offset, value) in listOf(8 to 2, 12 to Int.MAX_VALUE, 16 to 0, 20 to 2,
                24 to -1, 28 to -1, 40 to 0, 40 to 513, 40 to Int.MAX_VALUE,
                44 to -1, 44 to Int.MAX_VALUE, 56 to 0, 56 to Int.MAX_VALUE, 60 to 1)) {
            reject("ULTRA_KERNEL_RECOVERY_") { UltraKernelRecoveryRecord.decode(changedInt(encoded, offset, value)) }
        }
        for (value in listOf(-1L, 0L, Long.MAX_VALUE)) {
            val badKernel = resign(encoded.copyOf().also {
                ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putLong(32, value)
            })
            reject("ULTRA_KERNEL_RECOVERY_KERNEL_LENGTH") { UltraKernelRecoveryRecord.decode(badKernel) }
        }
        val wrongMagic = resign(encoded.copyOf().also { it[0] = 0 })
        reject("ULTRA_KERNEL_RECOVERY_MAGIC") { UltraKernelRecoveryRecord.decode(wrongMagic) }
        val overflow = resign(encoded.copyOf().also {
            ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putLong(48, Long.MAX_VALUE)
        })
        reject("ULTRA_KERNEL_RECOVERY_RANGE") { UltraKernelRecoveryRecord.decode(overflow) }
    }

    @Test
    fun `decoded ranges must be ordered disjoint and already merged`() {
        val encoded = record(plan(patch(8, byteArrayOf(0), 4), patch(32, byteArrayOf(0), 5))).encode()
        for (offset in listOf(7L, 8L, 9L)) {
            val malformed = resign(encoded.copyOf().also {
                ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putLong(48 + 49, offset)
            })
            reject("ULTRA_KERNEL_RECOVERY_RANGE") { UltraKernelRecoveryRecord.decode(malformed) }
        }
    }

    @Test
    fun `input ranges size and total allocation are bounded before retention`() {
        val overflow = UltraKernelSpec.parse("#kernel=6.6.1-test\n${Long.MAX_VALUE - 1}|0000|0102")
        reject("ULTRA_KERNEL_RECOVERY_PLAN_RANGE") { record(UltraKernelPlan.fromSpec(overflow)) }
        reject("ULTRA_KERNEL_RECOVERY_KERNEL_LENGTH") { record(plan(patch(1, byteArrayOf(0), 1)), 0) }
        reject("ULTRA_KERNEL_RECOVERY_PLAN_RANGE") { record(plan(patch(63, byteArrayOf(0), 1, 2))) }
        val max = (0 until UltraKernelRecoveryRecord.MAX_RANGES).map {
            patch(it * 2, byteArrayOf(0), 127)
        }
        assertEquals(512, record(plan(*max.toTypedArray()), 1024).rangeCount)
        val largeHex = "00".repeat(UltraKernelRecoveryRecord.MAX_BYTES)
        val huge = UltraKernelPlan.fromSpec(UltraKernelSpec.parse(
            "#kernel=6.6.1-test\n0|$largeHex|$largeHex"))
        reject("ULTRA_KERNEL_RECOVERY_RECORD_SIZE") { record(huge, UltraKernelRecoveryRecord.MAX_BYTES) }
        reject("ULTRA_KERNEL_RECOVERY_RECORD_SIZE") {
            UltraKernelRecoveryRecord.decode(ByteArray(UltraKernelRecoveryRecord.MAX_BYTES + 1))
        }
    }

    @Test
    fun `two real generated specs recover exact windows without retaining key or replacement`() {
        val root = File(System.getProperty("maplesu.repo", ".."))
        val directory = File(root, "docs/dual-mode/impl/_work/2026-11-15-p3/evidence/current-repatch-entry-r1")
        val fixtures = directory.walkTopDown().filter { it.isFile && it.extension == "spec" }.sortedBy { it.path }.toList()
        assertEquals(2, fixtures.size)
        for (file in fixtures) {
            val spec = UltraKernelSpec.read(file)
            val plan = UltraKernelPlan.fromSpec(spec, credential = UltraKernelCredential.of(spec.key))
            val size = (plan.records.maxOf { it.offset + it.length } + 32).toInt()
            // Real spec bytes/absolute offsets in a sparse synthetic buffer, not a real boot image.
            val source = ByteArray(size) { 0x35 }
            for (patch in plan.records) patch.original.copyInto(source, patch.offset.toInt())
            val current = apply(source, plan)
            val currentHash = UltraKernelSpec.sha256(current)
            val record = record(plan, size)
            val encoded = record.encode()
            fun contains(needle: ByteArray) = encoded.indices.any { start ->
                start + needle.size <= encoded.size && needle.indices.all { encoded[start + it] == needle[it] }
            }
            assertFalse(contains(spec.key.toByteArray(Charsets.US_ASCII)))
            assertFalse(contains("#key=".toByteArray(Charsets.US_ASCII)))
            assertArrayEquals(source, UltraKernelRecoveryRecord.decode(encoded).restore(current))
            assertEquals(currentHash, UltraKernelSpec.sha256(current))
            println("RECOVERY_FIXTURE sample=${file.parentFile.parentFile.name} records=${plan.records.size}" +
                " ranges=${record.rangeCount} originalBytes=${record.originalBytes} encodedBytes=${encoded.size}")
        }
    }
}
