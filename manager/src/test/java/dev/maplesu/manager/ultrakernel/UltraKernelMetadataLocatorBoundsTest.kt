package dev.maplesu.manager.ultrakernel

import java.math.BigInteger
import org.junit.Assert.*
import org.junit.Test

/** Pure synthetic wire fixtures for the SDK's existing base62 locator format. */
class UltraKernelMetadataLocatorBoundsTest {
    @Test fun leadingZeroTailsBeyondEightKeepTheSameSignedDisplacement() {
        for (count in 9..34) {
            for (delta in listOf(-134217728, -4096, -4, 4, 4096, 134217728)) {
                val magnitude = base62(BigInteger.valueOf(kotlin.math.abs(delta.toLong())))
                val credential = wire(magnitude, count, if (delta < 0) '0' else '1')
                assertEquals("count=$count delta=$delta", delta, credential.metadataDisplacement)
                assertTrue(credential.sdkMetadataValid)
            }
        }
    }

    @Test fun countThirtyFivePreservesOverlappingSeedAndAppendedDigit() {
        // For count=35, byte 15 is both the tail seed and the appended last magnitude digit.
        for (sign in listOf('0', '1', 'Z')) {
            val credential = wire(base62(BigInteger.valueOf(92)), 35, sign)
            assertEquals(if (sign == '0') -92 else 92, credential.metadataDisplacement)
            assertTrue(credential.sdkMetadataValid)
        }
    }

    @Test fun allNonzeroSignDigitsRetainPositiveSemantics() {
        for (sign in ALPHABET.drop(1)) {
            val credential = wire("4", 9, sign)
            assertEquals(4, credential.metadataDisplacement)
            assertTrue(credential.sdkMetadataValid)
        }
    }

    @Test fun overlappingLongTailsDecodeWithoutChangingTheAlignmentPolicy() {
        for (count in 36..49) {
            // For long tails, reused key bytes also occur inside the selected tail.
            val sign = when (count) { 48 -> 'g'; 49 -> 'f'; else -> '1' }
            val credential = wire("t", count, sign) // Magnitude 29 preserves those overlapping bytes.
            assertEquals("count=$count", 29, credential.metadataDisplacement)
            assertFalse(credential.sdkMetadataValid)
        }
    }

    @Test fun rebindingTheSameLongLocatorPreservesTheCompleteIdentity() {
        val credential = wire("4", 12)
        val before = credential.copySecret()
        assertSame(credential, credential.withMetadataDisplacement(4))
        assertArrayEquals(before, credential.copySecret())
    }

    @Test fun existingShortLocatorBindingKeepsItsPublicFormat() {
        val credential = UltraKernelCredential.of("Aa1".repeat(16))
        for (delta in listOf(-134217728, -9188272, -4, 4, 134217728)) {
            val bound = credential.withMetadataDisplacement(delta)
            assertEquals(delta, bound.metadataDisplacement)
            assertTrue(bound.sdkMetadataValid)
            assertEquals(UltraKernelCredential.LENGTH, bound.length)
        }
    }

    @Test fun intBoundariesRemainSeparateFromMetadataUseLimits() {
        val maximum = wire(base62(BigInteger.valueOf(Int.MAX_VALUE.toLong())), 12)
        val minimum = wire(base62(BigInteger.valueOf(Int.MAX_VALUE.toLong() + 1)), 12, '0')
        assertEquals(Int.MAX_VALUE, maximum.metadataDisplacement)
        assertEquals(Int.MIN_VALUE, minimum.metadataDisplacement)
        assertFalse(maximum.sdkMetadataValid)
        assertFalse(minimum.sdkMetadataValid)
        for (delta in listOf(-134217732, -3, 0, 3, 134217732)) {
            val credential = wire(base62(BigInteger.valueOf(kotlin.math.abs(delta.toLong()))), 12,
                if (delta < 0) '0' else '1')
            assertEquals(delta, credential.metadataDisplacement)
            assertFalse(credential.sdkMetadataValid)
        }
    }

    @Test fun overflowNeverWrapsIntoAnAcceptedSmallDisplacement() {
        val magnitudes = listOf(
            BigInteger.valueOf(Int.MAX_VALUE.toLong() + 1),
            BigInteger.ONE.shiftLeft(32).add(BigInteger.valueOf(4)),
            BigInteger.ONE.shiftLeft(63).add(BigInteger.valueOf(4)),
            BigInteger.ONE.shiftLeft(64).add(BigInteger.valueOf(4)),
            BigInteger.ONE.shiftLeft(128).add(BigInteger.valueOf(4)),
        )
        for ((index, magnitude) in magnitudes.withIndex()) {
            for (sign in listOf('0', '1')) {
                if (index == 0 && sign == '0') continue // Exact Int.MIN_VALUE is valid to decode.
                val credential = wire(base62(magnitude), 34, sign)
                assertNull(credential.metadataDisplacement)
                assertFalse(credential.sdkMetadataValid)
            }
        }
    }

    @Test fun unsupportedCountsAndLongMalformedTailsRemainUnresolved() {
        for (count in listOf(0, 1, 2, 51, 61)) {
            val key = CharArray(UltraKernelCredential.LENGTH) { 'a' }
            key[0] = '0'
            key[1] = ALPHABET[count]
            val credential = UltraKernelCredential.of(String(key))
            assertNull(credential.metadataDisplacement)
            assertFalse(credential.sdkMetadataValid)
        }
        // Exercise every expanded index bound, including a tail starting at bytes 0 and 1.
        for (count in 36..50) {
            val key = CharArray(UltraKernelCredential.LENGTH) { 'Z' }
            key[0] = '0'
            key[1] = ALPHABET[count]
            val credential = UltraKernelCredential.of(String(key))
            assertNull(credential.metadataDisplacement)
            assertFalse(credential.sdkMetadataValid)
        }
        assertFalse(UltraKernelCredential.of("Aa1".repeat(16)).sdkMetadataValid)
    }

    private fun wire(magnitude: String, count: Int, sign: Char = '1'): UltraKernelCredential {
        require(count in 3..49 && magnitude.length <= count - 2)
        val key = CharArray(UltraKernelCredential.LENGTH) { 'a' }
        key[0] = 'c'
        key[16] = 'g'
        val seed = if (count == 49) (ALPHABET.indexOf(key[0]) + count) % 62 else ALPHABET.indexOf(key[16])
        val plain = magnitude.padStart(count - 2, '0') + sign
        val tail = charArrayOf(ALPHABET[seed]) + CharArray(plain.length) { index ->
            ALPHABET[(ALPHABET.indexOf(plain[index]) + seed + index) % 62]
        }
        tail.copyInto(key, UltraKernelCredential.LENGTH + 2 - count, 0, count - 2)
        key[15] = tail[count - 2]
        key[2] = tail[count - 1]
        key[1] = ALPHABET[(ALPHABET.indexOf(key[0]) + count) % 62]
        return UltraKernelCredential.of(String(key))
    }

    private fun base62(value: BigInteger): String {
        var remaining = value
        val digits = StringBuilder()
        do {
            val parts = remaining.divideAndRemainder(BigInteger.valueOf(62))
            digits.append(ALPHABET[parts[1].toInt()])
            remaining = parts[0]
        } while (remaining.signum() != 0)
        return digits.reverse().toString()
    }

    companion object {
        private const val ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }
}
