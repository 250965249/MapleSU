package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.control.schema.ModesFile
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.control.schema.canonicalized
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 01 §8.1 `ControlJsonCodecTest`：往返字节稳定 / 排序 / 默认值 / 未知字段。 */
class ControlJsonCodecTest {

    @Test
    fun roundTripIsByteStable() {
        val modes = TestFixtures.modesFile()
        val first = ControlJsonCodec.encode(modes, ModesFile.serializer())
        val second = ControlJsonCodec.encode(modes, ModesFile.serializer())
        assertEquals(first, second)
        val decoded = ControlJsonCodec.decodeOrNull(first, ModesFile.serializer())
        assertNotNull(decoded)
        assertEquals(first, ControlJsonCodec.encode(decoded!!, ModesFile.serializer()))
    }

    @Test
    fun defaultsAreEncoded() {
        val raw = ControlJsonCodec.encode(TestFixtures.modesFile(), ModesFile.serializer())
        assertTrue(raw.contains("\"schema\":1"))
        // explicitNulls=true：显式 null 也必须落盘（wire 层可区分"未设置"）。
        assertTrue(raw.contains("\"last\":null"))
    }

    @Test
    fun nullVsMissingWireShape() {
        val encoded = ControlJsonCodec.encode(TestFixtures.modesFile(last = null), ModesFile.serializer())
        assertTrue(encoded.contains("\"last\":null"))
        // 读侧：显式 null 与缺字段都得到 null（wire 形态不同，值域相同——见交付报告偏差说明）。
        val withoutField = encoded.replace("\"last\":null,", "")
        val decoded = ControlJsonCodec.decodeOrNull(withoutField, ModesFile.serializer())
        assertEquals(null, decoded?.last)
    }

    @Test
    fun unknownFieldIgnoredOnRead() {
        val encoded = ControlJsonCodec.encode(TestFixtures.modesFile(), ModesFile.serializer())
        val withExtra = encoded.replaceFirst("{", "{\"futureField\":{\"x\":1},")
        val decoded = ControlJsonCodec.decodeOrNull(withExtra, ModesFile.serializer())
        assertNotNull(decoded)
        assertEquals(1L, decoded!!.revision)
    }

    @Test
    fun setOrderDoesNotLeak() {
        val shared = SharedSuperuserFile(
            revision = 2,
            updatedAt = 1,
            lastWriter = "A",
            entries = listOf(
                TestFixtures.grantIntent(uid = 2, packageName = "b.app", signers = listOf("f", "e")),
                TestFixtures.grantIntent(uid = 1, packageName = "a.app", signers = listOf("d", "c")),
            ),
            tombs = emptyList(),
            policy = dev.maplesu.manager.workmode.control.schema.SharedPolicy(),
        )
        val sorted = shared.copy(
            entries = shared.entries.reversed().map { it.copy(signerSha256 = it.signerSha256.sorted()) },
        )
        assertEquals(
            ControlJsonCodec.encode(sorted.canonicalized(), SharedSuperuserFile.serializer()),
            ControlJsonCodec.encode(shared.canonicalized(), SharedSuperuserFile.serializer()),
        )
    }

    @Test
    fun modesListOrderIsCanonical() {
        val ordered = TestFixtures.modesFile()
        val reversed = ordered.copy(modes = ordered.modes.reversed(), owners = emptyList())
        assertEquals(
            ControlJsonCodec.encode(ordered.canonicalized(), ModesFile.serializer()),
            ControlJsonCodec.encode(reversed.canonicalized(), ModesFile.serializer()),
        )
        assertTrue(
            ControlJsonCodec.encode(reversed.canonicalized(), ModesFile.serializer())
                .indexOf("\"A\"") < ControlJsonCodec.encode(reversed.canonicalized(), ModesFile.serializer())
                .indexOf("\"B\""),
        )
    }

    @Test
    fun corruptJsonDecodesToNull() {
        assertEquals(null, ControlJsonCodec.decodeOrNull<ModesFile>("{"))
        assertEquals(null, ControlJsonCodec.decodeOrNull<ModesFile>("[]"))
    }
}
