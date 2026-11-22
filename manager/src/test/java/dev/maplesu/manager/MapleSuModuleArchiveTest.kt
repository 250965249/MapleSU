package dev.maplesu.manager

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import dev.maplesu.manager.modules.ModuleInstallBackend
import dev.maplesu.manager.modules.ModuleInstallRouter
import dev.maplesu.manager.modules.ModuleType
import dev.maplesu.manager.modules.ModuleTypeDetector
import dev.maplesu.manager.workmode.WorkMode
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MapleSuModuleArchiveTest {
    @get:Rule val tmp = TemporaryFolder()

    private val entryPoint = dev.maplesu.manager.compat.NativeModuleAbi.ENTRY
    private val tags = listOf(
        Triple("de1f663bcae792d7c9ed1a21cdaeff00331fe11b074f0303e018f43998f8db3e", "枫栖测试", "04429c3f7172e4cce7ac7a5d44b75631ce91777b5f2a5eec076a3a508a76fb17"),
        Triple("7dc74a2b86805f2cd0f45c6a82d384fd568e341c6f05af17c7229c9ba6d4318b", "1.2", "8dbc019a6e51fe8d4a3db9feaf05535d70879f35626050cd4131bfe323ecefc2"),
        Triple("05c62cd446c811e772c94d97fd546738328f7c6b9967ed135190ef37ff06d866", "静态检查", "ed02c95e091c66100d6f2f4554f96392b2951b394ba042278eed8f236f43e1a3"),
        Triple("1f39b220291a2fb6e4fec95f179d0faf833ca534ef8ab2ffc4bd893768694451", "Maple", "d409c886fd6cedd694c1b126fd19eccd90e2463e04154c193effc7103ce63f1c"),
        Triple("b33dcddd88c07d079a8e0e9ec6ab976f15f2edba46cab91a61234cfbb982111c", "0123456789abcdef0123456789abcdef", "3020d9a6c07a30e2649dd29a72d7e57121f0c0ca457b6d21dca5a69acbe6c2c4"),
    )

    /** ELF64 fixture with an actual defined dynamic function and one executable PT_LOAD. */
    private fun elf(undefined: Boolean = false, duplicate: Boolean = false, id: String = tags.last().second): ByteArray {
        val metadata = (tags.joinToString("\u0000") {
            it.first + (if (it == tags.last()) id else it.second) + it.third
        } +
            if (duplicate) tags.first().let { it.first + it.second + it.third } else "").toByteArray()
        val strings = ("\u0000" + entryPoint + "\u0000").toByteArray()
        val strOffset = 512 + metadata.size
        val symOffset = (strOffset + strings.size + 7) and -8
        val shOffset = symOffset + 48
        val b = ByteBuffer.allocate(shOffset + 192).order(ByteOrder.LITTLE_ENDIAN)
        b.put(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1))
        b.putShort(16, 3); b.putShort(18, 183); b.putInt(20, 1)
        b.putLong(32, 64); b.putLong(40, shOffset.toLong())
        b.putShort(52, 64); b.putShort(54, 56); b.putShort(56, 1)
        b.putShort(58, 64); b.putShort(60, 3)
        b.putInt(64, 1); b.putInt(68, 5); b.putLong(80, 0x400000)
        b.putLong(96, b.capacity().toLong()); b.putLong(104, b.capacity().toLong()); b.putLong(112, 4096)
        b.putInt(256, 0xd65f03c0.toInt()) // RET, never executed.
        b.position(512); b.put(metadata); b.position(strOffset); b.put(strings)
        b.putInt(symOffset + 24, 1); b.put(symOffset + 28, 0x12)
        b.putShort(symOffset + 30, if (undefined) 0 else 1)
        b.putLong(symOffset + 32, 0x400100); b.putLong(symOffset + 40, 4)
        b.putInt(shOffset + 68, 3); b.putLong(shOffset + 88, strOffset.toLong())
        b.putLong(shOffset + 96, strings.size.toLong())
        b.putInt(shOffset + 132, 11); b.putLong(shOffset + 152, symOffset.toLong())
        b.putLong(shOffset + 160, 48); b.putInt(shOffset + 168, 1); b.putLong(shOffset + 184, 24)
        return b.array()
    }

    private fun zip(vararg files: Pair<String, ByteArray>) = tmp.newFile().also { file ->
        ZipArchiveOutputStream(file).use { zip ->
            for ((name, bytes) in files) {
                zip.putArchiveEntry(ZipArchiveEntry(name)); zip.write(bytes); zip.closeArchiveEntry()
            }
        }
    }

    @Test fun identifiesNativeAbiAndMetadataWithoutLoadingCode() {
        val source = zip("libdemo.so" to elf(), "wwwroot/index.html" to "hello".toByteArray())
        val before = source.readBytes()
        val report = ModuleArchiveInspector.inspect(source)
        assertEquals(ModuleArchiveInspector.ModuleType.MAPLESU, report.type)
        assertEquals("libdemo.so", report.nativeEntry)
        assertEquals(tags.last().second, report.id)
        assertEquals("枫栖测试", report.properties["name"])
        assertTrue(report.features.contains(ModuleArchiveInspector.Feature.WEB_UI))
        assertArrayEquals(before, source.readBytes())
        assertEquals(1, tmp.root.list()!!.size)
    }

    @Test fun ksuMetadataStillSelectsTheKsuBackend() {
        val report = ModuleArchiveInspector.inspect(zip("module.prop" to "id=maple_demo\n".toByteArray()))
        assertEquals(ModuleArchiveInspector.ModuleType.KERNEL_SU, report.type)
        assertNull(report.nativeEntry)
    }

    @Test fun validUltraDescriptorWithCustomLibraryNameReachesNativeBackend() {
        val file = zip("libdemo.so" to elf(), "service.sh" to "echo companion\n".toByteArray())
        assertEquals(ModuleArchiveInspector.ModuleType.MAPLESU, ModuleArchiveInspector.inspect(file).type)
        val evidence = ModuleTypeDetector.detect(file)
        assertEquals(ModuleType.MAPLESU, evidence.type)
        assertEquals(ModuleInstallBackend.MAPLESU_ULTRA, ModuleInstallRouter.route(WorkMode.LITE, evidence.type).backend)
    }

    @Test fun ordinaryLibraryNameDoesNotTurnScriptModuleIntoMixedFormat() {
        val file = zip("module.prop" to "id=script_demo\n".toByteArray(),
            "libmodule_helper.so" to byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1, 0))
        assertEquals(ModuleArchiveInspector.ModuleType.KERNEL_SU, ModuleArchiveInspector.inspect(file).type)
        val evidence = ModuleTypeDetector.detect(file)
        assertEquals(ModuleType.KERNELSU, evidence.type)
        assertEquals(ModuleInstallBackend.LITE_SCRIPT, ModuleInstallRouter.route(WorkMode.LITE, evidence.type).backend)
    }

    @Test fun nativeDescriptorDefinesIdentityWhenCompanionModulePropIsPresent() {
        val file = zip("module.prop" to "id=maple_demo\nversion=other\n".toByteArray(), "libdemo.so" to elf())
        val report = ModuleArchiveInspector.inspect(file)
        assertEquals(ModuleArchiveInspector.ModuleType.MAPLESU, report.type)
        assertEquals(tags.last().second, report.id)
        assertEquals(tags[1].second, report.properties["version"])
        assertEquals(ModuleType.MAPLESU, ModuleTypeDetector.detect(report).type)
        assertEquals(ModuleInstallBackend.MAPLESU_ULTRA,
            ModuleInstallRouter.route(WorkMode.LITE, ModuleTypeDetector.detect(file).type).backend)
        val catalog = dev.maplesu.manager.modules.ModuleCatalog(tmp.newFolder())
        val staged = catalog.stage(file, report.type, report.sha256)
        catalog.commit(staged.token)
        assertEquals(report.id, catalog.list().single().report.id)
    }

    @Test fun legacyPathSafeId32SurvivesRecognitionAndCatalogReadback() {
        val id = "touch_boost_oplus_1021_000000000"
        val file = zip("libtouch_boost.so" to elf(id = id))
        val report = ModuleArchiveInspector.inspect(file)
        assertEquals(id, report.id)
        val catalog = dev.maplesu.manager.modules.ModuleCatalog(tmp.newFolder())
        val staged = catalog.stage(file, report.type, report.sha256)
        catalog.commit(staged.token)
        assertEquals(id, catalog.list().single().report.id)
    }

    @Test fun refusesMultipleNativeEntries() {
        assertEquals("AMBIGUOUS_MODULE_TYPE", assertThrows(ModuleArchiveInspector.Failure::class.java) {
            ModuleArchiveInspector.inspect(zip("libone.so" to elf(), "libtwo.so" to elf()))
        }.code)
    }

    @Test fun refusesPathSeparatorsInLegacyId32() {
        assertThrows(ModuleArchiveInspector.Failure::class.java) {
            ModuleArchiveInspector.inspect(zip("libdemo.so" to elf(id = "../" + "a".repeat(29))))
        }
    }

    @Test fun anImportedSymbolOrPlainStringDoesNotIdentifyAnEntry() {
        for (bytes in listOf(elf(undefined = true), entryPoint.toByteArray())) {
            assertThrows(ModuleArchiveInspector.Failure::class.java) {
                ModuleArchiveInspector.inspect(zip("libdemo.so" to bytes))
            }
        }
    }

    @Test fun rejectsWrongMachineTruncationAndUnboundedElfTables() {
        for (bytes in listOf(
            elf().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putShort(18, 62) },
            elf().copyOf(900),
            elf().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putLong(40, Long.MAX_VALUE) },
        )) {
            assertThrows(ModuleArchiveInspector.Failure::class.java) {
                ModuleArchiveInspector.inspect(zip("libdemo.so" to bytes))
            }
        }
    }

    @Test fun rejectsDuplicateAndMalformedNativeMetadata() {
        assertThrows(ModuleArchiveInspector.Failure::class.java) {
            ModuleArchiveInspector.inspect(zip("libdemo.so" to elf(duplicate = true)))
        }
        val bytes = elf()
        val offset = 512 + tags.first().first.length
        bytes[offset] = 0xc3.toByte(); bytes[offset + 1] = 0x28
        assertThrows(ModuleArchiveInspector.Failure::class.java) {
            ModuleArchiveInspector.inspect(zip("libdemo.so" to bytes))
        }
    }

    @Test fun confirmationRemainsBoundToTheInspectedBytes() {
        val source = zip("module.prop" to "id=maple_demo\n".toByteArray())
        val report = ModuleArchiveInspector.inspect(source)
        ModuleArchiveInspector.verifyUnchanged(source, report)
        source.appendBytes(byteArrayOf(1))
        assertEquals("MODULE_ARCHIVE_CHANGED", assertThrows(ModuleArchiveInspector.Failure::class.java) {
            ModuleArchiveInspector.verifyUnchanged(source, report)
        }.code)
    }
}
