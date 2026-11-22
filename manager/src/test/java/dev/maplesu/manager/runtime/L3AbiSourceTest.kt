package dev.maplesu.manager.runtime

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Static assertion for the L3 ABI (v2) split across the Kotlin/native boundary.
 *
 * <p>ABI v2 removed the private option number. The gate is
 * `prctl(PR_SET_DUMPABLE, op, token_lo, token_hi, arg5)`, recognised only by that
 * option *and* a non-zero token in arg3/arg4; a bare `prctl(PR_SET_DUMPABLE, ...)`
 * keeps its native meaning. The structural rule is therefore restated, not dropped:
 * the gate call exists in exactly one place - the JNI source - and no Kotlin or Java
 * source may issue it or name its option (`PR_SET_DUMPABLE`). The retired v1 magic
 * (`0x4D535503` and its decimal spelling) must be gone from both sides, because a
 * leftover v1 call would now be an unknown option that can never arm anything.
 *
 * <p>The remaining assertions tie the source to the artifact that ships:
 * `libmaplesu_l3_su.so` must exist, be an AArch64 shared object and carry the JNI
 * symbol the Kotlin side declares. A stale or wrong-architecture stub therefore
 * cannot pass as the client.
 */
class L3AbiSourceTest {

    private val managerDir: File = sequenceOf(
        File("."), File("manager"), File("../manager"),
    ).map { it.absoluteFile.normalize() }
        .firstOrNull { File(it, "src/main/java").isDirectory }
        ?: error("cannot locate the manager module from " + File(".").absolutePath)

    private val mainJava = File(managerDir, "src/main/java")
    private val nativeSource = File(managerDir, "src/main/cpp/maplesu_su.c")
    private val shippedLibrary =
        File(managerDir, "src/main/jniLibs/arm64-v8a/lib" + NativeSu.LIBRARY + ".so")
    private val repoRoot = managerDir.parentFile
    private val buildScript = File(repoRoot, "tools/build_su_client.sh")

    /** Every Kotlin/Java file the App compiles, including the provider source dir. */
    private fun appSources(): List<File> {
        val roots = buildList {
            add(File(managerDir, "src"))
            File(repoRoot, "jailbreak-providers/android/src/main/java")
                .takeIf { it.isDirectory }?.let { add(it) }
        }
        return roots.flatMap { root ->
            root.walkTopDown()
                .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
                .filterNot { it.path.contains("${File.separator}test${File.separator}") }
                .filterNot { it.path.contains("androidTest") }
                .toList()
        }.distinctBy { it.absolutePath }
    }

    private fun text(file: File): String = file.readText(Charsets.UTF_8)

    /**
     * ABI v2: only the number 4 (the kernel's own `PR_SET_DUMPABLE`) is magic, and it
     * lives in the native source. The v1 option must not survive anywhere - a Kotlin
     * or C file still carrying it would be calling a number the module no longer
     * recognises.
     */
    @Test
    fun `the retired v1 option magic is gone from every source`() {
        val offenders = (appSources() + nativeSource).filter { source ->
            val body = text(source).lowercase()
            body.contains(V1_MAGIC_HEX) || body.contains(V1_MAGIC_DECIMAL)
        }
        assertTrue("the retired v1 magic 0x4D535503 is still in: " +
            offenders.joinToString { it.absolutePath }, offenders.isEmpty())
    }

    /**
     * Unrelated `prctl` calls already exist in the App (`Os.prctl(21 /*
     * PR_GET_SECCOMP */, ...)` in HomeViewModel), so the rule is not "never call
     * prctl" - it is "never issue the gate". The option argument must be a named
     * constant: a raw hex literal, the bare `4`, the gate's own option name or the
     * retired v1 value is exactly the ABI being built by hand, and all are refused.
     */
    @Test
    fun `no Kotlin or Java prctl call issues the L3 gate`() {
        val offenders = mutableListOf<String>()
        for (source in appSources()) {
            val body = text(source)
            var at = body.indexOf("prctl(")
            while (at >= 0) {
                val end = body.indexOf(')', at)
                val argument = if (end > at) body.substring(at + "prctl(".length, end) else ""
                val option = argument.substringBefore(',')
                val normalized = option.replace(" ", "").replace("\t", "")
                if (option.contains("0x", ignoreCase = true) ||
                    normalized == "4" ||
                    option.contains("PR_SET_DUMPABLE") ||
                    option.contains(V1_MAGIC_DECIMAL)) {
                    offenders += source.name + ": prctl(" + argument.take(48)
                }
                at = body.indexOf("prctl(", at + 1)
            }
        }
        assertTrue("prctl must be called with a named constant, never a raw option: " +
            offenders.joinToString(), offenders.isEmpty())
    }

    /**
     * The one magic ABI v2 has is `PR_SET_DUMPABLE`, and it stays native-only: a
     * Kotlin/Java file that names it could only be assembling the gate call itself.
     */
    @Test
    fun `no Kotlin or Java source names the gate option`() {
        val offenders = appSources().filter { text(it).contains("PR_SET_DUMPABLE") }
        assertTrue("PR_SET_DUMPABLE belongs to the JNI source only, found in: " +
            offenders.joinToString { it.absolutePath }, offenders.isEmpty())
    }

    @Test
    fun `the ABI v2 gate lives in the native source`() {
        val body = text(nativeSource)
        assertTrue("the source must declare ABI v2", body.contains("#define MSU_ABI_VERSION 2"))
        assertTrue("the option must be the kernel's PR_SET_DUMPABLE, not a private number",
            body.contains("#define MSU_PRCTL_OPTION PR_SET_DUMPABLE"))
        assertTrue("op=0 is the ABI's ARM operation", body.contains("#define MSU_OP_ARM 0"))
        assertTrue("op=1 is the ABI's SU operation", body.contains("#define MSU_OP_SU 1"))
        assertTrue("the gate is only reachable through prctl",
            body.contains("prctl(MSU_PRCTL_OPTION, (unsigned long)MSU_OP_SU"))
        // The one call site that must exist: the ABI's (token_lo, token_hi, arg5) form.
        assertTrue("the token must be split into the ABI's two 32-bit arguments",
            body.contains("(uint64_t)token & 0xffffffffULL") &&
                body.contains("(uint64_t)token >> 32"))
        assertTrue("arg5 is not used by the SU branch",
            body.contains(">> 32), 0UL);"))
        assertTrue("the child must prove it really became uid 0",
            body.contains("getuid() != 0"))
        assertTrue("the child must prove its effective uid is 0 as well",
            body.contains("geteuid() != 0"))
        assertTrue("a zero token must be refused before prctl (it is not magic)",
            body.contains("if (token == 0)"))
        assertTrue("the child must exec, never run a shell from Kotlin",
            body.contains("execv(argv[0], argv)"))
    }

    @Test
    fun `the shipped library is an AArch64 ELF with the JNI entry point`() {
        assertTrue("missing " + shippedLibrary.absolutePath, shippedLibrary.isFile)
        val bytes = shippedLibrary.readBytes()
        assertEquals("ELF magic", 0x7f, bytes[0].toInt() and 0xff)
        assertEquals('E'.code, bytes[1].toInt() and 0xff)
        assertEquals('L'.code, bytes[2].toInt() and 0xff)
        assertEquals('F'.code, bytes[3].toInt() and 0xff)
        assertEquals("ELFCLASS64", 2, bytes[4].toInt() and 0xff)
        // e_machine little-endian at offset 18: EM_AARCH64 = 183.
        val machine = (bytes[18].toInt() and 0xff) or ((bytes[19].toInt() and 0xff) shl 8)
        assertEquals("e_machine must be EM_AARCH64", 183, machine)
        val symbols = String(bytes, Charsets.ISO_8859_1)
        assertTrue("the library must export " + JNI_ENTRY,
            symbols.contains(JNI_ENTRY))
    }

    @Test
    fun `the build script produces exactly the library the app loads`() {
        val script = text(buildScript)
        val outLine = script.lines().firstOrNull { it.trimStart().startsWith("out=") }
            ?: error("build_su_client.sh has no out= default")
        assertTrue("the default output must be lib" + NativeSu.LIBRARY + ".so",
            outLine.contains("lib" + NativeSu.LIBRARY + ".so"))
        // The runtime's own su executable owns libmaplesu_su.so; the shim must not
        // claim that path or the jniLibs merge has two entries for one name.
        assertFalse("the default output must not reuse the runtime's name",
            outLine.contains("libmaplesu_su.so"))
        assertTrue("it must target arm64",
            script.contains("aarch64-linux-android"))
        assertTrue("it must compile the JNI source",
            script.contains("manager/src/main/cpp/maplesu_su.c"))
    }

    @Test
    fun `the native symbol matches the Kotlin declaration`() {
        assertEquals("Java_dev_maplesu_manager_runtime_NativeSu_run", JNI_ENTRY)
        val declared = text(File(mainJava, "dev/maplesu/manager/runtime/NativeSu.kt"))
        assertTrue("NativeSu must declare the external entry point",
            declared.contains("external fun run(token: Long, argv: Array<String>, " +
                "timeoutMs: Int): Bundle?"))
    }

    /**
     * 16 KB page compatibility. Android 15+ devices can run a 16 KB-page kernel, and
     * a shared object whose LOAD segments are 4 KB aligned cannot be mapped there.
     * NDK r28 already defaults to 16 KB, but the requirement is asserted on the
     * artifact that actually ships so a toolchain or flag edit cannot silently drop
     * it, and the build script must keep stating the flag explicitly.
     */
    @Test
    fun `the shipped library is 16 KB page aligned`() {
        val bytes = shippedLibrary.readBytes()
        val programOffset = readU64(bytes, 32)
        val entrySize = readU16(bytes, 54)
        val count = readU16(bytes, 56)
        assertEquals("ELF64 program header size", 56, entrySize)
        var loads = 0
        for (index in 0 until count) {
            val base = (programOffset + index.toLong() * entrySize).toInt()
            if (readU32(bytes, base) != 1L) continue // PT_LOAD
            loads++
            val fileOffset = readU64(bytes, base + 8)
            val virtualAddress = readU64(bytes, base + 16)
            val align = readU64(bytes, base + 48)
            assertTrue("PT_LOAD[$index] align 0x${align.toString(16)} is below 16 KB",
                align >= 0x4000L)
            assertEquals("PT_LOAD[$index] file offset and vaddr must be congruent " +
                "modulo 16 KB", fileOffset % 0x4000L, virtualAddress % 0x4000L)
        }
        assertTrue("the library has no PT_LOAD segment", loads > 0)
    }

    @Test
    fun `the build script states the 16 KB page alignment`() {
        assertTrue("build_su_client.sh must pass -Wl,-z,max-page-size=16384 so the " +
            "alignment is a statement, not a toolchain default",
            text(buildScript).contains("-Wl,-z,max-page-size=16384"))
    }

    private fun readU16(bytes: ByteArray, at: Int): Int =
        (bytes[at].toInt() and 0xff) or ((bytes[at + 1].toInt() and 0xff) shl 8)

    private fun readU32(bytes: ByteArray, at: Int): Long =
        (bytes[at].toLong() and 0xff) or
            ((bytes[at + 1].toLong() and 0xff) shl 8) or
            ((bytes[at + 2].toLong() and 0xff) shl 16) or
            ((bytes[at + 3].toLong() and 0xff) shl 24)

    private fun readU64(bytes: ByteArray, at: Int): Long {
        var value = 0L
        for (offset in 0 until 8) {
            value = value or ((bytes[at + offset].toLong() and 0xff) shl (8 * offset))
        }
        return value
    }

    private companion object {
        const val JNI_ENTRY = "Java_dev_maplesu_manager_runtime_NativeSu_run"
        /** The retired v1 option (0x4D535503), lower-case hex and decimal. */
        const val V1_MAGIC_HEX = "4d535503"
        const val V1_MAGIC_DECIMAL = "1297306883"
    }
}
