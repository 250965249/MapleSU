package dev.maplesu.manager.ultrakernel

/** Same authenticated execve transport; fixed wire fields match request_protocol.h. */
internal object UltraKernelRequestV2 {
    // Gate + allocation tail + optional execmem adapter, then 8-byte alignment.
    const val CAVE_OFFSET = 304
    // The public 48-byte descriptor is followed by a separate private provider
    // locator. QUERY continues to publish exactly the original wire length.
    const val BYTES = 568

    private const val SP = 31
    private const val ZR = 31
    private const val WIRE_BYTES = 48
    private const val RESPONSE = 48
    private const val COMPLETION = 96
    private const val READ_ARGS = 112
    private const val READ_DATA = 128
    private const val READ_MAX = 256
    private const val STACK_BYTES = READ_DATA + READ_MAX
    private const val REQUEST_MAGIC = 0x3251534dL
    private const val RESPONSE_MAGIC = 0x3252534dL
    private const val METADATA_MAGIC = 0x324d534dL
    private const val VERSION_LENGTH = 0x00300002L

    fun generate(a: UltraKernelAsm, r: UltraKernelSymbolResolver, f: UltraKernelFields) {
        val kernelRead = r.exact("copy_from_kernel_nofault")
        val capabilities = if (kernelRead != null) 7L else 3L
        // Old setter clients retain the exact eight-byte saved-ID write.
        a.emit(UltraKernelA64.ldAuto("ldrb", 12, 11, 67, 1))
        a.emit(UltraKernelA64.cmpImm(12, 0xa2, sf = 0))
        a.bCond(UltraKernelA64.EQ, "request")
        a.emit(UltraKernelA64.ldAuto("str", 0, 17, f.requireOffset(f.credSuid, UltraKernelStructOffsets.SUID), 8))
        a.bAbs(r.require("arm64_notify_die"))

        a.mark("request")
        // No callee-saved register or x18 is touched. C callees may destroy x0-x17/LR;
        // protocol state remains in this aligned stack frame until the outer frame restores.
        a.emit(UltraKernelA64.addImm(SP, SP, STACK_BYTES, sub = true))
        a.emit(UltraKernelA64.ldAuto("ldr", 1, 11, 76, 8))
        a.emit(UltraKernelA64.addImm(0, SP, 0))
        a.emit(UltraKernelA64.encodeMovImm(2, WIRE_BYTES.toLong(), sf = 0))
        a.blAbs(r.require("copy_from_user_nofault"))
        a.cbnz(0, "out")

        for (offset in intArrayOf(48, 64, 80))
            a.emit(UltraKernelA64.pair("stp", ZR, ZR, SP, offset / 8, true, 2))
        a.emit(UltraKernelA64.encodeMovImm(12, VERSION_LENGTH, sf = 0))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 4, 4))
        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 8, 4))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 8, 4))
        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 16, 8))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 16, 8))
        status(a, -22)

        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 0, 4))
        a.emit(UltraKernelA64.encodeMovImm(13, REQUEST_MAGIC, sf = 0))
        a.emit(UltraKernelA64.cmpReg(12, 13, sf = 0))
        a.bCond(UltraKernelA64.NE, "respond")
        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 4, 4))
        a.emit(UltraKernelA64.encodeMovImm(13, VERSION_LENGTH, sf = 0))
        a.emit(UltraKernelA64.cmpReg(12, 13, sf = 0))
        a.bCond(UltraKernelA64.NE, "respond")
        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 12, 4))
        a.cbnz(12, "respond", sf = false)
        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 8, 4))
        a.emit(UltraKernelA64.cmpImm(12, 1, sf = 0))
        a.bCond(UltraKernelA64.EQ, "query")
        a.emit(UltraKernelA64.cmpImm(12, 2, sf = 0))
        a.bCond(UltraKernelA64.EQ, "echo")
        if (kernelRead != null) {
            a.emit(UltraKernelA64.cmpImm(12, 3, sf = 0))
            a.bCond(UltraKernelA64.EQ, "read")
        }
        status(a, -95)
        a.b("respond")

        a.mark("query")
        a.emit(UltraKernelA64.encodeMovImm(12, capabilities))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 24, 8))
        a.adr(12, "metadata")
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 32, 8))
        a.emit(UltraKernelA64.encodeImm64(12, (2L shl 32) or WIRE_BYTES.toLong()))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 40, 8))
        a.b("success")
        a.mark("echo")
        a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, 32, 8))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 24, 8))
        a.b("success")
        if (kernelRead != null) {
            a.mark("read")
            // Snapshot the complete user descriptor before consulting its fields.
            a.emit(UltraKernelA64.addImm(0, SP, READ_ARGS))
            a.emit(UltraKernelA64.ldAuto("ldr", 1, SP, 40, 8))
            a.emit(UltraKernelA64.encodeMovImm(2, 16, sf = 0))
            a.blAbs(r.require("copy_from_user_nofault"))
            a.cbnz(0, "read-fault")
            a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, READ_ARGS + 12, 4))
            a.cbnz(12, "respond", sf = false)
            a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, READ_ARGS + 8, 4))
            a.cbz(12, "respond", sf = false)
            a.emit(UltraKernelA64.cmpImm(12, READ_MAX, sf = 0))
            a.bCond(UltraKernelA64.HI, "respond")
            a.emit(UltraKernelA64.addImm(12, 12, 1, sub = true))
            a.emit(UltraKernelA64.ldAuto("ldr", 13, SP, 32, 8))
            a.emit(UltraKernelA64.encodeMovImm(14, 0xffff000000000000UL.toLong()))
            a.emit(UltraKernelA64.cmpReg(13, 14))
            a.bCond(UltraKernelA64.CC, "respond")
            a.emit(UltraKernelA64.addReg(14, 13, 12, setFlags = true))
            a.bCond(UltraKernelA64.CS, "respond")
            a.emit(UltraKernelA64.ldAuto("ldr", 13, SP, READ_ARGS, 8))
            a.cbz(13, "respond")
            a.emit(UltraKernelA64.addReg(14, 13, 12, setFlags = true))
            a.bCond(UltraKernelA64.CS, "respond")
            a.emit(UltraKernelA64.addImm(0, SP, READ_DATA))
            a.emit(UltraKernelA64.ldAuto("ldr", 1, SP, 32, 8))
            a.emit(UltraKernelA64.ldAuto("ldr", 2, SP, READ_ARGS + 8, 4))
            a.blAbs(kernelRead)
            a.cbnz(0, "read-fault")
            a.emit(UltraKernelA64.ldAuto("ldr", 0, SP, READ_ARGS, 8))
            a.emit(UltraKernelA64.addImm(1, SP, READ_DATA))
            a.emit(UltraKernelA64.ldAuto("ldr", 2, SP, READ_ARGS + 8, 4))
            a.blAbs(r.require("copy_to_user_nofault"))
            a.cbnz(0, "read-fault")
            a.emit(UltraKernelA64.ldAuto("ldr", 12, SP, READ_ARGS + 8, 4))
            a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 24, 8))
            a.b("success")
            a.mark("read-fault")
            status(a, -14)
            a.b("respond")
        }
        a.mark("success")
        a.emit(UltraKernelA64.ldAuto("str", ZR, SP, RESPONSE + 12, 4))

        a.mark("respond")
        copyResponse(a, r, RESPONSE, WIRE_BYTES)
        a.cbnz(0, "out")
        // Publish completion only after the complete, completion-zero response copied.
        a.emit(UltraKernelA64.encodeMovImm(12, RESPONSE_MAGIC, sf = 0))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, COMPLETION, 4))
        copyResponse(a, r, COMPLETION, 4)
        a.mark("out")
        a.emit(UltraKernelA64.addImm(SP, SP, STACK_BYTES))
        a.bAbs(r.require("arm64_notify_die"))

        if (a.here() % 8 != 0) a.emit(UltraKernelA64.NOP)
        a.mark("metadata")
        val site = a.here().toLong()
        val metadata = ByteArray(WIRE_BYTES)
        UltraKernelA64.writeLe32(metadata, 0, METADATA_MAGIC)
        UltraKernelA64.writeLe32(metadata, 4, VERSION_LENGTH)
        fun write64(offset: Int, value: Long) {
            for (byte in 0 until 8) metadata[offset + byte] = (value ushr (byte * 8)).toByte()
        }
        write64(8, capabilities)
        write64(16, -site)
        write64(24, r.require("free_initmem").toLong() + 4 - site)
        a.embed(metadata)
        val providerGet = r.exact("maplesu_legacy_hook_provider_get")
        val providerPut = r.exact("maplesu_legacy_hook_provider_put")
        val privateTail = ByteArray(24)
        if (providerGet != null && providerPut != null) {
            UltraKernelA64.writeLe32(privateTail, 0, 0x35484c4d)
            UltraKernelA64.writeLe32(privateTail, 4, (24 shl 16) or 1)
            for ((offset, value) in listOf(8 to providerGet.toLong() - site,
                16 to providerPut.toLong() - site))
                for (byte in 0 until 8) privateTail[offset + byte] = (value shr (byte * 8)).toByte()
        }
        a.embed(privateTail)
    }

    private fun status(a: UltraKernelAsm, value: Int) {
        a.emit(UltraKernelA64.encodeMovImm(12, value.toLong(), sf = 0))
        a.emit(UltraKernelA64.ldAuto("str", 12, SP, RESPONSE + 12, 4))
    }

    private fun copyResponse(a: UltraKernelAsm, r: UltraKernelSymbolResolver, offset: Int, bytes: Int) {
        a.emit(UltraKernelA64.ldAuto("ldr", 0, SP, 24, 8))
        a.emit(UltraKernelA64.addImm(1, SP, offset))
        a.emit(UltraKernelA64.encodeMovImm(2, bytes.toLong(), sf = 0))
        a.blAbs(r.require("copy_to_user_nofault"))
    }
}
