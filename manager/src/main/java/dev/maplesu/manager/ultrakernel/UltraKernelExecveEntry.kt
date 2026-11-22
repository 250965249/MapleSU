package dev.maplesu.manager.ultrakernel

/** Select the legacy eight-register exec entry only when both native wrappers prove its ABI. */
internal object UltraKernelExecveEntry {
    fun resolve(symbols: UltraKernelSymbols, kernel: ByteArray): UltraKernelSymbols {
        if (symbols.offsetOf("do_execveat_common") != null) return symbols
        val entry = symbols.offsetsOf("__do_execve_file").singleOrNull() ?: return symbols
        val execve = intArrayOf(
            UltraKernelA64.movReg(5, 2), UltraKernelA64.movReg(3, 1), UltraKernelA64.movReg(1, 0),
            UltraKernelA64.movn(0, 99, sf = 0), UltraKernelA64.movReg(2, 31),
            UltraKernelA64.movReg(4, 31), UltraKernelA64.movReg(6, 31, sf = 0), UltraKernelA64.movReg(7, 31),
        )
        val execveat = intArrayOf(
            UltraKernelA64.movReg(6, 4, sf = 0), UltraKernelA64.movReg(5, 3), UltraKernelA64.movReg(3, 2),
            UltraKernelA64.movReg(2, 31), UltraKernelA64.movReg(4, 31), UltraKernelA64.movReg(7, 31),
        )
        if (!wrapper(symbols, kernel, "do_execve", execve, entry) ||
            !wrapper(symbols, kernel, "do_execveat", execveat, entry)) return symbols
        return object : UltraKernelSymbols by symbols {
            override fun offsetOf(name: String): Int? =
                if (name == "do_execveat_common") entry else symbols.offsetOf(name)

            override fun offsetsOf(name: String): List<Int> =
                if (name == "do_execveat_common") listOf(entry) else symbols.offsetsOf(name)
        }
    }

    private fun wrapper(
        symbols: UltraKernelSymbols,
        kernel: ByteArray,
        name: String,
        arguments: IntArray,
        entry: Int,
    ): Boolean {
        val start = symbols.offsetsOf(name).singleOrNull() ?: return false
        // Exact SCS/frame save and restore bound the argument moves: no intervening
        // calls, branches or stack arguments can silently change the proved ABI.
        val prefix = intArrayOf(0xF800865E.toInt(), 0xA9BF7BFD.toInt(), 0x910003FD.toInt())
        val suffix = intArrayOf(0xA8C17BFD.toInt(), 0xF85F8E5E.toInt(), UltraKernelA64.RET)
        val end = start.toLong() + (prefix.size + arguments.size + 1 + suffix.size) * 4
        if (start < 0 || end > kernel.size || end > (symbols.nextOffset(start) ?: kernel.size)) return false
        val call = start + (prefix.size + arguments.size) * 4
        val branch = UltraKernelA64.le32Bits(kernel, call)
        if (!UltraKernelA64.isBl(branch) ||
            call.toLong() + UltraKernelA64.signExtend((branch and 0x03FFFFFF).toLong(), 26) * 4 != entry.toLong()
        ) return false
        return (prefix + arguments).withIndex().all { (index, word) ->
            UltraKernelA64.le32Bits(kernel, start + index * 4) == word
        } && suffix.withIndex().all { (index, word) ->
            UltraKernelA64.le32Bits(kernel, call + 4 + index * 4) == word
        }
    }
}
