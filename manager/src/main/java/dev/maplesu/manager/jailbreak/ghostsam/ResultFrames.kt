package dev.maplesu.manager.jailbreak.ghostsam

/**
 * Strict result-frame reader for the V2 self-built consumer transport.
 * 'P' is exactly 10 bytes; 'R'/'F' are 5 bytes; 'X' and 'D' are single-byte tags.
 * NOTE: the MapleSU product App-side identity reader remains `LeaseProtocol.readIdentity`
 * (unchanged). This mirror exists so C/Kotlin reference paths reject malformed frames.
 */
object ResultFrames {
    data class Restore(val applied: Int, val origin: Int, val enforcing: Int,
                       val checkreqprot: Int, val policy: Int, val unloadErrno: Int)

    fun parse(data: ByteArray): Map<String, Any> {
        if (data.isEmpty()) throw LeaseWireException("LEASE_RESULT_FRAME_INVALID")
        return when (data[0].toInt().toChar()) {
            'P' -> {
                if (data.size != 10) throw LeaseWireException("LEASE_RESTORE_FRAME_INVALID")
                if (data[1].toInt() !in 0..3) throw LeaseWireException("LEASE_RESTORE_STATE_INVALID")
                if (data[2].toInt() !in 0..3) throw LeaseWireException("LEASE_RESTORE_ORIGIN_INVALID")
                if (data[3].toInt() !in setOf(0, 1, 0xFF)) throw LeaseWireException("LEASE_RESTORE_ENFORCING_INVALID")
                if (data[4].toInt() !in setOf(0, 1, 2, 0xFF)) throw LeaseWireException("LEASE_RESTORE_CHECKREQPROT_INVALID")
                if (data[5].toInt() !in 0..2) throw LeaseWireException("LEASE_RESTORE_POLICY_INVALID")
                val errno = ((data[6].toInt() and 0xFF) shl 24) or ((data[7].toInt() and 0xFF) shl 16) or
                    ((data[8].toInt() and 0xFF) shl 8) or (data[9].toInt() and 0xFF)
                mapOf("tag" to "P", "restore" to Restore(data[1].toInt(), data[2].toInt(), data[3].toInt(), data[4].toInt(), data[5].toInt(), errno))
            }
            'X' -> { if (data.size != 1) throw LeaseWireException("LEASE_RESULT_TRAILING"); mapOf("tag" to "X") }
            'D' -> { if (data.size != 1) throw LeaseWireException("LEASE_D_PAYLOAD_NONEMPTY"); mapOf("tag" to "D") }
            'R' -> {
                if (data.size != 5) throw LeaseWireException("LEASE_READY_FRAME_INVALID")
                val pid = ((data[1].toInt() and 0xFF) shl 24) or ((data[2].toInt() and 0xFF) shl 16) or
                    ((data[3].toInt() and 0xFF) shl 8) or (data[4].toInt() and 0xFF)
                if (pid <= 1) throw LeaseWireException("LEASE_SHELL_PID_INVALID")
                mapOf("tag" to "R", "pid" to pid)
            }
            'F' -> { if (data.size != 5 || data[1].toInt() !in 1..7) throw LeaseWireException("LEASE_STAGE_INVALID"); mapOf("tag" to "F", "stage" to data[1].toInt()) }
            else -> throw LeaseWireException("LEASE_RESULT_TAG_INVALID")
        }
    }
}
