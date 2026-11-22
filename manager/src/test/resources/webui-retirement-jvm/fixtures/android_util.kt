package android.util

object Log {
    @JvmStatic fun w(tag: String, message: String, error: Throwable) = 0
    @JvmStatic fun w(tag: String, message: String) = 0
    @JvmStatic fun e(tag: String, message: String, error: Throwable) = 0
    @JvmStatic fun e(tag: String, message: String) = 0
}
object Base64 {
    const val DEFAULT = 0
    @JvmStatic fun decode(value: String, flags: Int): ByteArray = java.util.Base64.getDecoder().decode(value)
}
