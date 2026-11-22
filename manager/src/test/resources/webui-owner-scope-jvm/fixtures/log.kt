package android.util

object Log {
    fun w(tag: String, message: String, error: Throwable) = 0
    fun w(tag: String, message: String) = 0
    fun i(tag: String, message: String) = 0
}
