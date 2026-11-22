package android.util

object Log { fun e(tag: String, message: String, error: Throwable): Int {
    check(tag.isNotEmpty() && message.isNotEmpty() && error.message != null); return 0
} }
