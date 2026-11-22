package android.content

open class Context
class Intent(val context: Context, val target: Class<*>) {
    var action: String? = null
    val extras = mutableMapOf<String, Any?>()
    fun putExtra(key: String, value: Int) = apply { extras[key] = value }
    fun putExtra(key: String, value: Long) = apply { extras[key] = value }
    fun putExtra(key: String, value: String?) = apply { extras[key] = value }
}
