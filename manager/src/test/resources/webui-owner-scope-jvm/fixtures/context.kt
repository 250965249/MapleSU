package android.content

open class Context {
    val started = ArrayList<Intent>()
    var startFailure: RuntimeException? = null
    fun startActivity(intent: Intent) { startFailure?.let { throw it }; started += intent }
}

class Intent(val context: Context? = null, val target: Class<*>? = null) {
    private val extras = HashMap<String, Any?>()
    fun addFlags(flags: Int) = this
    fun putExtra(key: String, value: String?) = apply { extras[key] = value }
    fun putExtra(key: String, value: Long) = apply { extras[key] = value }
    fun putExtra(key: String, value: Int) = apply { extras[key] = value }
    fun hasExtra(key: String) = extras.containsKey(key)
    fun getStringExtra(key: String) = extras[key] as? String
    fun getLongExtra(key: String, default: Long) = extras[key] as? Long ?: default
    fun getIntExtra(key: String, default: Int) = extras[key] as? Int ?: default
    companion object { const val FLAG_ACTIVITY_NEW_TASK = 0x10000000 }
}
