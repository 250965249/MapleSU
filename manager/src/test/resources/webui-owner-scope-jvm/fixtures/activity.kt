package android.app

open class Activity : android.content.Context() {
    val window = android.view.Window()
    val queued = ArrayList<Runnable>()
    var isFinishing = false
    fun runOnUiThread(action: Runnable) { queued += action }
    fun drain() { val pending = queued.toList(); queued.clear(); pending.forEach { it.run() } }
    fun getString(id: Int): String = id.toString()
    fun finish() { isFinishing = true }
}
