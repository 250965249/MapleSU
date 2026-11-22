package androidx.core.content

import android.content.Context
import android.content.Intent

object ContextCompat {
    var starts = 0
    var lastIntent: Intent? = null
    var lastContext: Context? = null
    fun startForegroundService(context: Context, intent: Intent) {
        starts++
        lastContext = context
        lastIntent = intent
    }
}
