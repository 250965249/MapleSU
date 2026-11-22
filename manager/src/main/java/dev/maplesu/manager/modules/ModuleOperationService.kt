package dev.maplesu.manager.modules

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.maplesu.core.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Keeps user module work foreground until its existing result or cancellation completes. */
class ModuleOperationService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val main = Handler(Looper.getMainLooper())
    private val jobs = mutableMapOf<String, Job>()
    private var latestStartId = 0

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        val token = intent?.getStringExtra(EXTRA_TOKEN)
        val task = token?.let(tasks::take)
        try {
            promote()
        } catch (error: Exception) {
            task?.result?.completeExceptionally(error)
            stopIfIdle()
            return START_NOT_STICKY
        }
        if (task == null) {
            stopIfIdle()
            return START_NOT_STICKY
        }
        val job = task.start(scope)
        if (job != null) {
            jobs[task.token] = job
            job.invokeOnCompletion {
                main.post {
                    jobs.remove(task.token)
                    stopIfIdle()
                }
            }
        } else {
            stopIfIdle()
        }
        return START_NOT_STICKY
    }

    private fun promote() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.module_operation_channel), NotificationManager.IMPORTANCE_LOW),
        )
        val notification = NotificationCompat.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_logo_vector)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.module_operation_running))
            .setOngoing(true)
            .setSilent(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION, notification)
        }
    }

    private fun stopIfIdle() {
        if (jobs.isEmpty()) stopSelfResult(latestStartId)
    }

    override fun onDestroy() {
        scope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL = "maplesu_module_operations"
        private const val NOTIFICATION = 24026
        private const val EXTRA_TOKEN = "module_operation_token"
        private val tasks = ModuleOperationTasks()

        /** No persistent queue: process recreation never replays an install or script. */
        suspend fun <T> run(context: Context, operation: suspend () -> T): T {
            currentCoroutineContext().ensureActive()
            val task = tasks.register {
                try { operation() } finally {
                    // This runs in the service owner even when the page has gone away.
                    com.maplesu.core.data.repository.ModuleRepositoryImpl.invalidateModuleList()
                }
            }
            try {
                ContextCompat.startForegroundService(context.applicationContext,
                    Intent(context.applicationContext, ModuleOperationService::class.java).putExtra(EXTRA_TOKEN, task.token))
                return task.result.await()
            } finally {
                tasks.discard(task.token)
                task.result.cancel()
            }
        }
    }
}
