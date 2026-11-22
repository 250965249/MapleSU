package dev.maplesu.manager.runtime

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.os.ResultReceiver
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.maplesu.core.R
import dev.maplesu.manager.jailbreak.DirtyfragAttempt
import dev.maplesu.manager.jailbreak.JailbreakRequest
import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/** Keeps the existing Hook endpoint alive while the Manager and its clients are backgrounded. */
class HookSuKeeperService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        @Suppress("DEPRECATION")
        val reply = intent?.getParcelableExtra<ResultReceiver>(EXTRA_REPLY)
        try {
            val status = JailbreakStatus.read(this)
            check(hookPublicationMayStayAlive(status, DirtyfragAttempt.readBootId(), ModeRuntime.active) &&
                status?.attemptId == intent?.getStringExtra(EXTRA_ATTEMPT) &&
                SuGate.read(this, status?.attemptId, status?.bootId).armed &&
                NativeSuBrokerService.isReady()) { "HOOK_PUBLICATION_NOT_READY" }
            val notifications = getSystemService(NotificationManager::class.java)
            notifications.createNotificationChannel(NotificationChannel(CHANNEL,
                getString(R.string.hook_su_channel), NotificationManager.IMPORTANCE_LOW))
            val open = Intent().setClassName(this, "com.maplesu.core.ui.MainActivity")
            val notification = NotificationCompat.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_logo_vector)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.hook_su_running))
                .setContentIntent(PendingIntent.getActivity(this, 0, open,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
                .setOngoing(true).setSilent(true).build()
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION, notification)
            }
            reply?.send(1, Bundle())
        } catch (error: Exception) {
            reply?.send(0, Bundle().apply { putString("failure", error.javaClass.simpleName) })
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelfResult(startId)
        }
        // Recovery belongs to trusted preparation/reproof; never replay a kernel attempt.
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL = "maplesu_hook_su"
        private const val NOTIFICATION = 24028
        private const val EXTRA_REPLY = "reply"
        private const val EXTRA_ATTEMPT = "attempt"

        /** Called off the main thread, only after trusted preparation verified the carrier. */
        fun retain(context: Context, attemptId: String?) {
            val ready = CompletableFuture<Unit>()
            val reply = object : ResultReceiver(null) {
                override fun onReceiveResult(resultCode: Int, resultData: Bundle?) {
                    if (resultCode == 1) ready.complete(Unit)
                    else ready.completeExceptionally(IllegalStateException(
                        "HOOK_PUBLICATION_KEEPER_FAILED:" + resultData?.getString("failure")))
                }
            }
            ContextCompat.startForegroundService(context.applicationContext,
                Intent(context, HookSuKeeperService::class.java)
                    .putExtra(EXTRA_ATTEMPT, attemptId).putExtra(EXTRA_REPLY, reply))
            ready.get(8, TimeUnit.SECONDS)
        }
    }
}

internal fun hookPublicationMayStayAlive(status: JailbreakStatus?, bootId: String?, mode: WorkMode?): Boolean =
    mode != WorkMode.KSU && !bootId.isNullOrBlank() && status?.bootId == bootId &&
        status.rootBackend == JailbreakRequest.BACKEND_HOOK &&
        status.stage == JailbreakStatus.STAGE_DAEMON_READY && status.failure == null &&
        !status.attemptId.isNullOrBlank()
