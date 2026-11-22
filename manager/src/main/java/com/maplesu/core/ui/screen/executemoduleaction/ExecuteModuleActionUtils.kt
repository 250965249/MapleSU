package com.maplesu.core.ui.screen.executemoduleaction

import android.os.Environment
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

fun saveLog(
    logSnapshot: () -> String,
    scope: CoroutineScope,
    failMessage: String,
    successMessage: String,
    showMessage: (String) -> Unit,
): () -> Unit = {
    val snapshot = logSnapshot()
    scope.launch {
        val result = withContext(Dispatchers.IO) {
            try {
                val date = SimpleDateFormat("yyyy-MM-dd-HH-mm-ss", Locale.getDefault()).format(Date())
                val file = File(
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                    "MapleSU_module_action_log_${date}.log",
                )
                file.writeText(snapshot)
                Result.success(file.absolutePath)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                Result.failure(error)
            }
        }
        showMessage(result.fold({ successMessage.format(it) }, { failMessage }))
    }
}
