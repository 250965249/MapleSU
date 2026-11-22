package com.maplesu.core.ui.util

import android.content.Context
import android.net.Uri
import androidx.core.content.ContextCompat
import org.junit.Assert.*
import org.junit.Test

class LocalSaveTest {
    @Test fun localSaveRegistersWithoutServiceAndAdvancesThroughProgressAndCompletion() {
        val starts = ContextCompat.starts
        val previousIntent = ContextCompat.lastIntent
        val targetPath = "/fixture/downloads/static-report.json"
        val id = DownloadManager.registerLocalSave("static-report.json", "application/json", targetPath)
        val initial = DownloadManager.downloads.value.getValue(id)
        assertEquals("static-report.json", initial.fileName)
        assertEquals("application/json", initial.mimeType)
        assertEquals(targetPath, initial.targetPath)
        assertEquals(DownloadCompletionAction.OPEN_FILE, initial.completionAction)
        assertEquals(DownloadManager.Status.PENDING, initial.status)
        assertNull(initial.expected)
        assertEquals(starts, ContextCompat.starts)
        assertSame(previousIntent, ContextCompat.lastIntent)
        DownloadManager.updateProgress(id, 53)
        val progress = DownloadManager.downloads.value.getValue(id)
        assertEquals(DownloadManager.Status.DOWNLOADING, progress.status)
        assertEquals(53, progress.progress)
        val uri = Uri.parse("content://downloads/static-report.json")
        DownloadManager.markCompleted(id, uri)
        val completed = DownloadManager.downloads.value.getValue(id)
        assertEquals(DownloadManager.Status.COMPLETED, completed.status)
        assertEquals(100, completed.progress)
        assertEquals(uri, completed.resultUri)
        assertEquals("application/json", completed.mimeType)
        assertEquals(targetPath, completed.targetPath)
        assertEquals(DownloadCompletionAction.OPEN_FILE, completed.completionAction)
        assertEquals(starts, ContextCompat.starts)
        assertSame(previousIntent, ContextCompat.lastIntent)
    }

    @Test fun localSavesAndNetworkDownloadsUseOneIdSequenceButNeverMerge() {
        val starts = ContextCompat.starts
        val first = DownloadManager.registerLocalSave("same.bin", "application/octet-stream")
        val second = DownloadManager.registerLocalSave("same.bin", "application/octet-stream")
        assertEquals(first + 1, second)
        assertEquals(DownloadCompletionAction.OPEN_FILE, DownloadManager.downloads.value.getValue(second).completionAction)
        assertEquals(starts, ContextCompat.starts)
        assertTrue(DownloadManager.downloads.value.getValue(second).url.startsWith("local-save:"))
        val source = "https://fixture.invalid/same.bin"
        val context = Context()
        val targetPath = "/fixture/downloads/network.bin"
        val network = DownloadManager.enqueue(context, source, "same.bin", targetPath = targetPath,
            mimeType = "application/octet-stream", cookie = "session=fixture", userAgent = "FixtureWebUI/1",
            completionAction = DownloadCompletionAction.OPEN_FILE)
        assertEquals(second + 1, network)
        assertEquals(starts + 1, ContextCompat.starts)
        val networkState = DownloadManager.downloads.value.getValue(network)
        assertEquals("application/octet-stream", networkState.mimeType)
        assertEquals(targetPath, networkState.targetPath)
        assertEquals(DownloadCompletionAction.OPEN_FILE, networkState.completionAction)
        val intent = requireNotNull(ContextCompat.lastIntent)
        assertSame(context, ContextCompat.lastContext)
        assertSame(context, intent.context)
        assertEquals(DownloadService::class.java, intent.target)
        assertEquals("com.maplesu.core.action.DOWNLOAD", intent.action)
        assertEquals(mapOf("downloadId" to network, "url" to source, "fileName" to "same.bin",
            "targetPath" to targetPath, "mimeType" to "application/octet-stream", "cookie" to "session=fixture",
            "userAgent" to "FixtureWebUI/1", "completionAction" to "OPEN_FILE"), intent.extras)
        assertEquals(network, DownloadManager.enqueue(context, source, "same.bin", targetPath = targetPath,
            mimeType = "application/octet-stream", cookie = "session=fixture", userAgent = "FixtureWebUI/1",
            completionAction = DownloadCompletionAction.OPEN_FILE))
        assertEquals(starts + 1, ContextCompat.starts)
        assertSame(intent, ContextCompat.lastIntent)
        DownloadManager.markFailed(first, "Cancelled")
        assertEquals(DownloadManager.Status.FAILED, DownloadManager.downloads.value.getValue(first).status)
        assertEquals("Cancelled", DownloadManager.downloads.value.getValue(first).error)
        assertEquals(DownloadManager.Status.PENDING, DownloadManager.downloads.value.getValue(second).status)
    }
}
