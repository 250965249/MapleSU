package com.maplesu.core.ui.util

enum class DownloadCompletionAction {
    INSTALL_MODULE,
    OPEN_FILE,
}

class DownloadService {
    companion object {
        const val ACTION_DOWNLOAD = "com.maplesu.core.action.DOWNLOAD"
        const val EXTRA_DOWNLOAD_ID = "downloadId"
        const val EXTRA_URL = "url"
        const val EXTRA_FILE_NAME = "fileName"
        const val EXTRA_EXPECTED_SIZE = "expectedSize"
        const val EXTRA_EXPECTED_SHA256 = "expectedSha256"
        const val EXTRA_TARGET_PATH = "targetPath"
        const val EXTRA_MIME_TYPE = "mimeType"
        const val EXTRA_COOKIE = "cookie"
        const val EXTRA_USER_AGENT = "userAgent"
        const val EXTRA_COMPLETION_ACTION = "completionAction"
        const val EXTRA_DELETE_FILE_ON_DISMISS = "deleteFileOnDismiss"
    }
}
