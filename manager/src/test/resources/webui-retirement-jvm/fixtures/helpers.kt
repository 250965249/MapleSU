package com.maplesu.core.ui.webui

import android.app.Activity

data class Insets(val a: Int, val b: Int, val c: Int, val d: Int) { val css = "" }
fun Activity.setTaskDescription(text: String) {}
fun webUIApps() = com.maplesu.core.ui.viewmodel.SuperUserViewModel.apps
object MonetColorsProvider { fun getColorsCss() = "" }
object MimeUtil { @JvmStatic fun getMimeFromFileName(path: String): String? = "text/plain" }
