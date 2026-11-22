package com.maplesu.core.ui.screen.templateeditor

internal fun <T> templateNeedsDiscardConfirmation(initial: T, draft: T, readOnly: Boolean): Boolean =
    !readOnly && initial != draft
