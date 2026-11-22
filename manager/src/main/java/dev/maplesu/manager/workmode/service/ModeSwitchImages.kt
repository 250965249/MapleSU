package dev.maplesu.manager.workmode.service

import java.io.File

/** Private copies of selected documents; an omitted Ultra boot uses the live partition. */
data class ModeSwitchImages(val boot: File? = null, val initBoot: File? = null)
