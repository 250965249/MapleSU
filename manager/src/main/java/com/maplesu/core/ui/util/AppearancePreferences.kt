package com.maplesu.core.ui.util

import android.content.Context
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.storage.SettingsPrefsRouter

/** Visual preferences follow the person, not the installed backend. Functional settings stay routed. */
object AppearancePreferences {
    const val NAME = "maplesu_appearance"
    const val INTRO_COMPLETE = "appearance_intro_complete_v1"
    const val INTRO_COMIC = "appearance_intro_comic"
    // v1 may have been written before bootstrap knew which legacy file to read.
    internal const val RESOLVED_MIGRATION = "migrated_resolved_v2"

    val keys = setOf(
        AppearancePrefsPolicy.HOME_LARGE_CARD, AppearancePrefsPolicy.DECORATION_SOURCE, "home_card_layout",
        "ui_mode", "color_mode", "miuix_monet", "key_color", "color_style", "color_spec",
        "wallpaper_path", "wallpaper_kind", "wallpaper_land_path", "wallpaper_land_kind",
        "wallpaper_dim", "wallpaper_blur", "wallpaper_seed", "wallpaper_seed_color",
        "ui_translucent", "ui_translucent_alpha", "status_decoration_anchor", "status_decoration_dim",
        "status_decoration_hide_text", "status_decoration_bias_x", "status_decoration_bias_y", "status_decoration_zoom",
        "nav_icon_circle", "nav_icon_tint", "snow_enabled", "snow_size", "snow_speed",
        "troll_rain_enabled", "troll_rain_size", "troll_rain_speed", "gravity_enabled", "gravity_mode",
        "flat_home", "enable_predictive_back", "enable_swipe_dismiss", "pager_interception_mode",
        "enable_blur", "enable_floating_bottom_bar", "enable_floating_bottom_bar_blur",
        "enable_navigation_badge", "nav_rail_expanded", "page_scale", "module_description_max_lines",
    )

    @Volatile private var cached: SharedPreferences? = null

    @JvmStatic
    fun prefs(context: Context): SharedPreferences = cached ?: synchronized(this) {
        cached ?: context.applicationContext.getSharedPreferences(NAME, Context.MODE_PRIVATE).also { shared ->
            if (!shared.getBoolean(RESOLVED_MIGRATION, false)) {
                val mode = ModeRuntime.active
                if (mode != null) {
                    importMissing(shared, SettingsPrefsRouter(context).prefs(mode).all, modeResolved = true)
                }
            }
            cached = shared
        }
    }

    /** Called after bootstrap activation; legacy reads stay on the detection worker. */
    @JvmStatic
    fun onModeResolved(context: Context) {
        val mode = ModeRuntime.active ?: return
        // Wait for a concurrent unresolved first read to publish its cached instance.
        val shared = synchronized(this) { cached } ?: return
        if (shared.getBoolean(RESOLVED_MIGRATION, false)) return
        val legacy = SettingsPrefsRouter(context).prefs(mode).all
        val complete = Runnable {
            synchronized(this) {
                if (!shared.getBoolean(RESOLVED_MIGRATION, false)) {
                    // Re-evaluate missing keys on the UI thread. A choice made while the source
                    // was being read is already present and wins; a later choice overwrites us.
                    importMissing(shared, legacy, modeResolved = true)
                }
            }
        }
        if (Looper.myLooper() === Looper.getMainLooper()) complete.run()
        else Handler(Looper.getMainLooper()).post(complete)
    }

    private fun importMissing(shared: SharedPreferences, legacy: Map<String, *>, modeResolved: Boolean) {
        val plan = migrationPlan(shared.all, legacy, modeResolved)
        if (plan.values.isEmpty() && !plan.complete) return
        val editor = shared.edit()
        for ((key, value) in plan.values) {
            if (shared.contains(key)) continue
            when (value) {
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Float -> editor.putFloat(key, value)
                is Long -> editor.putLong(key, value)
                is String -> editor.putString(key, value)
            }
        }
        if (plan.complete) editor.putBoolean("migrated_v1", true).putBoolean(RESOLVED_MIGRATION, true)
        editor.apply() // Existing preference listeners publish the newly imported appearance.
    }

    internal data class MigrationPlan(val values: Map<String, Any>, val complete: Boolean)

    /** Only missing visual values migrate, and only after the actual legacy source is known. */
    internal fun migrationPlan(
        existing: Map<String, *>,
        legacy: Map<String, *>,
        modeResolved: Boolean,
    ): MigrationPlan = if (!modeResolved) MigrationPlan(emptyMap(), complete = false) else MigrationPlan(
        values = legacy.mapNotNull { (key, value) ->
            if (key !in keys || key in existing) null else when (value) {
                is Boolean, is Int, is Float, is Long, is String -> key to value
                else -> null
            }
        }.toMap(),
        complete = modeResolved,
    )
}
