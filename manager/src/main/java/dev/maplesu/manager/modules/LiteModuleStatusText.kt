package dev.maplesu.manager.modules

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.data.model.Module

@Composable
fun liteModuleStatusText(module: Module): String {
    val resource = when (module.runtimeStatus) {
        "stored_pro" -> R.string.module_runtime_pro_stored
        "stored" -> R.string.module_runtime_stored
        "remove_pending" -> R.string.module_runtime_remove_pending
        "disabled" -> R.string.module_runtime_disabled
        "interrupted" -> R.string.module_runtime_interrupted
        "failed" -> R.string.module_runtime_failed
        "running" -> R.string.module_runtime_running
        "installed" -> R.string.module_runtime_installed
        "late_completed" -> R.string.module_runtime_late_completed
        "late_pending" -> R.string.module_runtime_late_pending
        else -> return ""
    }
    val base = if (module.runtimeStatus == "failed" && module.runtimeExitCode != null)
        stringResource(R.string.module_runtime_failed_code, module.runtimeExitCode)
    else stringResource(resource)
    // T6: the bundled module is a normal module with a normal lifecycle; the tag only
    // tells the user where it came from.
    val tagged = if (module.builtin) stringResource(R.string.module_builtin_tag) + " · " + base else base
    // T4: "installed" must never read as "fully working". Capabilities without a current
    // consumer are named on the module card, with the reasons
    // in the receipt (`stage.*`, `props.*`) rather than silently dropped.
    // The stored keys stay the wire contract; only the rendered label is localized, so an
    // unrecognized key is still shown verbatim instead of being guessed at.
    // A nullable function parameter cannot be inlined, so the composable label lookup happens
    // in a plain `map` first; calling `stringResource` inside `joinToString` does not compile.
    if (module.unsupported.isEmpty()) return tagged
    val labels = module.unsupported.map { capabilityLabel(it) }
    return tagged + "\n" + stringResource(
        R.string.module_runtime_unsupported,
        labels.joinToString(stringResource(R.string.module_capability_separator)))
}

/** Display name for one `unsupported` capability key (the key itself is never renamed). */
@Composable
private fun capabilityLabel(key: String): String = when (key) {
    "toggle" -> stringResource(R.string.module_capability_toggle)
    "stop" -> stringResource(R.string.module_capability_stop)
    "in-place-update" -> stringResource(R.string.module_capability_in_place_update)
    "mount" -> stringResource(R.string.module_capability_mount)
    "zygisk" -> stringResource(R.string.module_capability_zygisk)
    "sepolicy-apply" -> stringResource(R.string.module_capability_sepolicy_apply)
    else -> key
}
