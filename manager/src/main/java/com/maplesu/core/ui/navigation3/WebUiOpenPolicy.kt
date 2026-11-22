package com.maplesu.core.ui.navigation3

/**
 * Why a module WebUI is being opened.
 *
 * Only [USER_CLICK] and [DEEP_LINK] describe a user action that happened **now**.
 * Everything else — including any state we cannot classify — must not navigate.
 */
enum class WebUiOpenOrigin {
    /** The user tapped the module's own "open WebUI" control. */
    USER_CLICK,

    /** A validated `ksu://webui?id=…&token=…` deep link or home-screen shortcut. */
    DEEP_LINK,

    /** Process/Activity creation that carried no user action. */
    PROCESS_START,

    /** A saved base intent / task being restored by the system. */
    RESTORED_STATE,

    /** A post-install "open it now" receipt from the module installer. */
    INSTALL_RECEIPT,

    /** Anything the caller could not classify. */
    UNKNOWN,
}

/**
 * One request to show a module WebUI.
 *
 * Deliberately free of Android types so the decision is JVM-testable and cannot depend on
 * Activity/Intent side effects.
 */
data class WebUiOpenRequest(
    val moduleId: String?,
    val origin: WebUiOpenOrigin?,
    val tokenValid: Boolean = true,
)

/**
 * Fail-safe navigation gate for module WebUIs.
 *
 * The reported bug was an automatic jump into a module's WebUI on every app start. The fix
 * has two halves: remove the background caller that started the WebUI server
 * (`SoterLane`), and make this gate the single decision point so any future automatic
 * caller is rejected by construction. Unknown/absent origin, blank module id, an invalid
 * token, process start, restored state and install receipts all return `false` — the gate
 * never guesses its way into a navigation.
 */
object WebUiOpenPolicy {

    /** True only for the two origins that represent a present, explicit user action. */
    fun isExplicitUserAction(origin: WebUiOpenOrigin?): Boolean =
        origin == WebUiOpenOrigin.USER_CLICK || origin == WebUiOpenOrigin.DEEP_LINK

    /** Whether this request may start a WebUI Activity / route. */
    fun mayNavigate(request: WebUiOpenRequest?): Boolean {
        if (request == null) return false
        if (!isExplicitUserAction(request.origin)) return false
        if (!request.tokenValid) return false
        return request.moduleId?.isNotBlank() == true
    }
}

/**
 * One-shot, **process-local** holder for a pending WebUI open request.
 *
 * It survives composition/ViewModel recreation (so an explicit request is not lost while a
 * screen recomposes) but never process death and is never persisted: a cold start can
 * therefore never replay a previous request. The consumer clears the pending value
 * *before* navigating, so a crash or a duplicated delivery cannot open the page twice.
 */
class PendingWebUiOpen {

    private var pending: WebUiOpenRequest? = null

    /** Queue [request] if it passes the gate and nothing is already pending. */
    @Synchronized
    fun offer(request: WebUiOpenRequest?): Boolean {
        if (!WebUiOpenPolicy.mayNavigate(request)) return false
        if (pending != null) return false
        pending = request
        return true
    }

    /** Take and clear the pending request; `null` when there is nothing to do. */
    @Synchronized
    fun consume(): WebUiOpenRequest? {
        val request = pending ?: return null
        pending = null
        return request
    }

    @Synchronized
    fun isPending(): Boolean = pending != null

    @Synchronized
    fun clear() {
        pending = null
    }
}
