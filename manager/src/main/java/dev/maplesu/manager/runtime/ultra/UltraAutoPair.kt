package dev.maplesu.manager.runtime.ultra

import android.content.Context
import android.os.Looper
import android.util.Log
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.superuser.LiteImplantCodes
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate

object UltraAutoPair {

    /** rootKey 的固定长度（ASCII 字符），与 [UltraKeyProvisioning] 的校验一致。 */
    const val KEY_LENGTH = 48

    private const val TAG = "MapleSUUltraAutoPair"

    /** 本地 key 的三种状态，供设置页决定提示文案。 */
    enum class KeyState { Present, Absent, Malformed }

    data class Result(
        val paired: Boolean,
        val state: UltraEnvironmentProbe.State,
        val reason: String,
        val keyState: KeyState,
    )

    fun keyState(context: Context): KeyState {
        val key = UltraRootKeyStore.read(context.applicationContext) ?: return KeyState.Absent
        return if (key.length == KEY_LENGTH) KeyState.Present else KeyState.Malformed
    }

    /**
     * Ensures the pairing flag matches reality. Idempotent; safe to call on every start/refresh.
     */
    fun ensure(context: Context, maintenance: Boolean = true): Result {
        check(Looper.myLooper() != Looper.getMainLooper()) {
            "ULTRA_AUTO_PAIR_BACKGROUND_THREAD_REQUIRED"
        }
        // W19 写者静默：切换期间不写任何配对/环境状态。
        if (LiteImplantQuiesceGate.isBlocked()) {
            return Result(
                false, UltraEnvironmentProbe.State.Unknown,
                LiteImplantCodes.QUIESCING, keyState(context),
            )
        }
        val appContext = context.applicationContext
        if (UltraIdentityRecovery.blocked(appContext)) {
            return Result(false, UltraEnvironmentProbe.State.Unknown, "RECOVERY_SUSPENDED", keyState(appContext))
        }
        UltraEnvironmentProbe.refresh(appContext, force = false)
        if (!UltraEnvironmentProbe.currentSnapshot(appContext).rootAvailable) {
            UltraIdentityRecovery.recover(appContext)
        }
        val observation = UltraEnvironmentProbe.currentSnapshot(appContext)
        if (UltraInstallCredentialRecovery.hasVerifiedInstallCredential(appContext)) {
            val installKey = UltraRootKeyStore.read(appContext)
            val installScope = UltraAuthorization.captureClientScope(appContext, UltraSdkCredentials.client(appContext)) {
                installKey != null && UltraRootKeyStore.read(appContext) == installKey &&
                    !UltraIdentityRecovery.blocked(appContext)
            } ?: return Result(false, observation.state, "SDK_CREDENTIAL_SCOPE_CHANGED", keyState(appContext))
            val initialized = dev.maplesu.manager.runtime.authorization.SuperuserControl
                .initializeForInstallationIfAbsent(appContext, installScope)
            if (!initialized.succeeded) return Result(false, observation.state,
                "AUTHORIZATION_INITIALIZATION_PENDING", keyState(appContext))
            if (!installScope.current() || installKey == null ||
                !UltraKeyPairedStore.markInstallAuthorizationObserved(appContext, installKey)) {
                return Result(false, UltraEnvironmentProbe.State.Unknown, "SDK_CREDENTIAL_SCOPE_CHANGED", keyState(appContext))
            }
        }
        val key = UltraRootKeyStore.read(appContext)
        val rootCurrent = UltraRootKeyStore.captureOwnerMarker(appContext)
        val sessionCurrent = UltraSdkSession.captureOwnerMarker(appContext)
        if (key == null) {
            val owner = observation.managerOwnerIdentity
            if (owner != null && observation.rootAvailable) {
                val bootId = UltraEnvironmentAutoSetup.currentBootId()
                val ownerProbe = UltraRuntimeClient()
                val current = {
                    !Thread.currentThread().isInterrupted && bootId != null &&
                        UltraEnvironmentAutoSetup.currentBootId() == bootId &&
                        ModeRuntime.activation === observation.modeActivation && rootCurrent() && sessionCurrent() &&
                        !UltraIdentityRecovery.blocked(appContext) && UltraRootKeyStore.read(appContext) == null &&
                        UltraEnvironmentProbe.currentSnapshot(appContext).let {
                            it.modeActivation === observation.modeActivation && it.managerOwnerIdentity == owner
                        } && ownerProbe.queryManagerOwnerIdentity().identity == owner
                }
                val scope = UltraAuthorization.captureOwnerScope(appContext, owner, current)
                    ?: return Result(false, UltraEnvironmentProbe.State.Unknown, "SDK_CREDENTIAL_SCOPE_CHANGED", KeyState.Absent)
                return complete(observation, scope.current, alreadyPaired = { true }, persist = {},
                    verifyManagerSu = {
                        val su = UltraSuChannel(timeoutMillis = 700L)
                        UltraSelfWhitelist.verifyExec(current = scope.current,
                            probe = { su.rootUid() == 0 },
                            rootVerified = { UltraEnvironmentProbe.hasCurrentRootProof(appContext) },
                            refresh = { UltraSelfWhitelist.ensureOwner(appContext, owner, scope.current).succeeded })
                    }, maintain = {}, keyState = KeyState.Absent)
            }
            Log.i(TAG, "auto-pair skipped: local rootKey absent")
            return Result(false, UltraEnvironmentProbe.State.NoKey, "ULTRA_KEY_ABSENT", KeyState.Absent)
        }
        if (key.length != KEY_LENGTH) {
            Log.w(TAG, "auto-pair skipped: rootKey length=${key.length} (want $KEY_LENGTH)")
            return Result(false, UltraEnvironmentProbe.State.NoKey, "ULTRA_KEY_FORMAT", KeyState.Malformed)
        }

        val bootId = UltraEnvironmentAutoSetup.currentBootId()
        UltraEnvironmentProbe.refresh(appContext, force = false)
        val verified = UltraEnvironmentProbe.currentSnapshot(appContext)
        val current = { !Thread.currentThread().isInterrupted &&
            bootId != null && UltraEnvironmentAutoSetup.currentBootId() == bootId &&
            ModeRuntime.activation === verified.modeActivation && rootCurrent() && sessionCurrent() &&
            !UltraIdentityRecovery.blocked(appContext) && UltraRootKeyStore.read(appContext) == key }
        return complete(verified,
            current = current,
            alreadyPaired = { UltraKeyPairedStore.matchesVerifiedKey(appContext, key) },
            persist = { UltraKeyPairedStore.markPaired(appContext, key) },
            verifyManagerSu = {
                val client = UltraSdkCredentials.client(appContext, key, bootId)
                val su = UltraSuChannel(timeoutMillis = 700L)
                UltraSelfWhitelist.verifyExec(
                    current = current,
                    probe = { su.rootUid() == 0 },
                    rootVerified = { verified.rootAvailable },
                    refresh = { UltraSelfWhitelist.ensureCurrentAuthority(appContext, client, current).succeeded },
                )
            },
            maintain = {
                if (maintenance) UltraPairingMaintenance.request(appContext, key)
            })
    }

    /** Scoped SDK proof and durable identity precede actual manager SU and maintenance. */
    internal fun complete(
        observation: UltraEnvironmentProbe.Snapshot,
        current: () -> Boolean,
        alreadyPaired: () -> Boolean,
        persist: () -> Unit,
        verifyManagerSu: () -> Boolean,
        maintain: () -> Unit,
        keyState: KeyState = KeyState.Present,
    ): Result {
        val state = observation.state
        if (!observation.rootAvailable) {
            return Result(false, state,
                if (state == UltraEnvironmentProbe.State.Running) "SDK_ROOT_UNVERIFIED" else "ULTRA_ENV_${state.name}",
                keyState)
        }
        if (!current()) return Result(false, UltraEnvironmentProbe.State.Unknown, "ULTRA_KEY_CHANGED", keyState)
        val already = alreadyPaired()
        if (!already) persist()
        if (!current()) return Result(false, UltraEnvironmentProbe.State.Unknown, "ULTRA_KEY_CHANGED", keyState)
        val managerSuVerified = recoveryCandidate { verifyManagerSu() } == true
        if (!current()) return Result(false, UltraEnvironmentProbe.State.Unknown, "ULTRA_KEY_CHANGED", keyState)
        maintain()
        if (!current()) return Result(false, UltraEnvironmentProbe.State.Unknown, "ULTRA_KEY_CHANGED", keyState)
        return Result(managerSuVerified, state,
            if (!managerSuVerified) "MANAGER_SU_UNVERIFIED" else if (already) "ALREADY_PAIRED" else "PAIRED",
            keyState)
    }

    /** Human hint for the settings page; `null` when a valid local key exists. */
    fun keyHint(context: Context): String? = when (keyState(context)) {
        KeyState.Present -> null
        KeyState.Absent -> "未检测到本地密钥，请先安装系统环境"
        KeyState.Malformed -> "本地密钥长度异常（需 $KEY_LENGTH 字符），请重新安装系统环境"
    }
}
