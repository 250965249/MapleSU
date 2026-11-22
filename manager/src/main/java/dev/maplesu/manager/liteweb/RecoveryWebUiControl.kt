package dev.maplesu.manager.liteweb

import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.RootExecResult

const val RECOVERY_WEBUI_PAUSE_PATH = "/data/adb/maplesu/recovery/webui.paused"

enum class RecoveryWebUiState { RUNNING, STOPPED, UNKNOWN }

data class RecoveryWebUiStatus(val state: RecoveryWebUiState, val error: String = "")

/** Blocking control of the recovery listener only; call from an IO dispatcher. */
class RecoveryWebUiControl(
    private val execute: (String) -> RootExecResult = { RootExec.execute(it) },
) {
    fun status(): RecoveryWebUiStatus = run(RecoveryWebUiScripts.inspect(), stopping = false)

    fun stop(): RecoveryWebUiStatus = run(RecoveryWebUiScripts.stop(), stopping = true)

    private fun run(script: String, stopping: Boolean): RecoveryWebUiStatus {
        val result = runCatching { execute(script) }.getOrNull()
            ?: return RecoveryWebUiStatus(RecoveryWebUiState.UNKNOWN, "CONTROL_FAILED")
        val rows = result.output.lineSequence().filter { it.startsWith("MAPLESU_WEBUI_CONTROL ") }.toList()
        val match = rows.singleOrNull()?.let { RECEIPT.matchEntire(it) }
            ?: return RecoveryWebUiStatus(RecoveryWebUiState.UNKNOWN, "CONTROL_RECEIPT_INVALID")
        val state = RecoveryWebUiState.valueOf(match.groupValues[1])
        val code = match.groupValues[2]
        if (!result.ok || state == RecoveryWebUiState.UNKNOWN || code != "OK" ||
            (stopping && state != RecoveryWebUiState.STOPPED)) {
            return RecoveryWebUiStatus(RecoveryWebUiState.UNKNOWN, code.takeUnless { it == "OK" } ?: "CONTROL_FAILED")
        }
        return RecoveryWebUiStatus(state)
    }

    private companion object {
        val RECEIPT = Regex("MAPLESU_WEBUI_CONTROL (RUNNING|STOPPED|UNKNOWN) ([A-Z][A-Z0-9_]+)")
    }
}

/** No token is read or emitted. A successful stop requires both PID and socket absence. */
internal object RecoveryWebUiScripts {
    private val common = """
        set -u
        R=/data/adb/maplesu/recovery
        fail() { echo "MAPLESU_WEBUI_CONTROL UNKNOWN ${'$'}1"; exit 1; }
        [ "${'$'}(id -u)" = 0 ] || fail ROOT_REQUIRED
        [ -r "${'$'}R/webui.conf" ] || fail CONFIG_UNREADABLE
        PORT=${'$'}(sed -n 's/^webuiPort=//p;s/^port=//p' "${'$'}R/webui.conf" 2>/dev/null | head -1)
        case "${'$'}PORT" in ''|*[!0-9]*) fail CONFIG_INVALID;; esac
        [ "${'$'}PORT" -gt 0 ] && [ "${'$'}PORT" -lt 65536 ] || fail CONFIG_INVALID
        HEX=${'$'}(printf '%04X' "${'$'}PORT") || fail CONFIG_INVALID
        identity() {
          P=${'$'}1
          [ -d "/proc/${'$'}P" ] || return 1
          [ -r "/proc/${'$'}P/comm" ] || return 2
          read -r COMM < "/proc/${'$'}P/comm" || return 2
          case "${'$'}COMM" in maplesu-liteweb|main|app_process|app_process64) ;; *) return 1;; esac
          [ -r "/proc/${'$'}P/cmdline" ] || return 2
          CMD=${'$'}(tr '\000' ' ' < "/proc/${'$'}P/cmdline" 2>/dev/null) || return 2
          A0=${'$'}{CMD%% *}
          case "${'$'}A0" in
            maplesu-liteweb) ;;
            /system/bin/app_process|/system/bin/app_process64)
              case "${'$'}CMD" in *'--nice-name=maplesu-liteweb '*'dev.maplesu.manager.liteweb.daemon.LiteWebDaemonMain'*) ;;
                *) return 1;; esac;;
            *) return 1;;
          esac
          [ -r "/proc/${'$'}P/status" ] && [ -r "/proc/${'$'}P/environ" ] || return 2
          UID_VALUE=${'$'}(awk '/^Uid:/ {print ${'$'}2}' "/proc/${'$'}P/status" 2>/dev/null) || return 2
          [ "${'$'}UID_VALUE" = 0 ] || return 2
          CP=${'$'}(tr '\000' '\n' < "/proc/${'$'}P/environ" 2>/dev/null | sed -n 's/^CLASSPATH=//p')
          case "${'$'}CP" in
            "${'$'}R/manager.apk"|/data/app/*/dev.maplesu.manager-*/base.apk) return 0;;
            *) return 2;;
          esac
        }
        inspect_state() {
          TARGET=''
          if [ -e "${'$'}R/liteweb.pid" ]; then
            [ -r "${'$'}R/liteweb.pid" ] || fail PROC_UNREADABLE
            PID=${'$'}(cat "${'$'}R/liteweb.pid" 2>/dev/null) || fail PROC_UNREADABLE
            case "${'$'}PID" in ''|*[!0-9]*) fail PID_INVALID;; esac
            if [ -d "/proc/${'$'}PID" ]; then
              identity "${'$'}PID"; RC=${'$'}?
              [ "${'$'}RC" = 0 ] || fail PID_IDENTITY_MISMATCH
            fi
          fi
          for D in /proc/[0-9]*; do
            case "${'$'}{D#/proc/}" in ''|*[!0-9]*) continue;; esac
            [ -d "${'$'}D" ] || continue
            identity "${'$'}{D#/proc/}"; RC=${'$'}?
            if [ "${'$'}RC" = 2 ] && [ -d "${'$'}D" ]; then fail PROC_UNREADABLE; fi
            [ "${'$'}RC" = 0 ] || continue
            [ -z "${'$'}TARGET" ] || fail MULTIPLE_DAEMONS
            TARGET=${'$'}{D#/proc/}
          done
          TCP=${'$'}(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null) || fail SOCKETS_UNREADABLE
          [ -n "${'$'}TCP" ] || fail SOCKETS_UNREADABLE
          LISTEN=${'$'}(printf '%s\n' "${'$'}TCP" | awk -v h="${'$'}HEX" '${'$'}4 == "0A" && substr(${'$'}2,length(${'$'}2)-4) == ":" h {n++} END {print n+0}')
          if [ -n "${'$'}TARGET" ] && [ "${'$'}LISTEN" -gt 0 ]; then STATE=RUNNING
          elif [ -z "${'$'}TARGET" ] && [ "${'$'}LISTEN" = 0 ]; then STATE=STOPPED
          else fail LISTENER_IDENTITY_UNCERTAIN
          fi
        }
    """.trimIndent()

    fun inspect(): String = common + "\ninspect_state\necho \"MAPLESU_WEBUI_CONTROL ${'$'}STATE OK\"\n"

    fun stop(): String = common + "\n" + """
        inspect_state
        umask 077
        [ ! -L "${'$'}R/webui.paused" ] && [ ! -L "${'$'}R/webui.paused.tmp" ] || fail PAUSE_WRITE_FAILED
        printf 'paused\n' > "${'$'}R/webui.paused.tmp" || fail PAUSE_WRITE_FAILED
        chmod 600 "${'$'}R/webui.paused.tmp" || fail PAUSE_WRITE_FAILED
        mv -f "${'$'}R/webui.paused.tmp" "${'$'}R/webui.paused" || fail PAUSE_WRITE_FAILED
        [ -f "${'$'}R/webui.paused" ] || fail PAUSE_WRITE_FAILED
        if [ -n "${'$'}TARGET" ]; then
          identity "${'$'}TARGET" || fail PID_IDENTITY_MISMATCH
          kill -TERM "${'$'}TARGET" 2>/dev/null || fail SIGNAL_FAILED
          N=0
          while [ -d "/proc/${'$'}TARGET" ] && [ "${'$'}N" -lt 20 ]; do
            sleep 0.1
            N=${'$'}((N+1))
          done
          if [ -d "/proc/${'$'}TARGET" ]; then
            identity "${'$'}TARGET" || fail PID_IDENTITY_MISMATCH
            kill -KILL "${'$'}TARGET" 2>/dev/null || fail SIGNAL_FAILED
            N=0
            while [ -d "/proc/${'$'}TARGET" ] && [ "${'$'}N" -lt 20 ]; do sleep 0.1; N=${'$'}((N+1)); done
          fi
          [ ! -d "/proc/${'$'}TARGET" ] || fail STOP_VERIFY_FAILED
        fi
        inspect_state
        [ "${'$'}STATE" = STOPPED ] || fail STOP_VERIFY_FAILED
        rm -f "${'$'}R/liteweb.pid" || fail PID_CLEANUP_FAILED
        echo 'MAPLESU_WEBUI_CONTROL STOPPED OK'
    """.trimIndent() + "\n"

    /** Explicit manager start may resume; host/boot launches never clear this marker. */
    fun resume(): String = """
        [ ! -L '$RECOVERY_WEBUI_PAUSE_PATH' ] || { echo PAUSE_CLEAR_FAILED; exit 1; }
        rm -f '$RECOVERY_WEBUI_PAUSE_PATH' || { echo PAUSE_CLEAR_FAILED; exit 1; }
        [ ! -e '$RECOVERY_WEBUI_PAUSE_PATH' ] || { echo PAUSE_CLEAR_FAILED; exit 1; }
    """.trimIndent()
}
