package dev.maplesu.manager.modules

import android.content.Context
import java.io.File

/**
 * Publishes the bundled module tools that MapleSU ships itself.
 *
 * Contract is taken from the pinned KSU userspace, not invented:
 *
 * - `defs.rs:15` - tools live in `BINARY_DIR` = `<working>/bin/`.
 * - `assets.rs:20-24` - each asset is written by `ensure_binary`: unlink, write, chmod 0755.
 * - `assets.rs:26-28` - `resetprop` is then republished as a **symlink** to the host
 *   binary (`remove_file` + `symlink` every time), because there is one host, not
 *   one executable per tool name.
 * - `cli.rs:521-524` - the host dispatches on `arg0.ends_with("resetprop")`.
 *
 * Deployment is a plain file operation. It performs **no mount and no SELinux
 * policy work**, so publishing tools never changes global policy state and never
 * adds a mountpoint observable in `/proc/self/mountinfo`.
 *
 * Location: `/data/adb/maplesu` is the existing Root-owned (0:0, 0700) private
 * directory MapleSU already uses for authorization storage. Tools placed under it
 * share KSU's own visibility class (`/data/adb/ksu`): non-Root callers cannot
 * list it or stat a known path inside it. Nothing is created under `/dev`,
 * `/data/local/tmp`, or any other world-traversable location.
 */
object ModuleToolDeployment {
    /** Mirrors KSU `WORKING_DIR` shape under MapleSU's own namespace. */
    const val WORKING_DIR = "/data/adb/maplesu"
    /** Mirrors KSU `BINARY_DIR`; this is what the module `PATH` receives. */
    const val BINARY_DIR = "$WORKING_DIR/bin"
    /** Existing platform type; assigning it declares no new SELinux type. */
    private const val TOOL_CONTEXT = "u:object_r:system_file:s0"
    /** Host executable inside the APK; module tool names are symlinks to it. */
    private const val HOST_ENTRY = "libmaplesu_tools.so"
    private const val HOST_NAME = "maplesu-tools"
    /**
     * Independent executable, so it is copied as a real file rather than linked to
     * the multicall host. `module-policy` is the existing standalone loader with a
     * fixed libsepol build; deployment here only publishes it, it does not load any
     * rule. Nothing below writes to `/sys/fs/selinux/load`.
     */
    private const val POLICY_ENTRY = "libmaplesu_policy.so"
    private const val POLICY_NAME = "maplesu-policy"
    /**
     * Fixed upstream BusyBox, pinned by SHA-256 in `third_party/busybox/PROVENANCE.md`.
     * It is published as its own real file: module scripts call `busybox ash`/`busybox sh`
     * directly, and it is not a multicall applet of the MapleSU host.
     */
    private const val BUSYBOX_ENTRY = "libmaplesu_busybox.so"
    private const val BUSYBOX_NAME = "busybox"
    /** Tool name -> symlink to the host. Mirrors `assets.rs:26-28`. */
    private val links = listOf("resetprop")

    fun names(): Set<String> = links.toSet()

    fun hostSource(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, HOST_ENTRY)

    fun policySource(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, POLICY_ENTRY)

    fun busyboxSource(context: Context): File =
        File(context.applicationInfo.nativeLibraryDir, BUSYBOX_ENTRY)

    /** Absolute path of a published tool, for callers that must name it. */
    fun toolPath(name: String): String = "$BINARY_DIR/$name"

    /** Absolute path of the published policy loader. */
    fun policyPath(): String = "$BINARY_DIR/$POLICY_NAME"

    /** Absolute path of the published BusyBox, mirroring KSU `BUSYBOX_PATH`. */
    fun busyboxPath(): String = "$BINARY_DIR/$BUSYBOX_NAME"

    internal fun script(context: Context): String {
        val policyShim = context.assets.open("maplesu/modules/sepolicy.sh").bufferedReader().use { it.readText() }
        val uiPrintShim = context.assets.open("maplesu/modules/ui-print.sh").bufferedReader().use { it.readText() }
        val lifecycle = mapOf("module-run.sh" to "run.sh", "module-boot.sh" to "boot.sh",
            "module-mount.sh" to "mount.sh").mapValues { (_, asset) ->
            context.assets.open("maplesu/modules/$asset").bufferedReader().use { it.readText() }
        }
        return script(context.applicationInfo.nativeLibraryDir, policyShim, uiPrintShim, lifecycle)
    }

    internal fun script(nativeDirectory: String, policyShim: String, uiPrintShim: String,
                        lifecycle: Map<String, String> = emptyMap()): String {
        val linkLines = links.joinToString("\n") { name -> "link_tool " + quote(name) }
        val lifecycleLines = lifecycle.entries.joinToString("\n") { (name, source) ->
            require(name in setOf("module-run.sh", "module-boot.sh", "module-mount.sh"))
            """
            tool_stage=$name
            temporary="${'$'}(/system/bin/mktemp ${quote(BINARY_DIR)}/.lifecycle.XXXXXX)"
            /system/bin/cat > "${'$'}temporary" <<'MAPLESU_LIFECYCLE_ASSET'
$source
MAPLESU_LIFECYCLE_ASSET
            /system/bin/chown 0:0 "${'$'}temporary"
            /system/bin/chmod 0755 "${'$'}temporary"
            /system/bin/chcon ${TOOL_CONTEXT} "${'$'}temporary"
            /system/bin/mv -f "${'$'}temporary" ${quote("$BINARY_DIR/$name")}
            /system/bin/printf 'MAPLESU_TOOL_LIFECYCLE:%s %s\n' ${quote(name)} "${'$'}(/system/bin/sha256sum ${quote("$BINARY_DIR/$name")} | /system/bin/cut -d ' ' -f 1)"
            """.trimIndent()
        }
        return """
            (
            set -eu
            umask 077
            tool_stage=root
            trap 'tool_exit=${'$'}?; if [ "${'$'}tool_exit" -ne 0 ]; then /system/bin/printf "MAPLESU_TOOL_FAILURE:%s:%s\n" "${'$'}tool_stage" "${'$'}tool_exit"; fi; exit "${'$'}tool_exit"' 0
            test "${'$'}(/system/bin/id -u)" = 0
            # Refuse to operate through a symlinked parent: a hostile or stale link
            # here would redirect the whole tool tree.
            tool_stage=directories
            test ! -L /data/adb
            test ! -L ${quote(WORKING_DIR)}
            test ! -L ${quote(BINARY_DIR)}
            # Both native publication and boot loading require a private root-owned parent.
            # Also correct a parent created by an earlier permissive-umask install.
            /system/bin/mkdir -p -m 0700 /data/adb
            test "${'$'}(/system/bin/stat -c %u /data/adb)" = 0
            /system/bin/chmod 0700 /data/adb
            /system/bin/mkdir -p ${quote(BINARY_DIR)}
            /system/bin/chown 0:0 ${quote(WORKING_DIR)} ${quote(BINARY_DIR)}
            # Root-only parent, like KSU's working directory: 0755 would let a non-Root
            # caller reach the tool binaries by absolute path even though /data/adb itself
            # is 0700. BINARY_DIR stays 0755 because the tools must be executable.
            /system/bin/chmod 0700 ${quote(WORKING_DIR)}
            /system/bin/chmod 0755 ${quote(BINARY_DIR)}
            host=${quote(BINARY_DIR)}/$HOST_NAME
            hostsource=${quote(File(nativeDirectory, HOST_ENTRY).absolutePath)}
            tool_stage=host-source
            test -f "${'$'}hostsource"
            # ensure_binary order: unlink, write, chmod 0755.
            expected="${'$'}(/system/bin/sha256sum "${'$'}hostsource" | /system/bin/cut -d ' ' -f 1)"
            current=none
            if [ -f "${'$'}host" ] && [ ! -L "${'$'}host" ]; then
                current="${'$'}(/system/bin/sha256sum "${'$'}host" | /system/bin/cut -d ' ' -f 1)"
            fi
            hoststate=unchanged
            tool_stage=host-publish
            if [ "${'$'}current" != "${'$'}expected" ]; then
                /system/bin/rm -f "${'$'}host"
                /system/bin/cat "${'$'}hostsource" > "${'$'}host"
                hoststate=updated
            fi
            # A previous interrupted publication may have written all bytes before
            # setting ownership, mode or context. Matching hashes do not prove these.
            /system/bin/chown 0:0 "${'$'}host"
            /system/bin/chmod 0755 "${'$'}host"
            /system/bin/chcon ${TOOL_CONTEXT} "${'$'}host"
            tool_stage=host-verify
            actual="${'$'}(/system/bin/sha256sum "${'$'}host" | /system/bin/cut -d ' ' -f 1)"
            test "${'$'}actual" = "${'$'}expected"
            test -x "${'$'}host"
            /system/bin/printf 'MAPLESU_TOOL_HOST:%s %s\n' "${'$'}hoststate" "${'$'}actual"
            # Independent executables are published as real files with the same
            # ensure_binary order, never as links to the multicall host.
            publish_binary() {
                name="${'$'}1"; entry="${'$'}2"; tag="${'$'}3"
                destination=${quote(BINARY_DIR)}/"${'$'}name"
                source=${quote(nativeDirectory)}/"${'$'}entry"
                test -f "${'$'}source"
                expected="${'$'}(/system/bin/sha256sum "${'$'}source" | /system/bin/cut -d ' ' -f 1)"
                current=none
                if [ -f "${'$'}destination" ] && [ ! -L "${'$'}destination" ]; then
                    current="${'$'}(/system/bin/sha256sum "${'$'}destination" | /system/bin/cut -d ' ' -f 1)"
                fi
                state=unchanged
                if [ "${'$'}current" != "${'$'}expected" ]; then
                    /system/bin/rm -f "${'$'}destination"
                    /system/bin/cat "${'$'}source" > "${'$'}destination"
                    state=updated
                fi
                /system/bin/chown 0:0 "${'$'}destination"
                /system/bin/chmod 0755 "${'$'}destination"
                /system/bin/chcon ${TOOL_CONTEXT} "${'$'}destination"
                actual="${'$'}(/system/bin/sha256sum "${'$'}destination" | /system/bin/cut -d ' ' -f 1)"
                test "${'$'}actual" = "${'$'}expected"
                test -x "${'$'}destination"
                /system/bin/printf '%s:%s %s\n' "${'$'}tag" "${'$'}state" "${'$'}actual"
            }
            tool_stage=policy
            publish_binary $POLICY_NAME $POLICY_ENTRY MAPLESU_TOOL_POLICY
            tool_stage=busybox
            publish_binary $BUSYBOX_NAME $BUSYBOX_ENTRY MAPLESU_TOOL_BUSYBOX
            # Shell functions do not survive exec. Publish ui_print as a command so
            # lifecycle, metamodule and nested module shells all receive it.
            tool_stage=ui-print
            ui_print=${quote(BINARY_DIR)}/ui_print
            temporary="${'$'}(/system/bin/mktemp ${quote(BINARY_DIR)}/.ui_print.XXXXXX)"
            /system/bin/cat > "${'$'}temporary" <<'MAPLESU_UI_PRINT_SHIM'
$uiPrintShim
MAPLESU_UI_PRINT_SHIM
            /system/bin/chown 0:0 "${'$'}temporary"
            /system/bin/chmod 0755 "${'$'}temporary"
            /system/bin/chcon ${TOOL_CONTEXT} "${'$'}temporary"
            /system/bin/mv -f "${'$'}temporary" "${'$'}ui_print"
            test -x "${'$'}ui_print"
            $lifecycleLines
            # KSU-native modules expect the manager working directory to exist and to be
            # writable by Root (module.rs/defs.rs put BINARY_DIR under it). Create only
            # the directories, never touch an existing file, so nothing another manager
            # put there is replaced.
            tool_stage=ksu-dirs
            for d in /data/adb/ksu /data/adb/ksu/bin; do
                test -L "${'$'}d" && { /system/bin/printf 'MAPLESU_KSU_DIR_CONFLICT:%s\n' "${'$'}d" >&2; exit 1; }
                /system/bin/mkdir -p "${'$'}d"
                /system/bin/chown 0:0 "${'$'}d"
                /system/bin/chmod 0755 "${'$'}d"
            done
            /system/bin/printf 'MAPLESU_KSU_DIR:ready\n'
            # T2: the public hook directories. They live under the same 0700 Root-only
            # working directory as the tools, so creating them adds no ordinary-app
            # observable surface; they exist so an executable dropped into one is run
            # by the matching boot stage (KSU `post-fs-data.d`/`service.d`/
            # `boot-completed.d`, module.rs:385-405).
            tool_stage=hooks
            for hook in post-fs-data.d post-mount.d service.d boot-completed.d; do
                hookdir=${quote(WORKING_DIR)}/"${'$'}hook"
                test -L "${'$'}hookdir" && { /system/bin/printf 'MAPLESU_HOOK_DIR_CONFLICT:%s\n' "${'$'}hookdir" >&2; exit 1; }
                /system/bin/mkdir -p "${'$'}hookdir"
                /system/bin/chown 0:0 "${'$'}hookdir"
                /system/bin/chmod 0755 "${'$'}hookdir"
            done
            /system/bin/printf 'MAPLESU_HOOK_DIRS:ready\n'
            # T6: the kernel-side TEESimulator needs MapleSU's kernel_module_kit
            # (access_process_vm + execmem). This build integrates no kit payload and no
            # loader, so the capability is recorded as a fact. The bundled module's
            # service script checks this file and refuses to start a daemon that could
            # not inject (which would otherwise stay resident doing nothing). When a kit
            # is integrated this file changes and the script proceeds.
            tool_stage=kit
            kit=${quote(WORKING_DIR)}/kit
            /system/bin/mkdir -p "${'$'}kit"
            /system/bin/chown 0:0 "${'$'}kit"
            /system/bin/chmod 0700 "${'$'}kit"
            /system/bin/cat > "${'$'}kit/status" <<'MAPLESU_KIT_STATUS'
tee_kit=unavailable
tee_kit_reason=MapleSU kernel_module_kit is not integrated in this build (no kernel payload or loader)
MAPLESU_KIT_STATUS
            /system/bin/chown 0:0 "${'$'}kit/status"
            /system/bin/chmod 0644 "${'$'}kit/status"
            /system/bin/printf 'MAPLESU_KIT_STATUS:written\n'
            # Publish the on-demand module entry; deployment itself loads no rules.
            tool_stage=sepolicy
            shim=${quote(BINARY_DIR)}/sepolicy
            /system/bin/cat > "${'$'}shim" <<'MAPLESU_SEPOLICY_SHIM'
$policyShim
MAPLESU_SEPOLICY_SHIM
            /system/bin/chown 0:0 "${'$'}shim"
            /system/bin/chmod 0755 "${'$'}shim"
            /system/bin/chcon ${TOOL_CONTEXT} "${'$'}shim"
            test -x "${'$'}shim"
            shimsha="${'$'}(/system/bin/sha256sum "${'$'}shim" | /system/bin/cut -d ' ' -f 1)"
            /system/bin/printf 'MAPLESU_TOOL_SEPOLICY:updated %s\n' "${'$'}shimsha"
            # Modules using magiskpolicy --live share the same on-demand loader.
            /system/bin/rm -f ${quote(BINARY_DIR)}/magiskpolicy
            /system/bin/ln -s "${'$'}shim" ${quote(BINARY_DIR)}/magiskpolicy
            # KernelSU-compatible module-requested policy commands.
            tool_stage=ksud
            ksud=${quote(BINARY_DIR)}/ksud
            /system/bin/cat > "${'$'}ksud" <<'MAPLESU_KSUD_SHIM'
#!/system/bin/sh
case "${'$'}1" in
  sepolicy)
    shift
    exec /data/adb/maplesu/bin/sepolicy "${'$'}@"
    ;;
  --version|-v|version)
    echo "ksud (MapleSU compatibility entry)"
    exit 0
    ;;
  "")
    echo "usage: ksud <sepolicy check|apply|patch|--version>" >&2
    exit 2
    ;;
  *)
    echo "ksud: subcommand ${'$'}1 is not supported by this entry" >&2
    exit 2
    ;;
esac
MAPLESU_KSUD_SHIM
            /system/bin/chown 0:0 "${'$'}ksud"
            /system/bin/chmod 0755 "${'$'}ksud"
            /system/bin/chcon ${TOOL_CONTEXT} "${'$'}ksud"
            test -x "${'$'}ksud"
            /system/bin/printf 'MAPLESU_TOOL_KSUD:updated %s\n' "${'$'}(/system/bin/sha256sum "${'$'}ksud" | /system/bin/cut -d ' ' -f 1)"
            # A previous build published `magisk` directly in BINARY_DIR. Its presence
            # makes the Manager's Magisk probe succeed, which the module page reports as
            # "conflict with Magisk: all modules unavailable". The shim now lives in
            # compat/ only; remove the stale entry so `command -v magisk` cannot find it.
            tool_stage=compat
            stale_magisk=${quote(BINARY_DIR)}/magisk
            if [ -e "${'$'}stale_magisk" ] || [ -L "${'$'}stale_magisk" ]; then
                /system/bin/rm -f "${'$'}stale_magisk"
                /system/bin/printf 'MAPLESU_STALE_MAGISK_REMOVED:1\n'
            else
                /system/bin/printf 'MAPLESU_STALE_MAGISK_REMOVED:0\n'
            fi
            # `magisk` entry, kept OUT of BINARY_DIR on purpose. LSPosed's customize.sh
            # calls the `magisk` command directly, but KSU-native installers treat its mere
            # presence as "another root is installed" and abort - measured: Zygisk Next
            # aborts with "Multiple root implementation is NOT supported!" because
            # `which magisk` succeeded. KSU itself ships no magisk binary. So the shim is
            # published under BINARY_DIR/compat and that directory is added to PATH only
            # for the modules whose installer actually invokes `magisk`.
            compat=${quote(BINARY_DIR)}/compat
            /system/bin/mkdir -p "${'$'}compat"
            /system/bin/chown 0:0 "${'$'}compat"
            /system/bin/chmod 0755 "${'$'}compat"
            magisk=${quote(BINARY_DIR)}/compat/magisk
            /system/bin/cat > "${'$'}magisk" <<'MAPLESU_MAGISK_SHIM'
#!/system/bin/sh
case "${'$'}1" in
  --path)
    echo /data/adb/maplesu
    exit 0
    ;;
  --version|-v|version)
    echo "27.0"
    exit 0
    ;;
  --daemon)
    echo "magisk: daemon mode is not provided" >&2
    exit 2
    ;;
  "")
    echo "usage: magisk <--path|--version>" >&2
    exit 2
    ;;
  *)
    echo "magisk: subcommand ${'$'}1 is not supported by this entry" >&2
    exit 2
    ;;
esac
MAPLESU_MAGISK_SHIM
            /system/bin/chown 0:0 "${'$'}magisk"
            /system/bin/chmod 0755 "${'$'}magisk"
            /system/bin/chcon ${TOOL_CONTEXT} "${'$'}magisk"
            test -x "${'$'}magisk"
            /system/bin/printf 'MAPLESU_TOOL_MAGISK:updated %s\n' "${'$'}(/system/bin/sha256sum "${'$'}magisk" | /system/bin/cut -d ' ' -f 1)"
            link_tool() {
                # Keep the directory quoted at assignment, not inside a double-quoted
                # expansion: quote() already returns a single-quoted literal, so
                # embedding it in double quotes would keep the quote characters as
                # real path bytes and create a link named with a leading apostrophe.
                name="${'$'}1"; target=${quote(BINARY_DIR)}/"${'$'}name"
                # KSU republishes the link unconditionally: remove then symlink.
                /system/bin/rm -f "${'$'}target"
                /system/bin/ln -s "${'$'}host" "${'$'}target"
                test -L "${'$'}target"
                test "${'$'}(/system/bin/readlink "${'$'}target")" = "${'$'}host"
                # The tool must actually run through the link and identify itself.
                version="${'$'}("${'$'}target" --version 2>/dev/null | /system/bin/head -1)"
                case "${'$'}version" in
                    *resetprop*) ;;
                    *) /system/bin/printf 'MAPLESU_TOOL_LINK:%s BAD_VERSION:%s\n' "${'$'}name" "${'$'}version" >&2; exit 1 ;;
                esac
                /system/bin/printf 'MAPLESU_TOOL_LINK:%s %s\n' "${'$'}name" "${'$'}version"
            }
            tool_stage=link-resetprop
            $linkLines
            )
        """.trimIndent()
    }

    data class Published(
        val hostSha256: String,
        val hostUpdated: Boolean,
        val tools: Map<String, String>,
        val policySha256: String,
        val policyUpdated: Boolean,
        val busyboxSha256: String,
        val busyboxUpdated: Boolean,
    )

    fun parse(output: List<String>): Published {
        val hostLine = output.firstOrNull { it.startsWith("MAPLESU_TOOL_HOST:") }
            ?: error("MODULE_TOOL_HOST_NOT_REPORTED")
        val hostParts = hostLine.removePrefix("MAPLESU_TOOL_HOST:").trim().split(' ')
        require(hostParts.size == 2) { "MODULE_TOOL_HOST_RECEIPT_INVALID:$hostLine" }
        val policyParts = receipt(output, "MAPLESU_TOOL_POLICY")
        val busyboxParts = receipt(output, "MAPLESU_TOOL_BUSYBOX")
        val tools = LinkedHashMap<String, String>()
        output.filter { it.startsWith("MAPLESU_TOOL_LINK:") }.forEach { line ->
            val parts = line.removePrefix("MAPLESU_TOOL_LINK:").trim().split(' ', limit = 2)
            require(parts.size == 2) { "MODULE_TOOL_LINK_RECEIPT_INVALID:$line" }
            tools[parts[0]] = parts[1]
        }
        val missing = links.toSet() - tools.keys
        require(missing.isEmpty()) { "MODULE_TOOL_LINK_NOT_PUBLISHED:" + missing.joinToString() }
        return Published(hostParts[1], hostParts[0] == "updated", tools,
            policyParts[1], policyParts[0] == "updated",
            busyboxParts[1], busyboxParts[0] == "updated")
    }

    private fun receipt(output: List<String>, tag: String): List<String> {
        val line = output.firstOrNull { it.startsWith("$tag:") } ?: error("${tag}_NOT_REPORTED")
        val parts = line.removePrefix("$tag:").trim().split(' ')
        require(parts.size == 2) { "${tag}_RECEIPT_INVALID:$line" }
        return parts
    }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
