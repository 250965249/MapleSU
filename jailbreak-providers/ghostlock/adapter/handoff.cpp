#include "handoff.hpp"
#include "restore_script.hpp"
#include "attack/ops.hpp"
#include "session/runtime_config.h"
#include "support/fatal_error.hpp"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <string>
#include <unistd.h>

namespace {
// App EACCES can hide an absent optional node. Resolve only an unknown baseline
// from the rooted shell, before the subshell, so restoration and its record agree.
constexpr char kCheckreqprotBaselineProbe[] = R"sh(
if [ "$BASELINE_CHECKREQPROT" = -1 ] &&
   [ -d /sys/fs/selinux ] && [ -r /sys/fs/selinux ] && [ -x /sys/fs/selinux ] &&
   [ ! -e /sys/fs/selinux/checkreqprot ]; then
  BASELINE_CHECKREQPROT=-2
fi
)sh";

std::string quote(const std::string& value) {
    std::string result = "'";
    for (const char ch : value) result += ch == '\'' ? "'\\''" : std::string(1, ch);
    return result + "'";
}
}

void ghostlock::attack::write_root_script() {
    const auto& config = maplesu::ghostlock_adapter::configuration;
    const std::string path = config::runtime_config_snapshot().root_script_path;
    if (path != config.home + "/.ghostlock_root.sh") throw FatalError{};
    /*
     * S09/S10: the restore body runs in a subshell so its `exit N` becomes a
     * status instead of ending the attempt before the consumer exists. The
     * lease consumer receives the status plus the observed booleans. Ultra uses
     * the shared hook helper's receipt and restore evidence, as DirtyFrag does;
     * it has no raw lease consumer to execute after enforcement is restored.
     */
    // Both restored booleans must be observed (or checkreqprot proven absent).
    // An unreadable value uses the documented baseline and is labelled as such.
    const char* source = config.enforcing >= 0 && config.checkreqprot != -1 ? "o" : "d";
    std::string handover;
    if (!config.target.empty()) {
        handover = quote(config.helper) + " --handover --target " + quote(config.target) +
            " --attempt " + quote(config.attempt) + " --boot " + quote(config.arguments[3]);
    }
    const std::string pre = handover.empty() ? "" :
        "maplesu_handover_pre() { " + handover +
        " --phase pre --entry-enforcing \"$TARGET_ENFORCING\"" +
        (config.target == "normal" ? " --ksud '/data/user/0/dev.maplesu.manager/ksud'" : "") +
        // Ultra's successful helper already verified the final restore and
        // published its receipt. End this subshell before restore.sh reopens
        // selinuxfs after enforcing. An early failure still uses its restore tail.
        (config.target == "ultra" ?
            "; MAPLESU_HANDOVER_RC=$?; if [ \"$MAPLESU_HANDOVER_RC\" = 0 ]; then "
            "echo 'maplesu-ghostlock: backend handover exit=0; restore verified by shared helper' >&2; "
            "exit 0; fi; "
            // Keep the backend error after the restore tail, without hiding a
            // later restoration error. Normal still reports the restore frame.
            "trap 'MAPLESU_RESTORE_RC=$?; trap - EXIT; "
            "[ \"$MAPLESU_RESTORE_RC\" = 0 ] && exit \"$MAPLESU_HANDOVER_RC\"; "
            "exit \"$MAPLESU_RESTORE_RC\"' EXIT; return \"$MAPLESU_HANDOVER_RC\"; }\n" :
            "; MAPLESU_HANDOVER_RC=$?; "
            "if [ \"$MAPLESU_HANDOVER_RC\" = 0 ]; then TARGET_ENFORCING=1; fi; "
            "return \"$MAPLESU_HANDOVER_RC\"; }\n");
    std::string completion;
    if (config.target == "ultra") {
        // The App creates this file. Keep its descriptor across enforcement,
        // and use shell builtins for the final write, as the 93260 source does.
        completion = "exec 7>" + quote(config.home + "/root-worker-result.json") + " || exit 68\n" +
            "maplesu_worker_finish() {\n"
            "  MAPLESU_WORKER_RC=$?\n"
            "  trap - EXIT HUP INT TERM\n"
            "  echo '{\"schema\":\"maplesu.ghostlock.worker.v1\",\"provider\":\"ghostlock\","
            "\"bootId\":\"" + config.arguments[3] + "\",\"attempt\":\"" + config.attempt +
            "\",\"exitCode\":'\"$MAPLESU_WORKER_RC\"'}' >&7\n"
            "  exec 7>&-\n"
            "  exit \"$MAPLESU_WORKER_RC\"\n"
            "}\ntrap maplesu_worker_finish EXIT\ntrap 'exit 130' HUP INT TERM\n";
    }
    std::string script = "#!/system/bin/sh\nexec >>" + quote(config.home + "/root-worker.log") +
        " 2>&1\n" + completion + "HOME_DIR=" + quote(config.home) +
        "\nSELINUX_ATTEMPT_ID=" + quote(config.attempt) +
        "\nSELINUX_BOOT_ID=" + quote(config.arguments[3]) +
        "\nBASELINE_ENFORCING=" + std::to_string(config.enforcing) +
        "\nBASELINE_CHECKREQPROT=" + std::to_string(config.checkreqprot) + "\n" +
        kCheckreqprotBaselineProbe + "(\n" +
        pre + maplesu_ghostlock_restore_script;
    if (config.target == "ultra") {
        script += "\n)\nexit $?\n";
    } else {
        script += std::string("\n)\nRESTORE_RC=$?\n") +
        "ENF=$(cat /sys/fs/selinux/enforce 2>/dev/null)\n" +
        "case \"$ENF\" in 0|1) ;; *) ENF=-1 ;; esac\n" +
        "CRP=$(cat /sys/fs/selinux/checkreqprot 2>/dev/null)\n" +
        "case \"$CRP\" in 0|1) ;; *) CRP=-1; " +
        "if [ \"$BASELINE_CHECKREQPROT\" = -2 ] && [ ! -e /sys/fs/selinux/checkreqprot ]; " +
        "then CRP=-2; fi ;; esac\n" +
        "echo \"maplesu-ghostlock: consumer dispatch restore=$RESTORE_RC enforce=$ENF checkreqprot=$CRP\" >&2\n" +
        "exec " + quote(config.consumer);
        for (const auto& argument : config.arguments) script += " " + quote(argument);
        script += std::string(" r") + "$RESTORE_RC:$ENF:$CRP:" + source + "\n";
    }
    // Per-attempt home; never truncate a pre-existing entry or follow a symlink.
    const int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0700);
    if (fd < 0) throw FatalError{};
    size_t used = 0;
    while (used < script.size()) {
        const ssize_t count = write(fd, script.data() + used, script.size() - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { close(fd); unlink(path.c_str()); throw FatalError{}; }
        used += static_cast<size_t>(count);
    }
    if (close(fd)) { unlink(path.c_str()); throw FatalError{}; }
    std::fprintf(stdout, "maplesu-ghostlock: downstream script prepared\n");
}
