#include "maplesu_sdk/module_callback.h"
#include <csignal>
#include <string>
#include <unistd.h>

namespace maplesu::sdk::features::callback {
KModErr invoke_module_on_uninstall(const std::string& id) {
    if (id == "stall") for (;;) pause();
    if (id == "crash") raise(SIGKILL);
    if (id == "error") return KModErr::ERR_MODULE_PARAM;
    if (id == "descendant") {
        if (fork() == 0) for (;;) pause();
        for (;;) pause();
    }
    return KModErr::OK;
}
}
