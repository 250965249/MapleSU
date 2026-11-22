#include "module_err_def.h"
#include <cassert>

static_assert(to_num(KModErr::ERR_MAPLESU_ENV_NOT_INSTALL) == -19916);
static_assert(to_num(KModErr::ERR_SET_FILE_SELINUX) == -19915);
static_assert(to_num(KModErr::ERR_PID_NOT_FOUND) == -19904);

int main() {
    assert(to_string(KModErr::ERR_MAPLESU_ENV_NOT_INSTALL) == "ERR_MAPLESU_ENV_UNPREPARED");
    assert(to_string(KModErr::OK) == "OK");
    assert(to_string(KModErr::ERR_MODULE_PARAM) == "ERR_MODULE_PARAM");
    assert(to_string(static_cast<KModErr>(-30000)) == "Unknown(-30000)");
}
