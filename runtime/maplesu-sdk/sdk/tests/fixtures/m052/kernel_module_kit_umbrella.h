#pragma once
// Host fixture substitutes the unused kernel/AsmJit boundary only. Installer
// bodies, payloads, public errors and the executable publisher remain real.
#include "module_err_def.h"
#include "maplesu_sdk/maplesu_installer.h"
namespace maplesu::sdk { struct module_record; }
constexpr unsigned FOLDER_HEAD_ROOT_KEY_LEN = 16;
