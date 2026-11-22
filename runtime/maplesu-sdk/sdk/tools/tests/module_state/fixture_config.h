#pragma once
#include <string>
#include "module_err_def.h"
namespace fixture {
extern std::string key;
extern KModErr root_result, reset_result, install_result;
extern bool fail_chmod, fail_label;
extern unsigned chmod_calls, label_calls;
extern bool label_contract_ok;
}
