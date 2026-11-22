#pragma once
#include <string>

namespace boot_fixture {
void reset(const char* failure = "");
void event(const char* name);
bool root_held();
bool fail_lock_close();
std::string events();
}
