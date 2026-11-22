#pragma once
#include <array>
#include <string>

namespace maplesu::ghostlock_adapter {
struct Configuration {
    std::string home;
    std::string consumer;
    std::string target;
    std::string attempt;
    std::string helper;
    std::array<std::string, 5> arguments;
    // Set by initialize(): 0/1 is the observed entry value, -1 means the entry
    // exists but this domain cannot read it, -2 means it provably does not exist.
    // restore.sh consumes the difference instead of collapsing -1 and -2.
    int enforcing = -1;
    int checkreqprot = -1;
};
extern Configuration configuration;
// Only ordinary-App input validation and baseline reads; no provider stage here.
bool initialize(int argc, char** argv);
}
