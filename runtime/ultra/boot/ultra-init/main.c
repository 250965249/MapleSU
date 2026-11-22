// SPDX-License-Identifier: GPL-3.0-or-later
#include "handoff.h"

int main(int argc, char **argv, char **envp) {
    (void)argc;
    return maplesu_ultra_first_stage(argv, envp);
}
