
//
#pragma once

#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <utility>

#include "module_err_def.h"
#include "../src/maplesu_core/fixed_transfer_io.h"

#include "../src/maplesu/compat/fork_legacy_abi.h"

// 单字符运行标志文件（.safe_flag 等）。
//   '1' -> 1, '2' -> 2, '3' -> 3, 其他/打不开 -> 0
// 传给 basic_ifstream 构造函数）。
class RunFlagFile {
public:
    RunFlagFile() = default;
    explicit RunFlagFile(std::string path) : path_(std::move(path)) {}

    int read() {
        std::ifstream flag_file(path_, std::ios::in);
        if (flag_file.rdbuf() == nullptr) {
            return 0;
        }
        char flag_char = 0;
        flag_file >> flag_char;
        switch (flag_char) {
            case '1':
                return 1;
            case '2':
                return 2;
            case '3':
                return 3;
            default:
                return 0;
        }
    }

private:
    std::string path_;
};
