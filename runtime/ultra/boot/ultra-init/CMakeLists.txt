cmake_minimum_required(VERSION 3.22)
project(maplesu_ultra_first_stage LANGUAGES C)

# Explicit target only; ramdisk packaging requires a separately qualified bridge.
if(ANDROID)
    if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
        message(FATAL_ERROR "The Ultra first-stage candidate requires Android ARM64")
    endif()
    add_executable(maplesu-ultra-init EXCLUDE_FROM_ALL main.c handoff.c)
    target_compile_features(maplesu-ultra-init PRIVATE c_std_11)
    target_compile_options(maplesu-ultra-init PRIVATE -Wall -Wextra -Werror)
    target_link_options(maplesu-ultra-init PRIVATE -static -Wl,--no-undefined -Wl,-z,max-page-size=65536)
endif()

option(MAPLESU_ULTRA_INIT_HOST_TESTS "Build the isolated Linux host handoff seam" OFF)
if(MAPLESU_ULTRA_INIT_HOST_TESTS)
    if(ANDROID OR NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "The handoff seam uses a Linux host linker")
    endif()
    add_executable(maplesu-ultra-init-handoff-test EXCLUDE_FROM_ALL tests/handoff_test.c handoff.c)
    target_compile_features(maplesu-ultra-init-handoff-test PRIVATE c_std_11)
    target_compile_options(maplesu-ultra-init-handoff-test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    target_include_directories(maplesu-ultra-init-handoff-test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_options(maplesu-ultra-init-handoff-test PRIVATE
        -Wl,--wrap=getpid -Wl,--wrap=rename -Wl,--wrap=open -Wl,--wrap=read -Wl,--wrap=unlink
        -Wl,--wrap=syscall -Wl,--wrap=close -Wl,--wrap=execve -Wl,--wrap=write)
endif()
