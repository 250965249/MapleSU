cmake_minimum_required(VERSION 3.22)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(maplesu_ghostlock_review LANGUAGES CXX)
endif()

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "Ghostlock upstream review target requires Android arm64-v8a")
endif()

include(native-sources.cmake)
# This contains the original W1/W2/W3 and KSU consumer, not a MapleSU handoff.
# Explicit offline build only: never include this target in product packaging.
add_executable(maplesu-ghostlock-upstream-review EXCLUDE_FROM_ALL
    ${MAPLESU_GHOSTLOCK_REVIEW_SOURCES})
set_target_properties(maplesu-ghostlock-upstream-review PROPERTIES
    OUTPUT_NAME "libmaplesu_ghostlock.so"
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO
    POSITION_INDEPENDENT_CODE ON)
target_include_directories(maplesu-ghostlock-upstream-review PRIVATE upstream/src/core)
target_compile_definitions(maplesu-ghostlock-upstream-review PRIVATE
    TARGET_CONFIG_H="kernel/target.h")
target_compile_options(maplesu-ghostlock-upstream-review PRIVATE
    -O2 -flto -fno-rtti -Wall -Wextra -Wconversion -Wsign-conversion
    -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function)
target_link_options(maplesu-ghostlock-upstream-review PRIVATE -fPIE -pie -pthread -flto)

if(MAPLESU_BUILD_GHOSTLOCK_ADAPTER)
    include(adapter.cmake)
endif()
