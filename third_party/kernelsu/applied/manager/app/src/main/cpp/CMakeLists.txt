# MapleSU KSU JNI（03 分册 §4.2）。
# 注意：uapi 不再依赖仓库里的 symlink（Windows 上会落成 19 字节文本文件），
# 而是直接 -I applied 根目录；applied/manager/app/src/main/cpp/uapi 是真实副本。
cmake_minimum_required(VERSION 3.22.1)

project("maplesu_ksu")

# libcxx 由 prefab 提供（gradle/libs.versions.toml 的 lsposed-cxx）；
# 独立命令行构建（无 prefab）时退化为 NDK 自带的 c++_static（build_jni.sh 走这条）。
find_package(cxx QUIET CONFIG)
if(cxx_FOUND)
    link_libraries(cxx::cxx)
endif()

set(KSU_APPLIED "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../applied")
if(NOT EXISTS "${KSU_APPLIED}/uapi/supercall.h")
    message(FATAL_ERROR "applied/uapi missing: run third_party/kernelsu/scripts/apply_patches.py --clean")
endif()

add_library(maplesu_ksu SHARED jni.cc ksu.cc)
target_include_directories(maplesu_ksu PRIVATE . "${KSU_APPLIED}")
target_compile_definitions(maplesu_ksu PRIVATE KSU_MANAGER_GEN=2)

find_library(log-lib log)
target_link_libraries(maplesu_ksu ${log-lib})

add_library(adbroot SHARED adbroot.cc)
target_link_libraries(adbroot ${log-lib})
