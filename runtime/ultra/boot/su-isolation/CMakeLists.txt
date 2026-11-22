cmake_minimum_required(VERSION 3.22)
project(maplesu_helper_su_candidate LANGUAGES CXX ASM)
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/../../.." runtime)
target_sources(maplesu_policy_boot PRIVATE "${CMAKE_CURRENT_LIST_DIR}/helper_su_backend.cpp")
