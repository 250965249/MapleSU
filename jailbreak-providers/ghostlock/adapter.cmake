# Explicit derived target, independent of the unmodified review targets.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(overlay "${CMAKE_CURRENT_BINARY_DIR}/maplesu-overlay")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/derive.py" --output "${overlay}"
    RESULT_VARIABLE overlay_result OUTPUT_QUIET)
if(NOT overlay_result EQUAL 0)
    message(FATAL_ERROR "Ghostlock source overlay verification failed")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/derive.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream-manifest.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/adapter/restore.sh"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/core/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/core/attack/ops.cpp")
set(adapter_sources ${MAPLESU_GHOSTLOCK_REVIEW_SOURCES})
list(REMOVE_ITEM adapter_sources
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/core/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/core/attack/ops.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/src/core/session/root_child_frontend.cpp")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/adapter/restore.sh" MAPLESU_GHOSTLOCK_RESTORE_SCRIPT)
configure_file(adapter/restore_script.hpp.in "${overlay}/restore_script.hpp" @ONLY)
add_executable(maplesu-ghostlock-adapter EXCLUDE_FROM_ALL ${adapter_sources}
    "${overlay}/src/core/main.cpp" "${overlay}/src/core/attack/ops.cpp"
    adapter/main.cpp adapter/handoff.cpp adapter/frontend.cpp ../lease/src/lease_contract.c)
set_target_properties(maplesu-ghostlock-adapter PROPERTIES OUTPUT_NAME libmaplesu_ghostlock_provider.so
    CXX_STANDARD 23 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO POSITION_INDEPENDENT_CODE ON)
target_include_directories(maplesu-ghostlock-adapter PRIVATE upstream/src/core adapter "${overlay}" ../lease/src)
target_compile_definitions(maplesu-ghostlock-adapter PRIVATE TARGET_CONFIG_H="kernel/target.h")
target_compile_options(maplesu-ghostlock-adapter PRIVATE -O2 -fno-rtti -Wall -Wextra -Wconversion
    -Wsign-conversion -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function)
target_link_options(maplesu-ghostlock-adapter PRIVATE -fPIE -pie -pthread -Wl,-z,relro,-z,now -Wl,-z,max-page-size=16384)
