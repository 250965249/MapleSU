# MapleSU product adapter for the pinned DirtyFrag sources.
#
# Two explicit executables are produced for the APK:
#   libdfroot.so                      - native first stage (App UID, IpSec frame)
#   libmaplesu_dirtyfrag_bootstrap.so - kernel-dispatched privileged bootstrap
# The MapleSU root consumer is built by ../lease and staged by the App for the
# bootstrap to exec.
find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(overlay "${CMAKE_CURRENT_BINARY_DIR}/maplesu-overlay")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/derive.py" --output "${overlay}"
    RESULT_VARIABLE overlay_result OUTPUT_QUIET)
if(NOT overlay_result EQUAL 0)
    message(FATAL_ERROR "DirtyFrag source overlay verification failed")
endif()
file(READ "${overlay}/overlay.json" overlay_marker)
if(NOT overlay_marker MATCHES "\"complete\": true")
    message(FATAL_ERROR "DirtyFrag overlay did not publish a completion marker")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/derive.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/source-manifest.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/app/src/main/jni/exp.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/lkm/dfroot.c")

set(MAPLESU_DIRTYFRAG_KO_VARIANT "minimal" CACHE STRING
    "Kernel module form: minimal (no OEM text patches) or stock")
set_property(CACHE MAPLESU_DIRTYFRAG_KO_VARIANT PROPERTY STRINGS minimal stock)

# exp.c refers to "ko/<name>" and "splicehelper" through assembler .incbin, so
# every build input is copied into one staging directory first.
set(stage "${CMAKE_CURRENT_BINARY_DIR}/product-stage")
file(REMOVE_RECURSE "${stage}")
file(MAKE_DIRECTORY "${stage}/ko")
foreach(source libcxx.S elf_parser.c aes256.h include.inc splicehelper.c)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/upstream/app/src/main/jni/${source}"
        "${stage}/${source}" COPYONLY)
endforeach()
configure_file("${overlay}/app/src/main/jni/exp.c" "${stage}/exp.c" COPYONLY)

set(ko_kmis android12-5.10 android13-5.10 android13-5.15 android14-5.15
             android14-6.1 android15-6.6 android16-6.12 android17-6.18)
# A whole directory of per-KMI modules: one APK then carries OUR module for every
# family it has one for, instead of a single family plus foreign builds.
set(MAPLESU_KO_OVERRIDE_DIR "" CACHE PATH "directory holding <kmi>.ko replacements")

foreach(kmi ${ko_kmis})
    if(MAPLESU_KO_OVERRIDE_DIR AND EXISTS "${MAPLESU_KO_OVERRIDE_DIR}/${kmi}.ko")
        if(MAPLESU_KO_OVERRIDE AND kmi STREQUAL "${MAPLESU_KO_OVERRIDE_KMI}" AND
           NOT EXISTS "${MAPLESU_KO_OVERRIDE}")
            message(FATAL_ERROR "MAPLESU_KO_OVERRIDE does not exist: ${MAPLESU_KO_OVERRIDE}")
        endif()
        set(source "${MAPLESU_KO_OVERRIDE_DIR}/${kmi}.ko")
        message(STATUS "dirtyfrag(product): ${kmi} embeds ${source}")
    elseif(MAPLESU_KO_OVERRIDE AND kmi STREQUAL "${MAPLESU_KO_OVERRIDE_KMI}")
        # A caller-supplied module for this KMI: the product build uses it so the
        # stager injects OUR module (built for the target image) instead of a blob
        # built for a different kernel.
        if(NOT EXISTS "${MAPLESU_KO_OVERRIDE}")
            message(FATAL_ERROR "MAPLESU_KO_OVERRIDE does not exist: ${MAPLESU_KO_OVERRIDE}")
        endif()
        set(source "${MAPLESU_KO_OVERRIDE}")
        message(STATUS "dirtyfrag(product): ${kmi} embeds ${MAPLESU_KO_OVERRIDE}")
    elseif(MAPLESU_DIRTYFRAG_KO_VARIANT STREQUAL "minimal")
        set(source "${overlay}/artifacts/dfroot-${kmi}.minimal.ko")
    else()
        set(source "${CMAKE_CURRENT_SOURCE_DIR}/upstream/stock-artifacts/ko/dfroot-${kmi}.ko")
    endif()
    configure_file("${source}" "${stage}/ko/dfroot-${kmi}.ko" COPYONLY)
    list(APPEND product_ko_files "${stage}/ko/dfroot-${kmi}.ko")
endforeach()

set(helper "${stage}/splicehelper")
add_custom_command(
    OUTPUT "${helper}"
    COMMAND "${CMAKE_C_COMPILER}" "--target=${CMAKE_C_COMPILER_TARGET}"
        "--sysroot=${CMAKE_SYSROOT}"
        "${stage}/splicehelper.c"
        -o "${helper}" -nodefaultlibs -nostartfiles -ffreestanding -static
    COMMAND "${CMAKE_STRIP}" "${helper}"
    DEPENDS "${stage}/splicehelper.c"
    VERBATIM)
add_custom_target(maplesu-dirtyfrag-splicehelper DEPENDS "${helper}")

add_executable(maplesu-dirtyfrag-native EXCLUDE_FROM_ALL
    "${stage}/exp.c" "${stage}/libcxx.S" "${stage}/elf_parser.c")
add_dependencies(maplesu-dirtyfrag-native maplesu-dirtyfrag-splicehelper)
set_target_properties(maplesu-dirtyfrag-native PROPERTIES
    OUTPUT_NAME "libdfroot"
    SUFFIX ".so"
    C_STANDARD 11)
target_include_directories(maplesu-dirtyfrag-native PRIVATE "${stage}")
target_compile_options(maplesu-dirtyfrag-native PRIVATE
    -Wall -Wextra -fno-stack-protector -fomit-frame-pointer "-Wa,-I,${stage}")
set_source_files_properties("${stage}/exp.c" PROPERTIES
    OBJECT_DEPENDS "${helper};${product_ko_files}")
target_link_libraries(maplesu-dirtyfrag-native PRIVATE log)
target_link_options(maplesu-dirtyfrag-native PRIVATE
    -fPIE -pie "-Wl,-z,max-page-size=16384")

add_executable(maplesu-dirtyfrag-bootstrap EXCLUDE_FROM_ALL
    adapter/bootstrap.c ../lease/src/lease_contract.c)
set_target_properties(maplesu-dirtyfrag-bootstrap PROPERTIES
    OUTPUT_NAME "libmaplesu_dirtyfrag_bootstrap"
    SUFFIX ".so"
    C_STANDARD 11)
target_include_directories(maplesu-dirtyfrag-bootstrap PRIVATE ../lease/src)
target_compile_options(maplesu-dirtyfrag-bootstrap PRIVATE -Wall -Wextra -O2)
target_link_options(maplesu-dirtyfrag-bootstrap PRIVATE
    -fPIE -pie "-Wl,-z,max-page-size=16384")

foreach(target maplesu-dirtyfrag-native maplesu-dirtyfrag-bootstrap)
    set_target_properties(${target} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/jailbreak-product")
endforeach()
