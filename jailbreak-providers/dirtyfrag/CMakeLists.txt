cmake_minimum_required(VERSION 3.22)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(maplesu_dirtyfrag_review LANGUAGES C ASM)
else()
    enable_language(ASM)
endif()

if(NOT ANDROID OR NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "DirtyFrag upstream review requires Android arm64-v8a")
endif()

# Preserve the pinned snapshot: upstream writes splicehelper beside its sources,
# and exp.c uses relative .incbin paths. All build inputs live in this staging dir.
set(review_stage "${CMAKE_CURRENT_BINARY_DIR}/upstream-review-stage")
set(review_output "${CMAKE_CURRENT_BINARY_DIR}/review-artifacts")
file(MAKE_DIRECTORY "${review_stage}/ko")
foreach(source exp.c libcxx.S elf_parser.c aes256.h include.inc splicehelper.c bootstrap.c)
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/upstream/app/src/main/jni/${source}"
        "${review_stage}/${source}" COPYONLY)
endforeach()

# The stock modules were built for the reference author's own kernels (every one
# carries a `*-dirty` vermagic). A device on stock GKI can accept them - the loader
# compares only the suffix - and then crashes inside their init, because the ABI they
# were built against is not the running one. A caller that has a module built for the
# target image can therefore replace exactly one KMI's blob.
set(MAPLESU_KO_OVERRIDE "" CACHE FILEPATH "module image that replaces the stock blob for one KMI")
set(MAPLESU_KO_OVERRIDE_KMI "" CACHE STRING "which KMI the override replaces")

set(review_ko_files)
foreach(kmi android12-5.10 android13-5.10 android13-5.15 android14-5.15
            android14-6.1 android15-6.6 android16-6.12 android17-6.18)
    set(ko "${review_stage}/ko/dfroot-${kmi}.ko")
    if(MAPLESU_KO_OVERRIDE AND kmi STREQUAL "${MAPLESU_KO_OVERRIDE_KMI}")
        if(NOT EXISTS "${MAPLESU_KO_OVERRIDE}")
            message(FATAL_ERROR "MAPLESU_KO_OVERRIDE does not exist: ${MAPLESU_KO_OVERRIDE}")
        endif()
        configure_file("${MAPLESU_KO_OVERRIDE}" "${ko}" COPYONLY)
        message(STATUS "dirtyfrag: ${kmi} embeds ${MAPLESU_KO_OVERRIDE}")
    else()
        configure_file("${CMAKE_CURRENT_SOURCE_DIR}/upstream/stock-artifacts/ko/dfroot-${kmi}.ko"
            "${ko}" COPYONLY)
    endif()
    list(APPEND review_ko_files "${ko}")
endforeach()

set(review_helper "${review_stage}/splicehelper")
add_custom_command(
    OUTPUT "${review_helper}"
    COMMAND "${CMAKE_C_COMPILER}" "--target=${CMAKE_C_COMPILER_TARGET}"
        "--sysroot=${CMAKE_SYSROOT}" "${review_stage}/splicehelper.c"
        -o "${review_helper}" -nodefaultlibs -nostartfiles -ffreestanding -static
    COMMAND "${CMAKE_STRIP}" "${review_helper}"
    DEPENDS "${review_stage}/splicehelper.c"
    VERBATIM)
add_custom_target(maplesu-dirtyfrag-splicehelper-upstream-review DEPENDS "${review_helper}")

add_executable(maplesu-dirtyfrag-upstream-review EXCLUDE_FROM_ALL
    "${review_stage}/exp.c" "${review_stage}/libcxx.S" "${review_stage}/elf_parser.c")
add_dependencies(maplesu-dirtyfrag-upstream-review maplesu-dirtyfrag-splicehelper-upstream-review)
target_include_directories(maplesu-dirtyfrag-upstream-review PRIVATE "${review_stage}")
target_compile_options(maplesu-dirtyfrag-upstream-review PRIVATE
    -Wall -Wextra -fno-stack-protector -fomit-frame-pointer "-Wa,-I,${review_stage}")
set_source_files_properties("${review_stage}/exp.c" PROPERTIES
    OBJECT_DEPENDS "${review_ko_files};${review_helper}")
target_link_libraries(maplesu-dirtyfrag-upstream-review PRIVATE log)

add_executable(maplesu-dirtyfrag-bootstrap-upstream-review EXCLUDE_FROM_ALL "${review_stage}/bootstrap.c")
foreach(target maplesu-dirtyfrag-upstream-review maplesu-dirtyfrag-bootstrap-upstream-review)
    target_link_options(${target} PRIVATE -Wl,-z,max-page-size=16384)
    set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${review_output}")
endforeach()

# Product adapter: derived first stage plus the MapleSU bootstrap. Explicitly
# excluded from ALL; the Manager packaging edge names the two targets.
if(MAPLESU_BUILD_DIRTYFRAG_ADAPTER)
    include(adapter.cmake)
endif()

# No install(), JNI attachment or default-build dependency.
