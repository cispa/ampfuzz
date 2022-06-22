cmake_minimum_required(VERSION 3.16)
project(amp_fuzz_fuzzer)

# set default build type to DEBUG
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif ()

# define directories
set(ANGORA_BIN_DIR "${CMAKE_BINARY_DIR}")
set(ANGORA_LIB_DIR "${ANGORA_BIN_DIR}/lib")
set(ANGORA_RULE_DIR "${ANGORA_BIN_DIR}/rules")
set(ANGORA_PASS_DIR "${ANGORA_BIN_DIR}/pass")
set(ANGORA_HARNESSES_DIR "${ANGORA_BIN_DIR}/harnesses")
# create directories
file(MAKE_DIRECTORY ${ANGORA_LIB_DIR})
file(MAKE_DIRECTORY ${ANGORA_RULE_DIR})
file(MAKE_DIRECTORY ${ANGORA_PASS_DIR})
file(MAKE_DIRECTORY ${ANGORA_HARNESSES_DIR})

add_custom_target(runtime_fast ALL
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND cargo build $<$<CONFIG:Release>:--release> --target-dir ${ANGORA_BIN_DIR} -p runtime_fast
        COMMAND cp ${ANGORA_BIN_DIR}/$<$<CONFIG:Release>:release>$<$<CONFIG:Debug>:debug>/libruntime_fast.a ${ANGORA_LIB_DIR})

add_custom_target(runtime ALL
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND cargo build $<$<CONFIG:Release>:--release> --target-dir ${ANGORA_BIN_DIR} -p runtime
        COMMAND cp ${ANGORA_BIN_DIR}/$<$<CONFIG:Release>:release>$<$<CONFIG:Debug>:debug>/libruntime.a ${ANGORA_LIB_DIR})

add_custom_target(fuzzer ALL
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND cargo build $<$<CONFIG:Release>:--release> --target-dir ${ANGORA_BIN_DIR} --bin fuzzer
        COMMAND cp ${ANGORA_BIN_DIR}/$<$<CONFIG:Release>:release>$<$<CONFIG:Debug>:debug>/fuzzer ${ANGORA_BIN_DIR})

add_custom_target(parse_track_file ALL
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND cargo build $<$<CONFIG:Release>:--release> --target-dir ${ANGORA_BIN_DIR} --bin parse_track_file
        COMMAND cp ${ANGORA_BIN_DIR}/$<$<CONFIG:Release>:release>$<$<CONFIG:Debug>:debug>/parse_track_file ${ANGORA_BIN_DIR})

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/llvm_mode")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/tools")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/harnesses")

install(PROGRAMS 01_install_package.py 02_instrument_target.py 03_fuzz_target.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR})