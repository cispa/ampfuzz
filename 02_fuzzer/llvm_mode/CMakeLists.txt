cmake_minimum_required(VERSION 3.4)
if(NOT LLVM_FOUND)
    find_package(LLVM REQUIRED CONFIG)

    message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
    message(STATUS "Using LLVMConfig.cmake from ${LLVM_DIR}")

    if (${LLVM_VERSION_MAJOR} LESS 11 OR ${LLVM_VERSION_MAJOR} GREATER 11)
        message(WARNING "The software has been developed for LLVM 11; \
proceed at your own risk!")
    endif()

    list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
    include(AddLLVM)
endif()

project(angora_llvm_mode VERSION 1.2.2 LANGUAGES C CXX ASM)

include_directories(include)
include_directories(dfsan_rt)
include_directories(../runtime/include)

add_subdirectory(compiler)
add_subdirectory(pass)
add_subdirectory(rules)
add_subdirectory(external_lib)
add_subdirectory(dfsan_rt)
add_subdirectory(libcxx)
