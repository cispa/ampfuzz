cmake_minimum_required(VERSION 3.16)
project(amp_fuzz_wllvm_wrapper)

include(ExternalProject)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib/libcxx)
ExternalProject_Add(libcxx
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/llvm
        CMAKE_ARGS "-DCMAKE_C_COMPILER=clang"
        "-DCMAKE_CXX_COMPILER=clang++"
        "-DLLVM_ENABLE_PROJECTS='libcxx$<SEMICOLON>libcxxabi'"
        "-DLLVM_INCLUDE_TESTS=OFF"
        "-DLLVM_INCLUDE_EXAMPLES=OFF"
        "-DLLVM_INCLUDE_BENCHMARKS=OFF"
        "-DLLVM_INCLUDE_TOOLS=OFF"
        "-DLLVM_BUILD_TOOLS=OFF"
        CMAKE_GENERATOR Ninja
        SOURCE_SUBDIR llvm
        BUILD_COMMAND ninja cxx cxxabi
        #prevent default install action
        INSTALL_COMMAND cp -r "./include" "${CMAKE_CURRENT_BINARY_DIR}"
        COMMAND cp ./lib/libc++.a "${CMAKE_CURRENT_BINARY_DIR}/lib/libcxx"
        COMMAND cp ./lib/libc++abi.a "${CMAKE_CURRENT_BINARY_DIR}/lib/libcxx")

find_program(CLANG_PATH clang)
get_filename_component(REAL_CLANG_PATH "${CLANG_PATH}" REALPATH)
get_filename_component(LLVM_COMPILER_PATH "${REAL_CLANG_PATH}" DIRECTORY)

configure_file(pre_clang.in ${CMAKE_CURRENT_SOURCE_DIR}/pre_clang @ONLY)
configure_file(pre_clang++.in ${CMAKE_CURRENT_SOURCE_DIR}/pre_clang++ @ONLY)
configure_file(01_prep_package.py.in ${CMAKE_CURRENT_SOURCE_DIR}/01_prep_package.py @ONLY)

install(PROGRAMS pre_clang pre_clang++ 01_prep_package.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR})