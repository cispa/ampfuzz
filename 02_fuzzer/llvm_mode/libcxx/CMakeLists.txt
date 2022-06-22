# libcxx_fast has no dependencies (=regular libcxx), libcxx_track depends on angora_clang
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake from ${LLVM_DIR}")

if (${LLVM_VERSION_MAJOR} LESS 11 OR ${LLVM_VERSION_MAJOR} GREATER 11)
    message(WARNING "The software has been developed for LLVM 11; \
proceed at your own risk!")
endif()

if (NOT LLVM_FOUND)
    message(FATAL_ERROR "You haven't install LLVM !")
endif()

include(ExternalProject)
file(MAKE_DIRECTORY ${ANGORA_LIB_DIR}/libcxx_fast)
ExternalProject_Add(libcxx_fast
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/llvm
        CMAKE_ARGS "-DCMAKE_C_COMPILER=clang"
            "-DCMAKE_CXX_COMPILER=clang++"
            "-DLLVM_ENABLE_PROJECTS='libcxx$<SEMICOLON>libcxxabi'"
            "-DLLVM_INCLUDE_TESTS=OFF"
            "-DLLVM_INCLUDE_EXAMPLES=OFF"
            "-DLLVM_INCLUDE_BENCHMARKS=OFF"
            "-DLLVM_INCLUDE_TOOLS=OFF"
            "-DLLVM_BUILD_TOOLS=OFF"
            "-DLIBCXXABI_ENABLE_SHARED=NO"
            "-DLIBCXX_ENABLE_SHARED=NO"
        CMAKE_GENERATOR Ninja
        SOURCE_SUBDIR llvm
        BUILD_COMMAND ninja cxx cxxabi
        #prevent default install action
        INSTALL_COMMAND cp -r "./include" "${ANGORA_BIN_DIR}"
            COMMAND cp ./lib/libc++.a "${ANGORA_LIB_DIR}/libcxx_fast"
            COMMAND cp ./lib/libc++abi.a "${ANGORA_LIB_DIR}/libcxx_fast")

ExternalProject_Get_property(libcxx_fast BINARY_DIR)
MESSAGE("libcxx_fast built in ${BINARY_DIR}")
install (DIRECTORY "${BINARY_DIR}/include" DESTINATION "${ANGORA_BIN_DIR}")
install (FILES "${BINARY_DIR}/lib/libc++.a" DESTINATION "${ANGORA_LIB_DIR}/libcxx_fast")
install (FILES "${BINARY_DIR}/lib/libc++abi.a" DESTINATION "${ANGORA_LIB_DIR}/libcxx_fast")

# libcxx_track requires installation of the above, both for config, build and install
ExternalProject_Get_property(libcxx_fast SOURCE_DIR)
file(MAKE_DIRECTORY ${ANGORA_LIB_DIR}/libcxx_track)
ExternalProject_Add(libcxx_track
        SOURCE_DIR "${SOURCE_DIR}"
        CMAKE_ARGS "-DCMAKE_C_COMPILER=${ANGORA_BIN_DIR}/san-clang"
            "-DCMAKE_CXX_COMPILER=${ANGORA_BIN_DIR}/san-clang++"
            "-DLLVM_ENABLE_PROJECTS='libcxx$<SEMICOLON>libcxxabi'"
            "-DLLVM_INCLUDE_TESTS=OFF"
            "-DLLVM_INCLUDE_EXAMPLES=OFF"
            "-DLLVM_INCLUDE_BENCHMARKS=OFF"
            "-DLLVM_INCLUDE_TOOLS=OFF"
            "-DLLVM_BUILD_TOOLS=OFF"
            "-DLIBCXXABI_ENABLE_SHARED=NO"
            "-DLIBCXX_ENABLE_SHARED=NO"
        CMAKE_GENERATOR Ninja
        SOURCE_SUBDIR llvm
        BUILD_COMMAND USE_DFSAN=1 ninja cxx cxxabi
        #prevent default install action
        INSTALL_COMMAND cp ./lib/libc++.a "${ANGORA_LIB_DIR}/libcxx_track"
            COMMAND cp ./lib/libc++abi.a "${ANGORA_LIB_DIR}/libcxx_track"
        DEPENDS libcxx_fast SanClang DFSanPass rules dfsan_abilist)

ExternalProject_Get_property(libcxx_track BINARY_DIR)
install (FILES "${BINARY_DIR}/lib/libc++.a" DESTINATION "${ANGORA_LIB_DIR}/libcxx_track")
install (FILES "${BINARY_DIR}/lib/libc++abi.a" DESTINATION "${ANGORA_LIB_DIR}/libcxx_track")
