
set(CMAKE_FIND_PACKAGE_RESOLVE_SYMLINKS TRUE)
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake from ${LLVM_DIR}")

if (${LLVM_VERSION_MAJOR} LESS 11 OR ${LLVM_VERSION_MAJOR} GREATER 11)
    message(WARNING "The software has been developed for LLVM 11; \
proceed at your own risk!")
endif()

if (NOT LLVM_FOUND)
    message(FATAL_ERROR "LLVM version 11 or above required!")
endif()

message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")

EXECUTE_PROCESS(
    COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/../../common/src/config.rs          
    COMMAND grep "pub const MAP_SIZE_POW2"
    COMMAND cut -f2 -d "="  
    COMMAND grep -o "[[:digit:]]*"
    COMMAND tr -d "\n" 
    OUTPUT_VARIABLE MAP_SIZE_POW2
)
message(STATUS "MAP_SIZE_POW2: ${MAP_SIZE_POW2}")

if (NOT TARGET LLVMPassConfig)
    add_library(LLVMPassConfig INTERFACE IMPORTED)
    set_target_properties(LLVMPassConfig PROPERTIES
        INTERFACE_COMPILE_OPTIONS "-fno-rtti" #-fpic
        INTERFACE_INCLUDE_DIRECTORIES "${LLVM_INCLUDE_DIRS}"
        INTERFACE_LINK_DIRECTORIES "${LLVM_LIBRARY_DIRS}"
        INTERFACE_COMPILE_DEFINITIONS "LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR};LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR};MAP_SIZE_POW2=${MAP_SIZE_POW2}"
        # INTERFACE_LINK_OPTIONS "-Wl,-znodelete"
    )
endif()

set (CMAKE_CXX_STANDARD 14)
# fix pass bug: https://github.com/sampsyo/llvm-pass-skeleton/issues/7#issuecomment-401834287
set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-znodelete")
if(APPLE)
    # User teor2345 reports that this is required to make things work on MacOS X.
    set (CMAKE_MODULE_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-flat_namespace -Wl,-undefined,suppress")
endif(APPLE)

add_library(UnfoldBranchPass MODULE UnfoldBranchPass.cc)
target_link_libraries(UnfoldBranchPass LLVMPassConfig)
add_custom_command(TARGET UnfoldBranchPass POST_BUILD
        COMMAND mkdir -p "${ANGORA_PASS_DIR}"
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/$<TARGET_FILE_NAME:UnfoldBranchPass>" "${ANGORA_PASS_DIR}")
install (TARGETS UnfoldBranchPass DESTINATION ${ANGORA_PASS_DIR})

add_library(IDPass MODULE IDPass.cc)
target_link_libraries(IDPass LLVMPassConfig)
add_custom_command(TARGET IDPass POST_BUILD
        COMMAND mkdir -p "${ANGORA_PASS_DIR}"
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/$<TARGET_FILE_NAME:IDPass>" "${ANGORA_PASS_DIR}")
install (TARGETS IDPass DESTINATION ${ANGORA_PASS_DIR})

add_library(AngoraPass MODULE AngoraPass.cc)
target_link_libraries(AngoraPass LLVMPassConfig)
add_custom_command(TARGET AngoraPass POST_BUILD
        COMMAND mkdir -p "${ANGORA_PASS_DIR}"
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/$<TARGET_FILE_NAME:AngoraPass>" "${ANGORA_PASS_DIR}")
install (TARGETS AngoraPass DESTINATION ${ANGORA_PASS_DIR})

add_library(DFSanPass MODULE DFSanPass.cc)
target_link_libraries(DFSanPass LLVMPassConfig)
add_custom_command(TARGET DFSanPass POST_BUILD
        COMMAND mkdir -p "${ANGORA_PASS_DIR}"
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/$<TARGET_FILE_NAME:DFSanPass>" "${ANGORA_PASS_DIR}")
install (TARGETS DFSanPass DESTINATION ${ANGORA_PASS_DIR})
