
add_executable(AngoraClang angora_clang.c)
set_target_properties(AngoraClang PROPERTIES OUTPUT_NAME "angora-clang")

add_custom_command(TARGET AngoraClang POST_BUILD
    COMMAND ln -sf "angora-clang" "angora-clang++"
    COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/angora-clang" "${ANGORA_BIN_DIR}"
    COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/angora-clang++" "${ANGORA_BIN_DIR}")

install (TARGETS AngoraClang DESTINATION ${ANGORA_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/angora-clang++ DESTINATION ${ANGORA_BIN_DIR})

add_executable(SanClang san_clang.c)
set_target_properties(SanClang PROPERTIES OUTPUT_NAME "san-clang")

add_custom_command(TARGET SanClang POST_BUILD
        COMMAND ln -sf "san-clang" "san-clang++"
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/san-clang" "${ANGORA_BIN_DIR}"
        COMMAND cp "${CMAKE_CURRENT_BINARY_DIR}/san-clang++" "${ANGORA_BIN_DIR}")

install (TARGETS SanClang DESTINATION ${ANGORA_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/san-clang++ DESTINATION ${ANGORA_BIN_DIR})

install (PROGRAMS make_target DESTINATION ${ANGORA_BIN_DIR})