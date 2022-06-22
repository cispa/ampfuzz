add_custom_target(rules
        COMMAND mkdir -p "${ANGORA_RULE_DIR}"
        COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/angora_abilist.txt" "${ANGORA_RULE_DIR}"
        COMMAND cp "${CMAKE_CURRENT_SOURCE_DIR}/exploitation_list.txt" "${ANGORA_RULE_DIR}")

install (FILES "angora_abilist.txt" DESTINATION ${ANGORA_RULE_DIR})
install (FILES "exploitation_list.txt" DESTINATION ${ANGORA_RULE_DIR})