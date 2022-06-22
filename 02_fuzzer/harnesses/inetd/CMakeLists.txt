set(ANGORA_HARNESS_INETD_DIR "${ANGORA_HARNESSES_DIR}/inetd")
file(MAKE_DIRECTORY ${ANGORA_HARNESS_INETD_DIR})

add_executable(inetd_wrap inetd_wrap.c)
install (TARGETS inetd_wrap DESTINATION ${ANGORA_HARNESS_INETD_DIR})

add_library(ioctl_shim SHARED ioctl_shim.c)
target_link_libraries(ioctl_shim ${CMAKE_DL_LIBS})
install (TARGETS ioctl_shim DESTINATION ${ANGORA_HARNESS_INETD_DIR})

install(PROGRAMS wrap.sh DESTINATION ${ANGORA_HARNESS_INETD_DIR})