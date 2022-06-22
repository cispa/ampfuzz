add_executable(inetd_wrap inetd_wrap.c)
install (TARGETS inetd_wrap DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_library(ioctl_shim SHARED ioctl_shim.c)
target_link_libraries(ioctl_shim ${CMAKE_DL_LIBS})
install (TARGETS ioctl_shim DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(PROGRAMS wrap.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR})