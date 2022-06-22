cmake_minimum_required(VERSION 3.16)
project(amp_fuzz_honeypot_synthesis)

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/symcc_amp")
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/harnesses")

install(PROGRAMS 01_install_package.py 02_instrument_target.py 03_collect_constraints.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR})