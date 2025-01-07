cmake_minimum_required(VERSION 3.5)
project(RN-Praxis)
set(CMAKE_C_STANDARD 11)

add_executable(webserver webserver.c http.c util.c data.c)
target_compile_options(webserver PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(webserver PRIVATE -lm)

# Packaging
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES ${CMAKE_BINARY_DIR} /\\..*$)
set(CPACK_VERBATIM_VARIABLES YES)
include(CPack)
