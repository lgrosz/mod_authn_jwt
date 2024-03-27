cmake_minimum_required(VERSION 3.10)

project(lighttpd-mod_authn_jwt C)

add_library(mod_authn_jwt SHARED mod_authn_jwt.c)
find_package(libjwt)

set(LIGHTTPD_SOURCE_DIR "" CACHE STRING "Path of lighttpd repository. \$\{LIGHTTPD_SOURCE_DIR}/src is expected to exist")
set(LIGHTTPD_BUILD_DIR "" CACHE STRING "Path of lighttpd build directory. \$\{LIGHTTPD_BUILD_DIR}/build is expected to exist")

if (NOT "${LIGHTTPD_SOURCE_DIR}" STREQUAL "")
    target_include_directories(mod_authn_jwt PUBLIC ${LIGHTTPD_SOURCE_DIR}/src)
endif()

if (NOT "${LIGHTTPD_BUILD_DIR}" STREQUAL "")
    target_include_directories(mod_authn_jwt PUBLIC ${LIGHTTPD_BUILD_DIR}/build)

    if (EXISTS "${LIGHTTPD_BUILD_DIR}/build/config.h")
        target_compile_definitions(mod_authn_jwt PUBLIC "HAVE_CONFIG_H")
    endif()
endif()

target_link_libraries(
    mod_authn_jwt
    jwt
)

set_target_properties(
    mod_authn_jwt
    PROPERTIES
    PREFIX ""
    )

include(GNUInstallDirs)
install(
    TARGETS mod_authn_jwt
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
