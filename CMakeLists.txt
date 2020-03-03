project(kwallet-password)
set(PROJECT_VERSION "5.18.80")

cmake_minimum_required(VERSION 3.10)
set (CMAKE_MODULE_PATH ${ECM_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

add_executable(kwallet-password kwallet_password.cpp)

target_sources(kwallet-password PRIVATE)

find_package(Qt5 CONFIG REQUIRED Core DBus)
find_package(LibGcrypt 1.5.0 REQUIRED)


include_directories (
    ${LIBGCRYPT_INCLUDE_DIR}
)

target_link_libraries(kwallet-password
    PRIVATE
    ${LIBGCRYPT_LIBRARIES}
    Qt5::DBus
)
