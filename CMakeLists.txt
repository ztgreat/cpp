cmake_minimum_required(VERSION 3.16)
project(proxy-cpp)

set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_FLAGS -pthread)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

include_directories(inc)
include_directories(inc/mongols)
include_directories(inc/mongols/lib)
include_directories(inc/mongols/lib/cppcodec)
include_directories(inc/mongols/lib/cppcodec/data)
include_directories(inc/mongols/lib/cppcodec/detail)
include_directories(inc/mongols/lib/hash)
include_directories(inc/mongols/lib/re2)
include_directories(src)
include_directories(src/re2)
include_directories(src/re2/util)

# yaml-cpp
include_directories(inc/yaml-cpp)
include_directories(inc/yaml-cpp/contrib)
include_directories(inc/yaml-cpp/node)
include_directories(inc/yaml-cpp/node/detail)


aux_source_directory(inc DIR_SRCS)
aux_source_directory(inc/mongols DIR_SRCS)
aux_source_directory(inc/mongols/lib DIR_SRCS)
aux_source_directory(inc/mongols/lib/cppcodec DIR_SRCS)
aux_source_directory(inc/mongols/lib/cppcodec/data DIR_SRCS)
aux_source_directory(inc/mongols/lib/cppcodec/detail DIR_SRCS)
aux_source_directory(inc/mongols/lib/hash DIR_SRCS)
aux_source_directory(inc/mongols/lib/re2 DIR_SRCS)
aux_source_directory(src DIR_SRCS)
aux_source_directory(src/hash DIR_SRCS)
aux_source_directory(src/lib DIR_SRCS)
aux_source_directory(src/re2 DIR_SRCS)
aux_source_directory(src/re2/util DIR_SRCS)
aux_source_directory(. DIR_SRCS)

add_executable(${PROJECT_NAME} ${DIR_SRCS})


target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})

target_link_libraries(${PROJECT_NAME} ${CMAKE_HOME_DIRECTORY}/libs/libyaml-cppd.a)