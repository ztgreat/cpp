cmake_minimum_required(VERSION 3.16)
project(proxy-cpp)

set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_FLAGS -pthread)

include_directories(inc)
include_directories(inc/motoro)
include_directories(inc/motoro/lib)
include_directories(inc/motoro/lib/cppcodec)
include_directories(inc/motoro/lib/cppcodec/data)
include_directories(inc/motoro/lib/cppcodec/detail)
include_directories(inc/motoro/lib/re2)
include_directories(src)
include_directories(src/re2)
include_directories(src/re2/util)

# yaml-cpp
include_directories(inc/yaml-cpp)
include_directories(inc/yaml-cpp/contrib)
include_directories(inc/yaml-cpp/node)
include_directories(inc/yaml-cpp/node/detail)


aux_source_directory(inc DIR_SRCS)
aux_source_directory(inc/motoro DIR_SRCS)
aux_source_directory(inc/motoro/lib DIR_SRCS)
aux_source_directory(inc/motoro/lib/cppcodec DIR_SRCS)
aux_source_directory(inc/motoro/lib/cppcodec/data DIR_SRCS)
aux_source_directory(inc/motoro/lib/cppcodec/detail DIR_SRCS)
aux_source_directory(inc/motoro/lib/re2 DIR_SRCS)
aux_source_directory(src DIR_SRCS)
aux_source_directory(src/lib DIR_SRCS)
aux_source_directory(src/re2 DIR_SRCS)
aux_source_directory(src/re2/util DIR_SRCS)
aux_source_directory(. DIR_SRCS)

add_executable(${PROJECT_NAME} ${DIR_SRCS})

target_link_libraries(${PROJECT_NAME} ${CMAKE_HOME_DIRECTORY}/libs/libyaml-cppd.a)