# Copyright 2024 Proyectos y Sistemas de Mantenimiento SL (eProsima).
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.20)

project(fastdds_fuzzing_test VERSION 1 LANGUAGES CXX)

# Find requirements
if(NOT fastcdr_FOUND)
    find_package(fastcdr 2 REQUIRED)
endif()

if(NOT fastdds_FOUND)
    find_package(fastdds 3 REQUIRED)
endif()

# Check C++11
include(CheckCXXCompilerFlag)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    check_cxx_compiler_flag(-std=c++11 SUPPORTS_CXX11)
    if(NOT SUPPORTS_CXX11)
        message(FATAL_ERROR "Compiler doesn't support C++11")
    endif()
endif()

# Set CMAKE_BUILD_TYPE to Release by default.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Setting build type to 'Debug' for fuzzing test.")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING
        "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
        FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "Configuring DDS fuzzing test example...")

# IDL generated files
file(GLOB FUZZING_TEST_SOURCES_CXX "*.cxx")
file(GLOB FUZZING_TEST_SOURCES_CPP "*.cpp")

# 选项：启用 ASAN (AddressSanitizer)
option(ENABLE_ASAN "Enable AddressSanitizer for memory error detection" OFF)

# 选项：启用 UBSAN (UndefinedBehaviorSanitizer)  
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer for undefined behavior detection" OFF)

# Fuzzer Node (异常节点 - 执行模糊测试)
add_executable(fuzzer_node 
    ${FUZZING_TEST_SOURCES_CXX}
    FuzzerNode.cpp
    Common.cpp
)
target_compile_definitions(fuzzer_node PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    NODE_TYPE_FUZZER
)
target_link_libraries(fuzzer_node fastdds fastcdr)

# Monitor Node 1 (启用 ASAN)
add_executable(monitor_node_asan
    ${FUZZING_TEST_SOURCES_CXX}
    MonitorNode.cpp
    Common.cpp
)
target_compile_definitions(monitor_node_asan PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    NODE_TYPE_MONITOR
    MONITOR_ID=1
)
if(ENABLE_ASAN OR CMAKE_BUILD_TYPE STREQUAL "ASAN")
    target_compile_options(monitor_node_asan PRIVATE 
        -fsanitize=address 
        -fno-omit-frame-pointer
        -g
    )
    target_link_options(monitor_node_asan PRIVATE -fsanitize=address)
    message(STATUS "ASAN enabled for monitor_node_asan")
endif()
target_link_libraries(monitor_node_asan fastdds fastcdr)

# Monitor Node 2 (启用 UBSAN)
add_executable(monitor_node_ubsan
    ${FUZZING_TEST_SOURCES_CXX}
    MonitorNode.cpp
    Common.cpp
)
target_compile_definitions(monitor_node_ubsan PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    NODE_TYPE_MONITOR
    MONITOR_ID=2
)
if(ENABLE_UBSAN OR CMAKE_BUILD_TYPE STREQUAL "UBSAN")
    target_compile_options(monitor_node_ubsan PRIVATE 
        -fsanitize=undefined
        -fno-sanitize-recover=all
        -g
    )
    target_link_options(monitor_node_ubsan PRIVATE -fsanitize=undefined)
    message(STATUS "UBSAN enabled for monitor_node_ubsan")
endif()
target_link_libraries(monitor_node_ubsan fastdds fastcdr)

# Monitor Node 3 (启用 ASAN + UBSAN)
add_executable(monitor_node_full
    ${FUZZING_TEST_SOURCES_CXX}
    MonitorNode.cpp
    Common.cpp
)
target_compile_definitions(monitor_node_full PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    NODE_TYPE_MONITOR
    MONITOR_ID=3
)
if((ENABLE_ASAN AND ENABLE_UBSAN) OR CMAKE_BUILD_TYPE STREQUAL "FULL_SANITIZE")
    target_compile_options(monitor_node_full PRIVATE 
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
        -fno-sanitize-recover=all
        -g
    )
    target_link_options(monitor_node_full PRIVATE -fsanitize=address,undefined)
    message(STATUS "ASAN+UBSAN enabled for monitor_node_full")
endif()
target_link_libraries(monitor_node_full fastdds fastcdr)

# Installation
install(TARGETS fuzzer_node monitor_node_asan monitor_node_ubsan monitor_node_full
    RUNTIME DESTINATION ${DATA_INSTALL_DIR}/fastdds/examples/cpp/fuzzing_test/${BIN_INSTALL_DIR})

# Copy XML configuration files
file(GLOB_RECURSE XML_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.xml)
foreach(XML_FILE_COMPLETE_PATH ${XML_FILES})
    get_filename_component(XML_FILE ${XML_FILE_COMPLETE_PATH} NAME_WE)
    configure_file(
        ${XML_FILE_COMPLETE_PATH}
        ${CMAKE_CURRENT_BINARY_DIR}/${XML_FILE}.xml
        COPYONLY)
    install(FILES ${XML_FILE_COMPLETE_PATH}
        DESTINATION ${DATA_INSTALL_DIR}/fastdds/examples/cpp/fuzzing_test/${BIN_INSTALL_DIR})
endforeach()

