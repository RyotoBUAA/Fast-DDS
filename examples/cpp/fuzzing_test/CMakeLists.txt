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
# 当在 Fast-DDS 主项目中构建时，fastdds_FOUND 已经被设置
# 当独立构建时，需要查找已安装的 fastcdr 和 fastdds
if(NOT fastcdr_FOUND)
    find_package(fastcdr 2 REQUIRED)
endif()

if(NOT fastdds_FOUND)
    find_package(fastdds 3 REQUIRED)
endif()

# 如果在主项目中构建，使用项目内部的 fastdds 目标
if(TARGET fastdds)
    message(STATUS "Building fuzzing_test as part of Fast-DDS project")
    set(FASTDDS_LIB fastdds)
else()
    message(STATUS "Building fuzzing_test standalone")
    set(FASTDDS_LIB fastdds fastcdr)
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
target_link_libraries(fuzzer_node ${FASTDDS_LIB})

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
target_link_libraries(monitor_node_asan ${FASTDDS_LIB})

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
target_link_libraries(monitor_node_ubsan ${FASTDDS_LIB})

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
target_link_libraries(monitor_node_full ${FASTDDS_LIB})

# ============================================================================
# 高级模糊测试节点 (协议感知模糊测试)
# ============================================================================
add_executable(advanced_fuzzer_node
    ${FUZZING_TEST_SOURCES_CXX}
    AdvancedFuzzerNode.cpp
    Common.cpp
)
target_compile_definitions(advanced_fuzzer_node PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    NODE_TYPE_ADVANCED_FUZZER
)
target_compile_features(advanced_fuzzer_node PRIVATE cxx_std_14)
target_link_libraries(advanced_fuzzer_node ${FASTDDS_LIB})

# ============================================================================
# libFuzzer 集成 (覆盖率引导模糊测试)
# ============================================================================
option(ENABLE_LIBFUZZER "Enable libFuzzer coverage-guided fuzzing" OFF)

if(ENABLE_LIBFUZZER)
    message(STATUS "Building libFuzzer harness...")
    
    add_executable(libfuzzer_harness
        ${FUZZING_TEST_SOURCES_CXX}
        LibFuzzerHarness.cpp
    )
    target_compile_definitions(libfuzzer_harness PRIVATE
        $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    )
    target_compile_options(libfuzzer_harness PRIVATE
        -g
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(libfuzzer_harness PRIVATE
        -fsanitize=fuzzer,address,undefined
    )
    target_compile_features(libfuzzer_harness PRIVATE cxx_std_14)
    target_link_libraries(libfuzzer_harness ${FASTDDS_LIB})
    
    # 安装 libFuzzer 目标
    install(TARGETS libfuzzer_harness
        RUNTIME DESTINATION ${DATA_INSTALL_DIR}/fastdds/examples/cpp/fuzzing_test/${BIN_INSTALL_DIR})
endif()

# ============================================================================
# AFL++ Harness
# ============================================================================
option(ENABLE_AFL "Enable AFL++ harness" OFF)

if(ENABLE_AFL)
    message(STATUS "Building AFL++ harness...")
    
    add_executable(afl_harness
        ${FUZZING_TEST_SOURCES_CXX}
        AFLHarness.cpp
    )
    target_compile_definitions(afl_harness PRIVATE
        $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    )
    # AFL++ 编译器会自动添加必要的插桩
    target_compile_options(afl_harness PRIVATE
        -g
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(afl_harness PRIVATE
        -fsanitize=address,undefined
    )
    target_compile_features(afl_harness PRIVATE cxx_std_14)
    target_link_libraries(afl_harness ${FASTDDS_LIB})
    
    install(TARGETS afl_harness
        RUNTIME DESTINATION ${DATA_INSTALL_DIR}/fastdds/examples/cpp/fuzzing_test/${BIN_INSTALL_DIR})
endif()

# ============================================================================
# CDR 专用 Fuzzer (测试序列化/反序列化)
# ============================================================================
option(ENABLE_CDR_FUZZER "Enable CDR serialization fuzzer" OFF)

if(ENABLE_CDR_FUZZER AND ENABLE_LIBFUZZER)
    message(STATUS "Building CDR fuzzer...")
    
    add_executable(cdr_fuzzer
        ${FUZZING_TEST_SOURCES_CXX}
        LibFuzzerHarness.cpp
    )
    target_compile_definitions(cdr_fuzzer PRIVATE
        $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
        FUZZ_TARGET_CDR_ONLY
    )
    target_compile_options(cdr_fuzzer PRIVATE
        -g
        -fsanitize=fuzzer,address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(cdr_fuzzer PRIVATE
        -fsanitize=fuzzer,address,undefined
    )
    target_compile_features(cdr_fuzzer PRIVATE cxx_std_14)
    target_link_libraries(cdr_fuzzer ${FASTDDS_LIB})
endif()

# ============================================================================
# 网络注入模糊测试器
# ============================================================================
add_executable(network_injector_fuzzer
    ${FUZZING_TEST_SOURCES_CXX}
    AdvancedFuzzerNode.cpp
    Common.cpp
)
target_compile_definitions(network_injector_fuzzer PRIVATE
    $<$<AND:$<NOT:$<BOOL:${WIN32}>>,$<STREQUAL:"${CMAKE_BUILD_TYPE}","Debug">>:__DEBUG>
    NODE_TYPE_NETWORK_INJECTOR
    USE_NETWORK_INJECTION
)
target_compile_features(network_injector_fuzzer PRIVATE cxx_std_14)
target_link_libraries(network_injector_fuzzer ${FASTDDS_LIB})

# ============================================================================
# 安装目标
# ============================================================================
install(TARGETS 
    fuzzer_node 
    monitor_node_asan 
    monitor_node_ubsan 
    monitor_node_full
    advanced_fuzzer_node
    network_injector_fuzzer
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

# ============================================================================
# 复制种子和字典文件
# ============================================================================
file(GLOB SEED_FILES ${CMAKE_CURRENT_SOURCE_DIR}/seeds/*.bin)
file(GLOB DICT_FILES ${CMAKE_CURRENT_SOURCE_DIR}/dictionaries/*.dict)

# 创建输出目录
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/seeds)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/dictionaries)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/crashes)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/corpus)

foreach(SEED_FILE ${SEED_FILES})
    get_filename_component(SEED_NAME ${SEED_FILE} NAME)
    configure_file(${SEED_FILE} ${CMAKE_CURRENT_BINARY_DIR}/seeds/${SEED_NAME} COPYONLY)
endforeach()

foreach(DICT_FILE ${DICT_FILES})
    get_filename_component(DICT_NAME ${DICT_FILE} NAME)
    configure_file(${DICT_FILE} ${CMAKE_CURRENT_BINARY_DIR}/dictionaries/${DICT_NAME} COPYONLY)
endforeach()

# ============================================================================
# 打印配置摘要
# ============================================================================
message(STATUS "")
message(STATUS "=== Fuzzing Test Configuration ===")
message(STATUS "  ASAN:       ${ENABLE_ASAN}")
message(STATUS "  UBSAN:      ${ENABLE_UBSAN}")
message(STATUS "  libFuzzer:  ${ENABLE_LIBFUZZER}")
message(STATUS "  AFL++:      ${ENABLE_AFL}")
message(STATUS "  CDR Fuzzer: ${ENABLE_CDR_FUZZER}")
message(STATUS "==================================")

