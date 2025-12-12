// Copyright 2024 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @file AFLHarness.cpp
 * @brief AFL++ 模糊测试 harness
 * 
 * 这个文件提供了一个可以与 AFL++ 一起使用的测试 harness。
 * 支持两种模式：
 * 1. 标准模式：从 stdin 读取输入
 * 2. 持久模式：使用 __AFL_LOOP 进行高效的持久化模糊测试
 * 
 * 编译方法（使用 AFL++ 编译器）：
 *   afl-clang-fast++ -g -fsanitize=address,undefined \
 *                    -I/path/to/fastdds/include \
 *                    AFLHarness.cpp -o afl_harness \
 *                    -lfastdds -lfastcdr
 * 
 * 运行方法：
 *   afl-fuzz -i seeds/ -o output/ -- ./afl_harness @@
 *   # 或者持久模式
 *   afl-fuzz -i seeds/ -o output/ -- ./afl_harness
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <unistd.h>

// Fast-DDS includes
#include <fastdds/rtps/common/SerializedPayload.hpp>
#include <fastcdr/Cdr.h>
#include <fastcdr/FastBuffer.h>

#include "TestMessagePubSubTypes.hpp"
#include "TestMessage.hpp"
#include "RTPSProtocolFuzzer.hpp"

using namespace eprosima::fastdds::rtps;

// ============================================================================
// AFL++ 持久模式支持
// ============================================================================

#ifdef __AFL_HAVE_MANUAL_CONTROL
    #define AFL_INIT() __AFL_INIT()
    #define AFL_LOOP(count) __AFL_LOOP(count)
#else
    #define AFL_INIT()
    #define AFL_LOOP(count) 1
#endif

// ============================================================================
// 测试目标函数
// ============================================================================

/**
 * @brief 测试 CDR 反序列化
 */
int test_cdr_deserialize(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 65536) {
        return 0;
    }
    
    try {
        eprosima::fastcdr::FastBuffer buffer(
            reinterpret_cast<char*>(const_cast<uint8_t*>(data)), size);
        
        eprosima::fastcdr::Cdr cdr(buffer, 
            eprosima::fastcdr::Cdr::LITTLE_ENDIANNESS,
            eprosima::fastcdr::CdrVersion::XCDRv1);
        
        SimpleTestMessage msg;
        
        uint32_t seq_num;
        cdr >> seq_num;
        msg.seq_num(seq_num);
        
        std::string message;
        cdr >> message;
        msg.message(message);
        
        uint8_t data_type;
        cdr >> data_type;
        msg.data_type(data_type);
        
    } catch (...) {
        // 异常是预期的
    }
    
    return 0;
}

/**
 * @brief 测试 RTPS 消息解析
 */
int test_rtps_parse(const uint8_t* data, size_t size)
{
    if (size < 20) {
        return 0;
    }
    
    try {
        const uint8_t* ptr = data;
        size_t remaining = size;
        
        // 检查 RTPS magic
        if (ptr[0] == 'R' && ptr[1] == 'T' && ptr[2] == 'P' && ptr[3] == 'S') {
            // 有效的 RTPS header
            ptr += 20;
            remaining -= 20;
            
            // 解析 submessages
            while (remaining >= 4) {
                uint8_t submessage_id = ptr[0];
                uint8_t flags = ptr[1];
                uint16_t length;
                memcpy(&length, ptr + 2, sizeof(length));
                
                ptr += 4;
                remaining -= 4;
                
                if (length == 0) {
                    length = remaining;
                }
                
                if (length > remaining) {
                    break;
                }
                
                // 处理 submessage 数据
                // 这里可以添加更详细的解析逻辑
                
                ptr += length;
                remaining -= length;
            }
        }
    } catch (...) {
        // 异常是预期的
    }
    
    return 0;
}

/**
 * @brief 测试 SerializedPayload
 */
int test_payload(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 1048576) {
        return 0;
    }
    
    try {
        SerializedPayload_t payload;
        payload.reserve(size);
        
        if (payload.data != nullptr) {
            memcpy(payload.data, data, size);
            payload.length = size;
            
            SimpleTestMessagePubSubType type;
            SimpleTestMessage msg;
            
            // 尝试反序列化
            type.deserialize(&payload, &msg);
            
            // 如果成功，尝试序列化回去
            SerializedPayload_t out_payload;
            out_payload.reserve(type.getSerializedSizeProvider(&msg)());
            type.serialize(&msg, &out_payload);
        }
    } catch (...) {
        // 异常是预期的
    }
    
    return 0;
}

/**
 * @brief 综合测试
 */
int test_all(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }
    
    // 根据输入选择测试
    uint8_t selector = data[0] % 3;
    
    switch (selector) {
        case 0:
            test_cdr_deserialize(data + 1, size - 1);
            break;
        case 1:
            test_rtps_parse(data + 1, size - 1);
            break;
        case 2:
            test_payload(data + 1, size - 1);
            break;
    }
    
    return 0;
}

// ============================================================================
// 输入读取函数
// ============================================================================

/**
 * @brief 从文件读取输入
 */
std::vector<uint8_t> read_file(const char* filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        return {};
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        return {};
    }
    
    return buffer;
}

/**
 * @brief 从 stdin 读取输入
 */
std::vector<uint8_t> read_stdin()
{
    std::vector<uint8_t> buffer;
    buffer.reserve(65536);
    
    int c;
    while ((c = getchar()) != EOF) {
        buffer.push_back(static_cast<uint8_t>(c));
        if (buffer.size() >= 1048576) {  // 最大 1MB
            break;
        }
    }
    
    return buffer;
}

// ============================================================================
// 主函数
// ============================================================================

int main(int argc, char** argv)
{
    // 初始化 AFL++ 延迟 fork 服务器
    AFL_INIT();
    
    // 持久模式循环
    while (AFL_LOOP(10000)) {
        std::vector<uint8_t> input;
        
        if (argc > 1) {
            // 从文件读取
            input = read_file(argv[1]);
        } else {
            // 从 stdin 读取
            input = read_stdin();
        }
        
        if (input.empty()) {
            continue;
        }
        
        // 运行测试
        test_all(input.data(), input.size());
    }
    
    return 0;
}

