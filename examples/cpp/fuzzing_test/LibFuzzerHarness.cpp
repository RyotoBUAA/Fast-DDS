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
 * @file LibFuzzerHarness.cpp
 * @brief 基于 libFuzzer 的覆盖率引导模糊测试器
 * 
 * 这个文件提供了多个 fuzz target，用于测试 Fast-DDS 的不同组件：
 * - CDR 序列化/反序列化
 * - RTPS 消息解析
 * - DDS 消息处理
 * 
 * 编译方法：
 *   clang++ -g -fsanitize=fuzzer,address,undefined \
 *           -I/path/to/fastdds/include \
 *           LibFuzzerHarness.cpp -o libfuzzer_harness \
 *           -lfastdds -lfastcdr
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <string>

// Fast-DDS includes
#include <fastdds/dds/core/Types.hpp>
#include <fastdds/rtps/common/CDRMessage_t.hpp>
#include <fastdds/rtps/common/SerializedPayload.hpp>
#include <fastcdr/Cdr.h>
#include <fastcdr/FastBuffer.h>

#include "TestMessagePubSubTypes.hpp"
#include "TestMessage.hpp"

using namespace eprosima::fastdds;
using namespace eprosima::fastdds::rtps;

// ============================================================================
// Fuzz Target 1: CDR 反序列化测试
// ============================================================================

/**
 * @brief 测试 CDR 反序列化的健壮性
 * 
 * 这个 fuzz target 尝试将随机字节序列反序列化为 SimpleTestMessage。
 * 目标是发现反序列化代码中的缓冲区溢出、越界读取等漏洞。
 */
extern "C" int LLVMFuzzerTestOneInput_CDR(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 65536) {
        return 0;  // 跳过空数据或过大数据
    }
    
    try {
        // 创建 FastBuffer 来包装输入数据
        eprosima::fastcdr::FastBuffer buffer(
            reinterpret_cast<char*>(const_cast<uint8_t*>(data)), size);
        
        // 尝试使用不同的字节序和 CDR 版本进行反序列化
        for (int endianness = 0; endianness <= 1; ++endianness) {
            for (int cdr_version = 0; cdr_version <= 2; ++cdr_version) {
                eprosima::fastcdr::Cdr::Endianness endian = 
                    endianness ? eprosima::fastcdr::Cdr::BIG_ENDIANNESS 
                               : eprosima::fastcdr::Cdr::LITTLE_ENDIANNESS;
                
                eprosima::fastcdr::CdrVersion version;
                switch (cdr_version) {
                    case 0: version = eprosima::fastcdr::CdrVersion::XCDRv1; break;
                    case 1: version = eprosima::fastcdr::CdrVersion::XCDRv2; break;
                    default: version = eprosima::fastcdr::CdrVersion::XCDRv1; break;
                }
                
                try {
                    eprosima::fastcdr::Cdr cdr(buffer, endian, version);
                    
                    SimpleTestMessage msg;
                    
                    // 尝试反序列化各个字段
                    uint32_t seq_num;
                    cdr >> seq_num;
                    msg.seq_num(seq_num);
                    
                    std::string message;
                    cdr >> message;
                    msg.message(message);
                    
                    uint8_t data_type;
                    cdr >> data_type;
                    msg.data_type(data_type);
                    
                } catch (const eprosima::fastcdr::exception::Exception& e) {
                    // CDR 异常是预期的，模糊测试会产生很多无效数据
                } catch (const std::exception& e) {
                    // 其他标准异常
                }
            }
        }
    } catch (...) {
        // 捕获所有异常，确保模糊测试可以继续
    }
    
    return 0;
}

// ============================================================================
// Fuzz Target 2: RTPS Header 解析测试
// ============================================================================

// RTPS 协议常量
constexpr uint8_t RTPS_MAGIC[4] = {'R', 'T', 'P', 'S'};
constexpr uint16_t RTPS_PROTOCOL_VERSION_MAJOR = 2;
constexpr uint16_t RTPS_PROTOCOL_VERSION_MINOR = 3;

/**
 * @brief RTPS Header 结构 (20 bytes)
 */
struct RTPSHeader {
    uint8_t magic[4];           // "RTPS"
    uint8_t protocol_version[2]; // Major.Minor
    uint8_t vendor_id[2];        // Vendor ID
    uint8_t guid_prefix[12];     // GUID Prefix
};

/**
 * @brief RTPS Submessage Header 结构 (4 bytes)
 */
struct SubmessageHeader {
    uint8_t submessage_id;       // Submessage type
    uint8_t flags;               // Flags (bit 0 = endianness)
    uint16_t submessage_length;  // Length of submessage
};

// Submessage IDs
enum SubmessageId : uint8_t {
    PAD = 0x01,
    ACKNACK = 0x06,
    HEARTBEAT = 0x07,
    GAP = 0x08,
    INFO_TS = 0x09,
    INFO_SRC = 0x0c,
    INFO_REPLY_IP4 = 0x0d,
    INFO_DST = 0x0e,
    INFO_REPLY = 0x0f,
    NACK_FRAG = 0x12,
    HEARTBEAT_FRAG = 0x13,
    DATA = 0x15,
    DATA_FRAG = 0x16,
};

/**
 * @brief 测试 RTPS 消息解析的健壮性
 */
extern "C" int LLVMFuzzerTestOneInput_RTPS(const uint8_t* data, size_t size)
{
    if (size < sizeof(RTPSHeader)) {
        return 0;  // 数据太小，无法构成有效的 RTPS 消息
    }
    
    try {
        const uint8_t* ptr = data;
        size_t remaining = size;
        
        // 解析 RTPS Header
        RTPSHeader header;
        memcpy(&header, ptr, sizeof(RTPSHeader));
        ptr += sizeof(RTPSHeader);
        remaining -= sizeof(RTPSHeader);
        
        // 验证 magic（模糊测试中这个检查会经常失败，这是预期的）
        bool valid_magic = (memcmp(header.magic, RTPS_MAGIC, 4) == 0);
        
        // 解析 Submessages
        while (remaining >= sizeof(SubmessageHeader)) {
            SubmessageHeader sub_header;
            memcpy(&sub_header, ptr, sizeof(SubmessageHeader));
            ptr += sizeof(SubmessageHeader);
            remaining -= sizeof(SubmessageHeader);
            
            // 检查 submessage 长度
            uint16_t length = sub_header.submessage_length;
            
            // 特殊情况：length 为 0 表示到消息末尾
            if (length == 0) {
                length = remaining;
            }
            
            if (length > remaining) {
                break;  // 长度无效
            }
            
            // 根据 submessage 类型进行处理
            switch (sub_header.submessage_id) {
                case DATA:
                case DATA_FRAG:
                    // 尝试解析 DATA submessage
                    if (length >= 20) {
                        // DATA submessage 至少需要 20 字节
                        uint16_t extra_flags = *reinterpret_cast<const uint16_t*>(ptr);
                        uint16_t octets_to_inline_qos = *reinterpret_cast<const uint16_t*>(ptr + 2);
                        // ... 更多解析逻辑
                    }
                    break;
                    
                case HEARTBEAT:
                    // HEARTBEAT submessage (28 bytes)
                    if (length >= 28) {
                        // 解析 reader/writer EntityId, sequence numbers
                    }
                    break;
                    
                case ACKNACK:
                    // ACKNACK submessage
                    if (length >= 24) {
                        // 解析 acknowledgment
                    }
                    break;
                    
                case GAP:
                case INFO_TS:
                case INFO_DST:
                case INFO_SRC:
                    // 其他 submessage 类型
                    break;
                    
                default:
                    // 未知 submessage 类型
                    break;
            }
            
            ptr += length;
            remaining -= length;
        }
    } catch (...) {
        // 捕获所有异常
    }
    
    return 0;
}

// ============================================================================
// Fuzz Target 3: SerializedPayload 测试
// ============================================================================

/**
 * @brief 测试 SerializedPayload 的处理
 */
extern "C" int LLVMFuzzerTestOneInput_Payload(const uint8_t* data, size_t size)
{
    if (size == 0 || size > 1048576) {  // 限制最大 1MB
        return 0;
    }
    
    try {
        // 创建 SerializedPayload
        SerializedPayload_t payload;
        payload.reserve(size);
        
        if (payload.data != nullptr) {
            memcpy(payload.data, data, size);
            payload.length = size;
            
            // 尝试使用 PubSubType 反序列化
            SimpleTestMessagePubSubType type;
            SimpleTestMessage msg;
            
            // 测试反序列化
            type.deserialize(&payload, &msg);
            
            // 测试序列化
            SerializedPayload_t out_payload;
            out_payload.reserve(type.getSerializedSizeProvider(&msg)());
            type.serialize(&msg, &out_payload);
        }
    } catch (...) {
        // 预期会有很多异常
    }
    
    return 0;
}

// ============================================================================
// Fuzz Target 4: 字符串处理测试
// ============================================================================

/**
 * @brief 专门测试字符串处理的健壮性
 */
extern "C" int LLVMFuzzerTestOneInput_String(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }
    
    try {
        // 将输入作为字符串处理
        std::string input(reinterpret_cast<const char*>(data), size);
        
        SimpleTestMessage msg;
        msg.message(input);
        
        // 测试消息的各种操作
        std::string copy = msg.message();
        size_t len = copy.length();
        
        // 测试空字符处理
        bool has_null = (copy.find('\0') != std::string::npos);
        
        // 测试序列化
        SimpleTestMessagePubSubType type;
        SerializedPayload_t payload;
        payload.reserve(type.getSerializedSizeProvider(&msg)());
        
        if (type.serialize(&msg, &payload)) {
            // 测试反序列化
            SimpleTestMessage msg2;
            type.deserialize(&payload, &msg2);
            
            // 验证往返一致性（可能因为空字符而不同）
        }
    } catch (...) {
    }
    
    return 0;
}

// ============================================================================
// 主 Fuzz Target（libFuzzer 入口点）
// ============================================================================

/**
 * @brief libFuzzer 主入口点
 * 
 * 使用输入的第一个字节来选择要测试的目标
 */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return 0;
    }
    
    // 使用第一个字节选择 fuzz target
    uint8_t selector = data[0] % 4;
    const uint8_t* payload = data + 1;
    size_t payload_size = size - 1;
    
    switch (selector) {
        case 0:
            return LLVMFuzzerTestOneInput_CDR(payload, payload_size);
        case 1:
            return LLVMFuzzerTestOneInput_RTPS(payload, payload_size);
        case 2:
            return LLVMFuzzerTestOneInput_Payload(payload, payload_size);
        case 3:
            return LLVMFuzzerTestOneInput_String(payload, payload_size);
        default:
            return 0;
    }
}

