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
 * @file RTPSProtocolFuzzer.hpp
 * @brief RTPS 协议感知的结构化模糊测试器
 * 
 * 这个文件实现了一个协议感知的模糊测试器，它理解 RTPS 协议的结构，
 * 可以生成语法上有效但语义上可能有问题的消息。
 */

#ifndef RTPS_PROTOCOL_FUZZER_HPP_
#define RTPS_PROTOCOL_FUZZER_HPP_

#include <cstdint>
#include <cstring>
#include <vector>
#include <random>
#include <memory>
#include <array>
#include <algorithm>

namespace dds_fuzzing {

// ============================================================================
// RTPS 协议结构定义
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief RTPS 消息头（20字节）
 */
struct RTPSMessageHeader {
    uint8_t magic[4];           // "RTPS"
    uint8_t protocol_version[2]; // Major.Minor (2.3)
    uint8_t vendor_id[2];        // Vendor ID
    uint8_t guid_prefix[12];     // GUID Prefix
};

/**
 * @brief Submessage 头（4字节）
 */
struct SubmessageHeader {
    uint8_t submessage_id;       // Submessage 类型
    uint8_t flags;               // 标志位
    uint16_t submessage_length;  // 长度
};

/**
 * @brief EntityId（4字节）
 */
struct EntityId {
    uint8_t entity_key[3];
    uint8_t entity_kind;
};

/**
 * @brief GuidPrefix（12字节）
 */
struct GuidPrefix {
    uint8_t value[12];
};

/**
 * @brief GUID（16字节）
 */
struct GUID {
    GuidPrefix prefix;
    EntityId entity_id;
};

/**
 * @brief SequenceNumber（8字节）
 */
struct SequenceNumber {
    int32_t high;
    uint32_t low;
};

/**
 * @brief Locator（24字节）
 */
struct Locator {
    int32_t kind;
    uint32_t port;
    uint8_t address[16];
};

/**
 * @brief DATA Submessage
 */
struct DataSubmessage {
    uint16_t extra_flags;
    uint16_t octets_to_inline_qos;
    EntityId reader_id;
    EntityId writer_id;
    SequenceNumber writer_sn;
    // 后面跟着 inline QoS 和 serialized payload
};

/**
 * @brief HEARTBEAT Submessage
 */
struct HeartbeatSubmessage {
    EntityId reader_id;
    EntityId writer_id;
    SequenceNumber first_sn;
    SequenceNumber last_sn;
    int32_t count;
};

/**
 * @brief ACKNACK Submessage
 */
struct AcknackSubmessage {
    EntityId reader_id;
    EntityId writer_id;
    SequenceNumber base;
    uint32_t num_bits;
    // 后面跟着 bitmap 和 count
};

/**
 * @brief GAP Submessage
 */
struct GapSubmessage {
    EntityId reader_id;
    EntityId writer_id;
    SequenceNumber gap_start;
    SequenceNumber gap_list_base;
    uint32_t gap_list_num_bits;
    // 后面跟着 bitmap
};

/**
 * @brief INFO_TS Submessage
 */
struct InfoTimestampSubmessage {
    uint32_t seconds;
    uint32_t fraction;
};

/**
 * @brief INFO_DST Submessage
 */
struct InfoDestinationSubmessage {
    GuidPrefix guid_prefix;
};

#pragma pack(pop)

// Submessage 类型枚举
enum class SubmessageKind : uint8_t {
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
    SEC_BODY = 0x30,
    SEC_PREFIX = 0x31,
    SEC_POSTFIX = 0x32,
    SRTPS_PREFIX = 0x33,
    SRTPS_POSTFIX = 0x34,
};

// 预定义的 EntityId
namespace EntityIds {
    constexpr EntityId UNKNOWN = {{0x00, 0x00, 0x00}, 0x00};
    constexpr EntityId PARTICIPANT = {{0x00, 0x00, 0x01}, 0xc1};
    constexpr EntityId SEDP_BUILTIN_TOPIC_WRITER = {{0x00, 0x00, 0x02}, 0xc2};
    constexpr EntityId SEDP_BUILTIN_TOPIC_READER = {{0x00, 0x00, 0x02}, 0xc7};
    constexpr EntityId SEDP_BUILTIN_PUBLICATIONS_WRITER = {{0x00, 0x00, 0x03}, 0xc2};
    constexpr EntityId SEDP_BUILTIN_PUBLICATIONS_READER = {{0x00, 0x00, 0x03}, 0xc7};
    constexpr EntityId SEDP_BUILTIN_SUBSCRIPTIONS_WRITER = {{0x00, 0x00, 0x04}, 0xc2};
    constexpr EntityId SEDP_BUILTIN_SUBSCRIPTIONS_READER = {{0x00, 0x00, 0x04}, 0xc7};
    constexpr EntityId SPDP_BUILTIN_PARTICIPANT_WRITER = {{0x00, 0x01, 0x00}, 0xc2};
    constexpr EntityId SPDP_BUILTIN_PARTICIPANT_READER = {{0x00, 0x01, 0x00}, 0xc7};
}

// ============================================================================
// 协议感知模糊测试器
// ============================================================================

/**
 * @brief 模糊测试变异策略
 */
enum class MutationStrategy {
    // 基础变异
    BIT_FLIP,           // 位翻转
    BYTE_FLIP,          // 字节翻转
    BYTE_INSERT,        // 字节插入
    BYTE_DELETE,        // 字节删除
    BYTE_REPLACE,       // 字节替换
    
    // 整数变异
    INT_BOUNDARY,       // 整数边界值
    INT_ARITHMETIC,     // 整数算术运算
    INT_INTERESTING,    // 有趣的整数值
    
    // 协议感知变异
    SWAP_SUBMESSAGES,   // 交换 submessage 顺序
    DUPLICATE_SUBMESSAGE, // 复制 submessage
    TRUNCATE_SUBMESSAGE,  // 截断 submessage
    CORRUPT_LENGTH,     // 破坏长度字段
    CORRUPT_ENTITYID,   // 破坏 EntityId
    CORRUPT_SEQNUM,     // 破坏序列号
    INVALID_SUBMESSAGE_ID, // 无效的 submessage ID
    
    // 结构变异
    REMOVE_HEADER,      // 移除消息头
    DUPLICATE_HEADER,   // 重复消息头
    NESTED_MESSAGE,     // 嵌套消息
};

/**
 * @brief RTPS 协议感知模糊测试器
 */
class RTPSProtocolFuzzer {
public:
    RTPSProtocolFuzzer(uint64_t seed = 0)
        : rng_(seed ? seed : std::random_device{}())
        , dist_byte_(0, 255)
        , dist_strategy_(0, static_cast<int>(MutationStrategy::NESTED_MESSAGE))
    {
        initialize_interesting_values();
    }
    
    /**
     * @brief 生成一个格式良好的 RTPS 消息
     */
    std::vector<uint8_t> generate_valid_message()
    {
        std::vector<uint8_t> message;
        
        // 添加 RTPS 消息头
        append_header(message);
        
        // 添加 1-5 个随机 submessage
        int num_submessages = 1 + (rng_() % 5);
        for (int i = 0; i < num_submessages; ++i) {
            append_random_submessage(message);
        }
        
        return message;
    }
    
    /**
     * @brief 对现有消息进行变异
     */
    std::vector<uint8_t> mutate(const std::vector<uint8_t>& input)
    {
        if (input.empty()) {
            return generate_valid_message();
        }
        
        std::vector<uint8_t> output = input;
        
        // 选择变异策略
        MutationStrategy strategy = static_cast<MutationStrategy>(dist_strategy_(rng_));
        
        switch (strategy) {
            case MutationStrategy::BIT_FLIP:
                mutate_bit_flip(output);
                break;
            case MutationStrategy::BYTE_FLIP:
                mutate_byte_flip(output);
                break;
            case MutationStrategy::BYTE_INSERT:
                mutate_byte_insert(output);
                break;
            case MutationStrategy::BYTE_DELETE:
                mutate_byte_delete(output);
                break;
            case MutationStrategy::BYTE_REPLACE:
                mutate_byte_replace(output);
                break;
            case MutationStrategy::INT_BOUNDARY:
                mutate_int_boundary(output);
                break;
            case MutationStrategy::INT_ARITHMETIC:
                mutate_int_arithmetic(output);
                break;
            case MutationStrategy::INT_INTERESTING:
                mutate_int_interesting(output);
                break;
            case MutationStrategy::SWAP_SUBMESSAGES:
                mutate_swap_submessages(output);
                break;
            case MutationStrategy::DUPLICATE_SUBMESSAGE:
                mutate_duplicate_submessage(output);
                break;
            case MutationStrategy::TRUNCATE_SUBMESSAGE:
                mutate_truncate_submessage(output);
                break;
            case MutationStrategy::CORRUPT_LENGTH:
                mutate_corrupt_length(output);
                break;
            case MutationStrategy::CORRUPT_ENTITYID:
                mutate_corrupt_entityid(output);
                break;
            case MutationStrategy::CORRUPT_SEQNUM:
                mutate_corrupt_seqnum(output);
                break;
            case MutationStrategy::INVALID_SUBMESSAGE_ID:
                mutate_invalid_submessage_id(output);
                break;
            case MutationStrategy::REMOVE_HEADER:
                mutate_remove_header(output);
                break;
            case MutationStrategy::DUPLICATE_HEADER:
                mutate_duplicate_header(output);
                break;
            case MutationStrategy::NESTED_MESSAGE:
                mutate_nested_message(output);
                break;
        }
        
        return output;
    }
    
    /**
     * @brief 基于覆盖率反馈进行引导的变异
     */
    std::vector<uint8_t> mutate_guided(
        const std::vector<uint8_t>& input,
        const std::vector<bool>& coverage_bitmap,
        double energy)
    {
        std::vector<uint8_t> output = input;
        
        // 基于能量决定变异次数
        int mutations = 1 + static_cast<int>(energy * 10);
        
        // 如果有覆盖率信息，根据未覆盖的区域增加变异强度
        if (!coverage_bitmap.empty()) {
            size_t uncovered = 0;
            for (bool covered : coverage_bitmap) {
                if (!covered) uncovered++;
            }
            // 未覆盖率越高，变异越激进
            double uncovered_ratio = static_cast<double>(uncovered) / coverage_bitmap.size();
            mutations += static_cast<int>(uncovered_ratio * 5);
        }
        
        for (int i = 0; i < mutations; ++i) {
            output = mutate(output);
        }
        
        return output;
    }
    
    /**
     * @brief 生成 DDS 特定的畸形消息
     */
    std::vector<uint8_t> generate_dds_attack()
    {
        std::vector<uint8_t> message;
        
        // 选择攻击类型
        int attack_type = rng_() % 10;
        
        switch (attack_type) {
            case 0:
                // 发现攻击：伪造 SPDP 消息
                generate_spdp_attack(message);
                break;
            case 1:
                // 中间人攻击：伪造心跳
                generate_heartbeat_attack(message);
                break;
            case 2:
                // 拒绝服务：大量 GAP 消息
                generate_gap_attack(message);
                break;
            case 3:
                // 数据注入：伪造 DATA 消息
                generate_data_injection(message);
                break;
            case 4:
                // 序列号攻击
                generate_seqnum_attack(message);
                break;
            case 5:
                // 重放攻击
                generate_replay_attack(message);
                break;
            case 6:
                // 分片攻击
                generate_fragment_attack(message);
                break;
            case 7:
                // QoS 攻击
                generate_qos_attack(message);
                break;
            case 8:
                // 安全子消息攻击
                generate_security_attack(message);
                break;
            default:
                // 随机格式良好消息
                message = generate_valid_message();
                break;
        }
        
        return message;
    }

private:
    std::mt19937_64 rng_;
    std::uniform_int_distribution<int> dist_byte_;
    std::uniform_int_distribution<int> dist_strategy_;
    
    // 有趣的测试值
    std::vector<uint8_t> interesting_8bit_;
    std::vector<uint16_t> interesting_16bit_;
    std::vector<uint32_t> interesting_32bit_;
    std::vector<uint64_t> interesting_64bit_;
    
    void initialize_interesting_values()
    {
        // 8位有趣值
        interesting_8bit_ = {0, 1, 16, 32, 64, 100, 127, 128, 255};
        
        // 16位有趣值
        interesting_16bit_ = {0, 1, 16, 32, 64, 100, 127, 128, 255, 256,
                             512, 1000, 1024, 4096, 32767, 32768, 65535};
        
        // 32位有趣值
        interesting_32bit_ = {0, 1, 16, 32, 64, 100, 127, 128, 255, 256,
                             512, 1000, 1024, 4096, 32767, 32768, 65535, 65536,
                             100000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF};
        
        // 64位有趣值
        interesting_64bit_ = {0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF,
                             0x100000000ULL, 0x7FFFFFFFFFFFFFFFULL,
                             0x8000000000000000ULL, 0xFFFFFFFFFFFFFFFFULL};
    }
    
    void append_header(std::vector<uint8_t>& message)
    {
        RTPSMessageHeader header = {};
        header.magic[0] = 'R';
        header.magic[1] = 'T';
        header.magic[2] = 'P';
        header.magic[3] = 'S';
        header.protocol_version[0] = 2;
        header.protocol_version[1] = 3;
        header.vendor_id[0] = 0x01;  // eProsima
        header.vendor_id[1] = 0x0F;
        
        // 随机 GUID prefix
        for (int i = 0; i < 12; ++i) {
            header.guid_prefix[i] = dist_byte_(rng_);
        }
        
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), ptr, ptr + sizeof(header));
    }
    
    void append_random_submessage(std::vector<uint8_t>& message)
    {
        // 选择 submessage 类型
        static const SubmessageKind kinds[] = {
            SubmessageKind::DATA,
            SubmessageKind::HEARTBEAT,
            SubmessageKind::ACKNACK,
            SubmessageKind::GAP,
            SubmessageKind::INFO_TS,
            SubmessageKind::INFO_DST,
        };
        
        SubmessageKind kind = kinds[rng_() % (sizeof(kinds) / sizeof(kinds[0]))];
        
        switch (kind) {
            case SubmessageKind::DATA:
                append_data_submessage(message);
                break;
            case SubmessageKind::HEARTBEAT:
                append_heartbeat_submessage(message);
                break;
            case SubmessageKind::ACKNACK:
                append_acknack_submessage(message);
                break;
            case SubmessageKind::GAP:
                append_gap_submessage(message);
                break;
            case SubmessageKind::INFO_TS:
                append_info_ts_submessage(message);
                break;
            case SubmessageKind::INFO_DST:
                append_info_dst_submessage(message);
                break;
            default:
                append_data_submessage(message);
                break;
        }
    }
    
    void append_data_submessage(std::vector<uint8_t>& message)
    {
        // 生成随机 payload
        int payload_size = 8 + (rng_() % 256);
        std::vector<uint8_t> payload(payload_size);
        for (auto& b : payload) {
            b = dist_byte_(rng_);
        }
        
        // Submessage header
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::DATA);
        header.flags = 0x05;  // E=1 (little endian), D=1 (has data)
        header.submessage_length = sizeof(DataSubmessage) + payload_size;
        
        // DATA submessage
        DataSubmessage data = {};
        data.extra_flags = 0;
        data.octets_to_inline_qos = 16;  // reader_id + writer_id = 8, writer_sn = 8
        data.reader_id = EntityIds::UNKNOWN;
        data.writer_id = generate_random_entity_id();
        data.writer_sn.high = 0;
        data.writer_sn.low = rng_() % 1000;
        
        // 添加到消息
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(&data);
        message.insert(message.end(), data_ptr, data_ptr + sizeof(data));
        
        message.insert(message.end(), payload.begin(), payload.end());
    }
    
    void append_heartbeat_submessage(std::vector<uint8_t>& message)
    {
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::HEARTBEAT);
        header.flags = 0x01;  // E=1 (little endian)
        header.submessage_length = sizeof(HeartbeatSubmessage);
        
        HeartbeatSubmessage hb = {};
        hb.reader_id = EntityIds::UNKNOWN;
        hb.writer_id = generate_random_entity_id();
        hb.first_sn.high = 0;
        hb.first_sn.low = 1;
        hb.last_sn.high = 0;
        hb.last_sn.low = rng_() % 1000;
        hb.count = rng_() % 100;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* hb_ptr = reinterpret_cast<const uint8_t*>(&hb);
        message.insert(message.end(), hb_ptr, hb_ptr + sizeof(hb));
    }
    
    void append_acknack_submessage(std::vector<uint8_t>& message)
    {
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::ACKNACK);
        header.flags = 0x01;
        header.submessage_length = sizeof(AcknackSubmessage) + 4;  // +4 for count
        
        AcknackSubmessage ack = {};
        ack.reader_id = generate_random_entity_id();
        ack.writer_id = EntityIds::UNKNOWN;
        ack.base.high = 0;
        ack.base.low = rng_() % 1000;
        ack.num_bits = 0;
        
        int32_t count = rng_() % 100;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* ack_ptr = reinterpret_cast<const uint8_t*>(&ack);
        message.insert(message.end(), ack_ptr, ack_ptr + sizeof(ack));
        
        const uint8_t* cnt_ptr = reinterpret_cast<const uint8_t*>(&count);
        message.insert(message.end(), cnt_ptr, cnt_ptr + sizeof(count));
    }
    
    void append_gap_submessage(std::vector<uint8_t>& message)
    {
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::GAP);
        header.flags = 0x01;
        header.submessage_length = sizeof(GapSubmessage);
        
        GapSubmessage gap = {};
        gap.reader_id = EntityIds::UNKNOWN;
        gap.writer_id = generate_random_entity_id();
        gap.gap_start.high = 0;
        gap.gap_start.low = rng_() % 100;
        gap.gap_list_base.high = 0;
        gap.gap_list_base.low = gap.gap_start.low + 1;
        gap.gap_list_num_bits = 0;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* gap_ptr = reinterpret_cast<const uint8_t*>(&gap);
        message.insert(message.end(), gap_ptr, gap_ptr + sizeof(gap));
    }
    
    void append_info_ts_submessage(std::vector<uint8_t>& message)
    {
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::INFO_TS);
        header.flags = 0x01;
        header.submessage_length = sizeof(InfoTimestampSubmessage);
        
        InfoTimestampSubmessage ts = {};
        ts.seconds = static_cast<uint32_t>(time(nullptr));
        ts.fraction = rng_() % 1000000;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* ts_ptr = reinterpret_cast<const uint8_t*>(&ts);
        message.insert(message.end(), ts_ptr, ts_ptr + sizeof(ts));
    }
    
    void append_info_dst_submessage(std::vector<uint8_t>& message)
    {
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::INFO_DST);
        header.flags = 0x01;
        header.submessage_length = sizeof(InfoDestinationSubmessage);
        
        InfoDestinationSubmessage dst = {};
        for (int i = 0; i < 12; ++i) {
            dst.guid_prefix.value[i] = dist_byte_(rng_);
        }
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* dst_ptr = reinterpret_cast<const uint8_t*>(&dst);
        message.insert(message.end(), dst_ptr, dst_ptr + sizeof(dst));
    }
    
    EntityId generate_random_entity_id()
    {
        EntityId id;
        for (int i = 0; i < 3; ++i) {
            id.entity_key[i] = dist_byte_(rng_);
        }
        // Entity kind: 0x00-0x03 user, 0xc0-0xc7 builtin
        id.entity_kind = (rng_() % 2 == 0) ? (dist_byte_(rng_) & 0x03) : (0xc0 | (dist_byte_(rng_) & 0x07));
        return id;
    }
    
    // ========== 变异操作 ==========
    
    void mutate_bit_flip(std::vector<uint8_t>& data)
    {
        if (data.empty()) return;
        size_t pos = rng_() % data.size();
        int bit = rng_() % 8;
        data[pos] ^= (1 << bit);
    }
    
    void mutate_byte_flip(std::vector<uint8_t>& data)
    {
        if (data.empty()) return;
        size_t pos = rng_() % data.size();
        data[pos] = ~data[pos];
    }
    
    void mutate_byte_insert(std::vector<uint8_t>& data)
    {
        size_t pos = data.empty() ? 0 : rng_() % (data.size() + 1);
        data.insert(data.begin() + pos, dist_byte_(rng_));
    }
    
    void mutate_byte_delete(std::vector<uint8_t>& data)
    {
        if (data.empty()) return;
        size_t pos = rng_() % data.size();
        data.erase(data.begin() + pos);
    }
    
    void mutate_byte_replace(std::vector<uint8_t>& data)
    {
        if (data.empty()) return;
        size_t pos = rng_() % data.size();
        data[pos] = dist_byte_(rng_);
    }
    
    void mutate_int_boundary(std::vector<uint8_t>& data)
    {
        if (data.size() < 4) return;
        size_t pos = rng_() % (data.size() - 3);
        uint32_t boundary = interesting_32bit_[rng_() % interesting_32bit_.size()];
        memcpy(&data[pos], &boundary, sizeof(boundary));
    }
    
    void mutate_int_arithmetic(std::vector<uint8_t>& data)
    {
        if (data.size() < 4) return;
        size_t pos = rng_() % (data.size() - 3);
        int32_t value;
        memcpy(&value, &data[pos], sizeof(value));
        int delta = (rng_() % 71) - 35;  // -35 to +35
        value += delta;
        memcpy(&data[pos], &value, sizeof(value));
    }
    
    void mutate_int_interesting(std::vector<uint8_t>& data)
    {
        if (data.empty()) return;
        
        int size = rng_() % 4;  // 1, 2, 4, or 8 bytes
        switch (size) {
            case 0:
                if (data.size() >= 1) {
                    size_t pos = rng_() % data.size();
                    data[pos] = interesting_8bit_[rng_() % interesting_8bit_.size()];
                }
                break;
            case 1:
                if (data.size() >= 2) {
                    size_t pos = rng_() % (data.size() - 1);
                    uint16_t val = interesting_16bit_[rng_() % interesting_16bit_.size()];
                    memcpy(&data[pos], &val, sizeof(val));
                }
                break;
            case 2:
                if (data.size() >= 4) {
                    size_t pos = rng_() % (data.size() - 3);
                    uint32_t val = interesting_32bit_[rng_() % interesting_32bit_.size()];
                    memcpy(&data[pos], &val, sizeof(val));
                }
                break;
            case 3:
                if (data.size() >= 8) {
                    size_t pos = rng_() % (data.size() - 7);
                    uint64_t val = interesting_64bit_[rng_() % interesting_64bit_.size()];
                    memcpy(&data[pos], &val, sizeof(val));
                }
                break;
        }
    }
    
    void mutate_swap_submessages(std::vector<uint8_t>& data)
    {
        // 需要解析消息结构来交换 submessage
        // 简化实现：随机交换两个范围
        if (data.size() < 64) return;  // 需要足够的空间
        
        size_t available = data.size() - 20;
        if (available < 32) return;
        
        size_t start1 = 20 + (rng_() % (available / 4));
        size_t max_len1 = std::min(size_t(16), (available - start1 + 20) / 2);
        if (max_len1 < 4) return;
        size_t len1 = 4 + (rng_() % (max_len1 - 3));
        
        if (start1 + len1 + 8 >= data.size()) return;
        
        size_t start2 = start1 + len1 + (rng_() % 8);
        if (start2 + len1 > data.size()) return;
        
        size_t len2 = len1;  // 使用相同长度，避免越界
        
        std::vector<uint8_t> temp1(data.begin() + start1, data.begin() + start1 + len1);
        std::vector<uint8_t> temp2(data.begin() + start2, data.begin() + start2 + len2);
        
        std::copy(temp2.begin(), temp2.end(), data.begin() + start1);
        std::copy(temp1.begin(), temp1.end(), data.begin() + start2);
    }
    
    void mutate_duplicate_submessage(std::vector<uint8_t>& data)
    {
        if (data.size() < 28) return;
        
        // 在消息头后复制一段数据
        size_t start = 20;
        size_t len = std::min(size_t(32), data.size() - start);
        
        std::vector<uint8_t> segment(data.begin() + start, data.begin() + start + len);
        data.insert(data.begin() + start + len, segment.begin(), segment.end());
    }
    
    void mutate_truncate_submessage(std::vector<uint8_t>& data)
    {
        if (data.size() <= 24) return;
        
        // 随机截断到某个位置
        size_t range = data.size() - 20;
        if (range == 0) return;
        size_t new_size = 20 + (rng_() % range);
        if (new_size < 20) new_size = 20;
        data.resize(new_size);
    }
    
    void mutate_corrupt_length(std::vector<uint8_t>& data)
    {
        // 找到 submessage 头并破坏长度字段
        if (data.size() < 24) return;
        
        // Submessage 头的 length 字段在 offset 2-3
        for (size_t i = 20; i < data.size() - 4; i += 4) {
            // 随机选择是否修改这个位置
            if (rng_() % 3 == 0) {
                // 破坏长度字段
                uint16_t bad_length = interesting_16bit_[rng_() % interesting_16bit_.size()];
                data[i + 2] = bad_length & 0xFF;
                data[i + 3] = (bad_length >> 8) & 0xFF;
                break;
            }
        }
    }
    
    void mutate_corrupt_entityid(std::vector<uint8_t>& data)
    {
        if (data.size() < 32) return;  // 需要至少 32 字节
        
        // EntityId 通常在 submessage 数据部分
        size_t available = data.size() - 28;
        if (available == 0) {
            available = 1;
        }
        size_t pos = 24 + ((rng_() % available) / 4) * 4;
        
        // 确保不会越界
        if (pos + sizeof(EntityId) > data.size()) {
            pos = data.size() - sizeof(EntityId);
        }
        
        EntityId bad_id;
        for (int i = 0; i < 3; ++i) {
            bad_id.entity_key[i] = dist_byte_(rng_);
        }
        bad_id.entity_kind = dist_byte_(rng_);
        
        memcpy(&data[pos], &bad_id, sizeof(bad_id));
    }
    
    void mutate_corrupt_seqnum(std::vector<uint8_t>& data)
    {
        if (data.size() < 40) return;  // 需要更多空间
        
        size_t available = data.size() - 32;
        if (available == 0) {
            available = 1;
        }
        size_t pos = 24 + ((rng_() % available) / 8) * 8;
        
        // 确保不会越界
        if (pos + sizeof(SequenceNumber) > data.size()) {
            pos = data.size() - sizeof(SequenceNumber);
        }
        
        SequenceNumber bad_sn;
        bad_sn.high = rng_() % 2 == 0 ? -1 : static_cast<int32_t>(rng_());
        bad_sn.low = interesting_32bit_[rng_() % interesting_32bit_.size()];
        
        memcpy(&data[pos], &bad_sn, sizeof(bad_sn));
    }
    
    void mutate_invalid_submessage_id(std::vector<uint8_t>& data)
    {
        if (data.size() < 24) return;
        
        // 在 submessage 头位置设置无效 ID
        data[20] = dist_byte_(rng_);  // 随机 ID，很可能无效
    }
    
    void mutate_remove_header(std::vector<uint8_t>& data)
    {
        if (data.size() <= 20) return;
        data.erase(data.begin(), data.begin() + 20);
    }
    
    void mutate_duplicate_header(std::vector<uint8_t>& data)
    {
        if (data.size() < 20) return;
        std::vector<uint8_t> header(data.begin(), data.begin() + 20);
        data.insert(data.begin(), header.begin(), header.end());
    }
    
    void mutate_nested_message(std::vector<uint8_t>& data)
    {
        // 在 payload 中嵌入另一个 RTPS 消息
        std::vector<uint8_t> inner = generate_valid_message();
        
        if (data.size() < 30) {
            data = inner;
            return;
        }
        
        // 在某个位置插入内部消息
        size_t range = data.size() - 24;
        if (range == 0) {
            data.insert(data.end(), inner.begin(), inner.end());
            return;
        }
        size_t pos = 24 + (rng_() % range);
        data.insert(data.begin() + pos, inner.begin(), inner.end());
    }
    
    // ========== DDS 攻击生成 ==========
    
    void generate_spdp_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成伪造的 SPDP 发现消息
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::DATA);
        header.flags = 0x05;
        
        // 创建假的 participant 数据
        std::vector<uint8_t> participant_data(256);
        for (auto& b : participant_data) {
            b = dist_byte_(rng_);
        }
        
        header.submessage_length = sizeof(DataSubmessage) + participant_data.size();
        
        DataSubmessage data = {};
        data.reader_id = EntityIds::SPDP_BUILTIN_PARTICIPANT_READER;
        data.writer_id = EntityIds::SPDP_BUILTIN_PARTICIPANT_WRITER;
        data.writer_sn.low = 1;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(&data);
        message.insert(message.end(), data_ptr, data_ptr + sizeof(data));
        
        message.insert(message.end(), participant_data.begin(), participant_data.end());
    }
    
    void generate_heartbeat_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成大量心跳消息
        for (int i = 0; i < 10; ++i) {
            SubmessageHeader header = {};
            header.submessage_id = static_cast<uint8_t>(SubmessageKind::HEARTBEAT);
            header.flags = 0x03;  // E=1, F=1
            header.submessage_length = sizeof(HeartbeatSubmessage);
            
            HeartbeatSubmessage hb = {};
            hb.reader_id = EntityIds::UNKNOWN;
            hb.writer_id = generate_random_entity_id();
            hb.first_sn.low = 1;
            hb.last_sn.low = 0xFFFFFFFF;  // 声称有大量数据
            hb.count = i;
            
            const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
            message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
            
            const uint8_t* hb_ptr = reinterpret_cast<const uint8_t*>(&hb);
            message.insert(message.end(), hb_ptr, hb_ptr + sizeof(hb));
        }
    }
    
    void generate_gap_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成 GAP 消息声称大量数据丢失
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::GAP);
        header.flags = 0x01;
        header.submessage_length = sizeof(GapSubmessage) + 32;  // 带有 bitmap
        
        GapSubmessage gap = {};
        gap.reader_id = EntityIds::UNKNOWN;
        gap.writer_id = generate_random_entity_id();
        gap.gap_start.low = 1;
        gap.gap_list_base.low = 1000000;  // 声称巨大间隙
        gap.gap_list_num_bits = 256;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* gap_ptr = reinterpret_cast<const uint8_t*>(&gap);
        message.insert(message.end(), gap_ptr, gap_ptr + sizeof(gap));
        
        // 添加 bitmap
        for (int i = 0; i < 32; ++i) {
            message.push_back(0xFF);
        }
    }
    
    void generate_data_injection(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 注入伪造的数据消息
        append_data_submessage(message);
        
        // 使用合法的 writer ID 但是假数据
        if (message.size() >= 32) {
            // 覆盖 writer_id 为内置 writer
            memcpy(&message[28], &EntityIds::SEDP_BUILTIN_PUBLICATIONS_WRITER, sizeof(EntityId));
        }
    }
    
    void generate_seqnum_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成带有异常序列号的消息
        append_data_submessage(message);
        
        if (message.size() >= 40) {
            // 设置异常序列号
            SequenceNumber bad_sn;
            bad_sn.high = -1;  // 负数高位
            bad_sn.low = 0xFFFFFFFF;  // 最大低位
            memcpy(&message[32], &bad_sn, sizeof(bad_sn));
        }
    }
    
    void generate_replay_attack(std::vector<uint8_t>& message)
    {
        // 生成看起来像重放的消息
        std::vector<uint8_t> original = generate_valid_message();
        
        // 复制消息多次
        for (int i = 0; i < 5; ++i) {
            message.insert(message.end(), original.begin(), original.end());
        }
    }
    
    void generate_fragment_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成 DATA_FRAG 消息
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::DATA_FRAG);
        header.flags = 0x05;
        header.submessage_length = 36 + 100;  // DataFrag header + payload
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        // DataFrag 结构
        uint16_t extra_flags = 0;
        uint16_t octets_to_inline_qos = 28;
        EntityId reader_id = EntityIds::UNKNOWN;
        EntityId writer_id = generate_random_entity_id();
        SequenceNumber writer_sn = {0, 1};
        uint32_t fragment_starting_num = 1;
        uint16_t fragments_in_submessage = 100;  // 声称有很多分片
        uint16_t fragment_size = 1024;
        uint32_t sample_size = 1024 * 1024;  // 声称总大小 1MB
        
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&extra_flags), 
                      reinterpret_cast<uint8_t*>(&extra_flags) + 2);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&octets_to_inline_qos), 
                      reinterpret_cast<uint8_t*>(&octets_to_inline_qos) + 2);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&reader_id), 
                      reinterpret_cast<uint8_t*>(&reader_id) + 4);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&writer_id), 
                      reinterpret_cast<uint8_t*>(&writer_id) + 4);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&writer_sn), 
                      reinterpret_cast<uint8_t*>(&writer_sn) + 8);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&fragment_starting_num), 
                      reinterpret_cast<uint8_t*>(&fragment_starting_num) + 4);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&fragments_in_submessage), 
                      reinterpret_cast<uint8_t*>(&fragments_in_submessage) + 2);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&fragment_size), 
                      reinterpret_cast<uint8_t*>(&fragment_size) + 2);
        message.insert(message.end(), reinterpret_cast<uint8_t*>(&sample_size), 
                      reinterpret_cast<uint8_t*>(&sample_size) + 4);
        
        // 添加 payload
        for (int i = 0; i < 100; ++i) {
            message.push_back(dist_byte_(rng_));
        }
    }
    
    void generate_qos_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成带有畸形 inline QoS 的 DATA 消息
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::DATA);
        header.flags = 0x07;  // E=1, Q=1 (has inline QoS), D=1
        header.submessage_length = sizeof(DataSubmessage) + 100;
        
        DataSubmessage data = {};
        data.extra_flags = 0;
        data.octets_to_inline_qos = 16;
        data.reader_id = EntityIds::UNKNOWN;
        data.writer_id = generate_random_entity_id();
        data.writer_sn.low = 1;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        const uint8_t* data_ptr = reinterpret_cast<const uint8_t*>(&data);
        message.insert(message.end(), data_ptr, data_ptr + sizeof(data));
        
        // 添加畸形 QoS 参数
        // Parameter ID (2 bytes) + Length (2 bytes) + Value
        for (int i = 0; i < 5; ++i) {
            uint16_t param_id = rng_() % 0x8000;  // 随机参数 ID
            uint16_t length = (rng_() % 64) * 4;  // 必须是 4 的倍数
            
            message.push_back(param_id & 0xFF);
            message.push_back((param_id >> 8) & 0xFF);
            message.push_back(length & 0xFF);
            message.push_back((length >> 8) & 0xFF);
            
            for (int j = 0; j < length && message.size() < 1000; ++j) {
                message.push_back(dist_byte_(rng_));
            }
        }
        
        // 添加终止参数
        uint16_t sentinel_id = 0x0001;  // PID_SENTINEL
        uint16_t sentinel_length = 0;
        message.push_back(sentinel_id & 0xFF);
        message.push_back((sentinel_id >> 8) & 0xFF);
        message.push_back(sentinel_length & 0xFF);
        message.push_back((sentinel_length >> 8) & 0xFF);
    }
    
    void generate_security_attack(std::vector<uint8_t>& message)
    {
        append_header(message);
        
        // 生成伪造的安全子消息
        SubmessageHeader header = {};
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::SEC_PREFIX);
        header.flags = 0x01;
        header.submessage_length = 64;
        
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&header);
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        // 添加伪造的安全数据
        for (int i = 0; i < 64; ++i) {
            message.push_back(dist_byte_(rng_));
        }
        
        // 添加 SEC_BODY
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::SEC_BODY);
        header.submessage_length = 128;
        
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        for (int i = 0; i < 128; ++i) {
            message.push_back(dist_byte_(rng_));
        }
        
        // 添加 SEC_POSTFIX
        header.submessage_id = static_cast<uint8_t>(SubmessageKind::SEC_POSTFIX);
        header.submessage_length = 32;
        
        message.insert(message.end(), hdr_ptr, hdr_ptr + sizeof(header));
        
        for (int i = 0; i < 32; ++i) {
            message.push_back(dist_byte_(rng_));
        }
    }
};

} // namespace dds_fuzzing

#endif // RTPS_PROTOCOL_FUZZER_HPP_

