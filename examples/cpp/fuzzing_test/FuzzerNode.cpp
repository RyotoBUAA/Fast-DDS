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
 * @file FuzzerNode.cpp
 * 模糊测试节点实现 - 生成并发送畸形数据包
 */

#include <iostream>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <cstring>

#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "Common.hpp"
#include "TestMessagePubSubTypes.hpp"

using namespace eprosima::fastdds::dds;

/**
 * @brief 模糊测试策略枚举
 */
enum class FuzzStrategy
{
    NORMAL,              // 正常消息（用于基线测试）
    BIT_FLIP,           // 位翻转
    BOUNDARY_VALUES,     // 边界值测试
    LARGE_PAYLOAD,       // 超大负载
    RANDOM_DATA,         // 随机数据
    SEQUENCE_CHAOS,      // 序列号混乱
    SPECIAL_CHARS,       // 特殊字符
    NULL_INJECTION,      // 空字符注入
    OVERFLOW_ATTEMPT,    // 溢出尝试
    FORMAT_STRING        // 格式字符串攻击尝试
};

/**
 * @brief 数据写入监听器
 */
class FuzzerListener : public DataWriterListener
{
public:
    FuzzerListener()
        : matched_(0)
    {
    }

    void on_publication_matched(
            DataWriter* writer,
            const PublicationMatchedStatus& info) override
    {
        if (info.current_count_change == 1)
        {
            matched_++;
            Logger::instance().log(LogLevel::INFO, "FUZZER",
                                  "Matched with subscriber");
        }
        else if (info.current_count_change == -1)
        {
            matched_--;
            Logger::instance().log(LogLevel::WARNING, "FUZZER",
                                  "Subscriber disconnected");
        }
    }

    int get_matched() const { return matched_; }

private:
    std::atomic<int> matched_;
};

/**
 * @brief 模糊测试引擎
 */
class FuzzEngine
{
public:
    FuzzEngine()
        : rng_(std::random_device{}())
        , dist_byte_(0, 255)
        , dist_strategy_(0, 9)
        , sequence_num_(0)
    {
    }

    /**
     * @brief 生成模糊测试消息
     */
    SimpleTestMessage generate_fuzzed_message()
    {
        SimpleTestMessage msg;
        
        // 随机选择模糊测试策略
        FuzzStrategy strategy = static_cast<FuzzStrategy>(dist_strategy_(rng_));
        
        switch (strategy)
        {
            case FuzzStrategy::NORMAL:
                generate_normal(msg);
                break;
            
            case FuzzStrategy::BIT_FLIP:
                generate_bit_flip(msg);
                break;
            
            case FuzzStrategy::BOUNDARY_VALUES:
                generate_boundary_values(msg);
                break;
            
            case FuzzStrategy::LARGE_PAYLOAD:
                generate_large_payload(msg);
                break;
            
            case FuzzStrategy::RANDOM_DATA:
                generate_random_data(msg);
                break;
            
            case FuzzStrategy::SEQUENCE_CHAOS:
                generate_sequence_chaos(msg);
                break;
            
            case FuzzStrategy::SPECIAL_CHARS:
                generate_special_chars(msg);
                break;
            
            case FuzzStrategy::NULL_INJECTION:
                generate_null_injection(msg);
                break;
            
            case FuzzStrategy::OVERFLOW_ATTEMPT:
                generate_overflow_attempt(msg);
                break;
            
            case FuzzStrategy::FORMAT_STRING:
                generate_format_string(msg);
                break;
        }
        
        return msg;
    }

private:
    void generate_normal(SimpleTestMessage& msg)
    {
        msg.seq_num(sequence_num_++);
        msg.message("Normal test message");
        msg.data_type(1);
    }

    void generate_bit_flip(SimpleTestMessage& msg)
    {
        msg.seq_num(sequence_num_++);
        
        // 生成正常消息然后翻转随机位
        std::string message = "Test message with bit flip";
        if (!message.empty())
        {
            size_t pos = dist_byte_(rng_) % message.length();
            size_t bit = dist_byte_(rng_) % 8;
            message[pos] ^= (1 << bit);
        }
        
        msg.message(message);
        msg.data_type(dist_byte_(rng_));
    }

    void generate_boundary_values(SimpleTestMessage& msg)
    {
        // 测试边界值
        static uint32_t boundary_values[] = {
            0, 1, 127, 128, 255, 256,
            32767, 32768, 65535, 65536,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
        };
        
        uint32_t val = boundary_values[dist_byte_(rng_) % 
                                       (sizeof(boundary_values) / sizeof(uint32_t))];
        msg.seq_num(val);
        msg.message("Boundary value test");
        msg.data_type(255);  // 最大值
    }

    void generate_large_payload(SimpleTestMessage& msg)
    {
        msg.seq_num(sequence_num_++);
        
        // 生成超大字符串（可能触发内存问题）
        size_t size = 10000 + (dist_byte_(rng_) * 100);
        std::string large_str(size, 'A');
        
        msg.message(large_str);
        msg.data_type(2);
        
        Logger::instance().log(LogLevel::INFO, "FUZZER",
                              "Generated large payload: " + 
                              std::to_string(size) + " bytes");
    }

    void generate_random_data(SimpleTestMessage& msg)
    {
        msg.seq_num(dist_byte_(rng_) | (dist_byte_(rng_) << 8) | 
                   (dist_byte_(rng_) << 16) | (dist_byte_(rng_) << 24));
        
        // 完全随机的字符串
        size_t len = 10 + (dist_byte_(rng_) % 100);
        std::string random_str;
        for (size_t i = 0; i < len; ++i)
        {
            random_str += static_cast<char>(dist_byte_(rng_));
        }
        
        msg.message(random_str);
        msg.data_type(dist_byte_(rng_));
    }

    void generate_sequence_chaos(SimpleTestMessage& msg)
    {
        // 故意打乱序列号
        static int chaos_counter = 0;
        
        switch (chaos_counter++ % 4)
        {
            case 0: msg.seq_num(0xFFFFFFFF); break;  // 最大值
            case 1: msg.seq_num(sequence_num_ + 1000); break;  // 跳跃
            case 2: msg.seq_num(sequence_num_ - 100); break;   // 回退
            case 3: msg.seq_num(0); break;  // 重置
        }
        
        msg.message("Sequence chaos test");
        msg.data_type(3);
    }

    void generate_special_chars(SimpleTestMessage& msg)
    {
        msg.seq_num(sequence_num_++);
        
        // 注入特殊字符
        std::string special = "Test\x00\x01\x02\xff\xfe\xfd";
        special += "\n\r\t\b\a";
        special += "Control chars: \x1b[31m RED \x1b[0m";
        
        msg.message(special);
        msg.data_type(4);
    }

    void generate_null_injection(SimpleTestMessage& msg)
    {
        msg.seq_num(sequence_num_++);
        
        // 在字符串中间注入空字符
        std::string with_null = "Before";
        with_null += '\0';
        with_null += "After";
        with_null += '\0';
        with_null += "End";
        
        msg.message(with_null);
        msg.data_type(5);
    }

    void generate_overflow_attempt(SimpleTestMessage& msg)
    {
        msg.seq_num(0xDEADBEEF);  // 特殊标记值
        
        // 尝试创建可能导致溢出的模式
        std::string overflow_pattern;
        for (int i = 0; i < 100; ++i)
        {
            overflow_pattern += std::to_string(i) + " ";
        }
        
        msg.message(overflow_pattern);
        msg.data_type(200);  // 超出正常范围
    }

    void generate_format_string(SimpleTestMessage& msg)
    {
        msg.seq_num(sequence_num_++);
        
        // 格式字符串测试（如果接收方不当处理可能有风险）
        msg.message("%s%s%s%s%s%s%s%s%s%s%n%n%n%n%n%n");
        msg.data_type(6);
    }

    std::mt19937 rng_;
    std::uniform_int_distribution<int> dist_byte_;
    std::uniform_int_distribution<int> dist_strategy_;
    std::atomic<uint32_t> sequence_num_;
};

/**
 * @brief 模糊测试节点类
 */
class FuzzerNode
{
public:
    FuzzerNode()
        : participant_(nullptr)
        , publisher_(nullptr)
        , topic_(nullptr)
        , writer_(nullptr)
    {
    }

    ~FuzzerNode()
    {
        cleanup();
    }

    bool init()
    {
        Logger::instance().log(LogLevel::INFO, "FUZZER",
                              "Initializing fuzzer node...");

        // 创建 DomainParticipant
        DomainParticipantQos pqos;
        pqos.name("FuzzerNode");
        
        participant_ = DomainParticipantFactory::get_instance()->create_participant(
            TEST_DOMAIN_ID, pqos);
        
        if (participant_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, "FUZZER",
                                  "Failed to create DomainParticipant");
            return false;
        }

        // 注册类型
        TypeSupport type(new SimpleTestMessagePubSubType());
        type.register_type(participant_);

        // 创建 Topic
        topic_ = participant_->create_topic(
            SIMPLE_TOPIC_NAME,
            type.get_type_name(),
            TOPIC_QOS_DEFAULT);
        
        if (topic_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, "FUZZER",
                                  "Failed to create Topic");
            return false;
        }

        // 创建 Publisher
        publisher_ = participant_->create_publisher(PUBLISHER_QOS_DEFAULT);
        if (publisher_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, "FUZZER",
                                  "Failed to create Publisher");
            return false;
        }

        // 创建 DataWriter
        DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
        wqos.reliability().kind = RELIABLE_RELIABILITY_QOS;
        wqos.durability().kind = TRANSIENT_LOCAL_DURABILITY_QOS;
        wqos.history().kind = KEEP_ALL_HISTORY_QOS;

        writer_ = publisher_->create_datawriter(topic_, wqos, &listener_);
        if (writer_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, "FUZZER",
                                  "Failed to create DataWriter");
            return false;
        }

        Logger::instance().log(LogLevel::INFO, "FUZZER",
                              "Fuzzer node initialized successfully");
        return true;
    }

    void run(uint32_t message_count = 1000, uint32_t interval_ms = 100)
    {
        Logger::instance().log(LogLevel::INFO, "FUZZER",
                              "Starting fuzzing test...");
        
        // 等待至少一个订阅者连接
        while (listener_.get_matched() == 0 && !SignalHandler::should_stop())
        {
            std::cout << "Waiting for subscribers..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        if (SignalHandler::should_stop())
        {
            return;
        }

        Logger::instance().log(LogLevel::INFO, "FUZZER",
                              "Subscribers connected, starting to send fuzzed messages");

        // 发送模糊测试消息
        uint32_t sent = 0;
        PerformanceMonitor perf_monitor;
        
        while (sent < message_count && !SignalHandler::should_stop())
        {
            perf_monitor.start_measurement();
            
            // 生成并发送模糊消息
            SimpleTestMessage msg = engine_.generate_fuzzed_message();
            
            if (writer_->write(&msg))
            {
                sent++;
                
                if (sent % 100 == 0)
                {
                    Logger::instance().log(LogLevel::INFO, "FUZZER",
                                          "Sent " + std::to_string(sent) + 
                                          " fuzzed messages");
                }
            }
            else
            {
                Logger::instance().log(LogLevel::ERROR, "FUZZER",
                                      "Failed to send message");
            }
            
            perf_monitor.end_measurement();
            
            // 控制发送速率
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }

        Logger::instance().log(LogLevel::INFO, "FUZZER",
                              "Fuzzing test completed. Total messages sent: " +
                              std::to_string(sent));
        
        perf_monitor.print_stats();
    }

private:
    void cleanup()
    {
        if (participant_ != nullptr)
        {
            participant_->delete_contained_entities();
            DomainParticipantFactory::get_instance()->delete_participant(participant_);
        }
    }

    DomainParticipant* participant_;
    Publisher* publisher_;
    Topic* topic_;
    DataWriter* writer_;
    FuzzerListener listener_;
    FuzzEngine engine_;
};

/**
 * @brief 主函数
 */
int main(int argc, char** argv)
{
    std::cout << "========================================" << std::endl;
    std::cout << "  DDS Fuzzing Test - Fuzzer Node" << std::endl;
    std::cout << "========================================" << std::endl;

    // 解析命令行参数
    uint32_t message_count = 1000;
    uint32_t interval_ms = 100;
    
    if (argc > 1)
    {
        message_count = std::atoi(argv[1]);
    }
    if (argc > 2)
    {
        interval_ms = std::atoi(argv[2]);
    }

    std::cout << "Configuration:" << std::endl;
    std::cout << "  Message count: " << message_count << std::endl;
    std::cout << "  Interval: " << interval_ms << " ms" << std::endl;

    // 设置日志文件
    Logger::instance().set_log_file("fuzzer_node.log");

    // 设置信号处理
    SignalHandler::setup();

    // 创建并运行模糊测试节点
    FuzzerNode node;
    
    if (!node.init())
    {
        std::cerr << "Failed to initialize fuzzer node" << std::endl;
        return EXIT_FAILURE;
    }

    node.run(message_count, interval_ms);

    Logger::instance().log(LogLevel::INFO, "MAIN",
                          "Fuzzer node shutdown complete");
    return EXIT_SUCCESS;
}

