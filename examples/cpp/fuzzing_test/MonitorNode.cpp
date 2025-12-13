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
 * @file MonitorNode.cpp
 * 监控节点实现 - 接收消息并检测异常
 * 配合 ASAN/UBSAN 检测内存和未定义行为错误
 */

#include <iostream>
#include <thread>
#include <chrono>
#include <sstream>

#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/subscriber/qos/DataReaderQos.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "Common.hpp"
#include "TestMessagePubSubTypes.hpp"

using namespace eprosima::fastdds::dds;

#ifndef MONITOR_ID
#define MONITOR_ID 1
#endif

/**
 * @brief 监控节点的数据读取监听器
 */
class MonitorListener : public DataReaderListener
{
public:
    MonitorListener(int monitor_id)
        : monitor_id_(monitor_id)
        , detector_(monitor_id)
        , expected_seq_(0)
    {
        std::stringstream ss;
        ss << "Monitor-" << monitor_id_;
        node_name_ = ss.str();
        
        Logger::instance().log(LogLevel::INFO, node_name_,
                              "Listener initialized");
    }

    ~MonitorListener() override
    {
        detector_.print_statistics();
    }

    void on_data_available(DataReader* reader) override
    {
        SimpleTestMessage simple_msg;
        SampleInfo info;

        // 尝试读取简单消息
        if (reader->take_next_sample(&simple_msg, &info) == RETCODE_OK)
        {
            if (info.valid_data)
            {
                process_simple_message(simple_msg);
            }
        }
    }

    void on_subscription_matched(
            DataReader* /*reader*/,
            const SubscriptionMatchedStatus& info) override
    {
        if (info.current_count_change == 1)
        {
            Logger::instance().log(LogLevel::INFO, node_name_,
                                  "Matched with publisher");
        }
        else if (info.current_count_change == -1)
        {
            Logger::instance().log(LogLevel::WARNING, node_name_,
                                  "Publisher disconnected");
        }
    }

private:
    void process_simple_message(const SimpleTestMessage& msg)
    {
        // 记录接收到的消息
        detector_.record_message_received(sizeof(msg));

        // 检测序列号异常
        detector_.check_sequence_anomaly(msg.seq_num(), expected_seq_);
        expected_seq_ = msg.seq_num() + 1;

        // 检测消息内容
        std::string message_str = msg.message();
        
        // 检测可能的内存问题（超过 5KB 视为大消息）
        if (message_str.size() > 5000)
        {
            std::stringstream ss;
            ss << "Message size " << message_str.size() << " bytes exceeds expected bounds";
            Logger::instance().log_anomaly("LARGE_MESSAGE", ss.str());
            detector_.record_error();
        }

        // 检测特殊字符或格式错误
        for (char c : message_str)
        {
            if (c < 0 || c > 127)
            {
                Logger::instance().log_anomaly("INVALID_CHAR",
                    "Non-ASCII character detected in message");
                detector_.record_error();
                break;
            }
        }

        // 检测数据类型字段
        uint8_t data_type = msg.data_type();
        if (data_type > 100)  // 假设有效范围是 0-100
        {
            std::stringstream ss;
            ss << "Invalid data_type value: " << static_cast<int>(data_type);
            Logger::instance().log_anomaly("INVALID_DATA_TYPE", ss.str());
            detector_.record_error();
        }

        // 定期打印统计信息
        if (msg.seq_num() % 100 == 0)
        {
            std::stringstream ss;
            ss << "Received message #" << msg.seq_num()
               << " (type=" << static_cast<int>(data_type) << ")";
            Logger::instance().log(LogLevel::INFO, node_name_, ss.str());
        }

        // 模拟一些可能触发 ASAN/UBSAN 的操作（用于测试）
        #ifdef __DEBUG
        // 边界检查（如果 fuzzer 发送畸形数据，这里可能触发 sanitizer）
        if (message_str.length() > 0)
        {
            // 安全的访问
            volatile char first_char = message_str[0];
            (void)first_char;  // 避免未使用警告
        }
        #endif
    }

    int monitor_id_;
    std::string node_name_;
    AnomalyDetector detector_;
    uint32_t expected_seq_;
};

/**
 * @brief 监控节点类
 */
class MonitorNode
{
public:
    MonitorNode(int monitor_id)
        : monitor_id_(monitor_id)
        , participant_(nullptr)
        , subscriber_(nullptr)
        , topic_(nullptr)
        , reader_(nullptr)
        , listener_(monitor_id)
    {
        std::stringstream ss;
        ss << "Monitor-" << monitor_id_;
        node_name_ = ss.str();
    }

    ~MonitorNode()
    {
        cleanup();
    }

    bool init()
    {
        Logger::instance().log(LogLevel::INFO, node_name_,
                              "Initializing monitor node...");

        // 创建 DomainParticipant
        DomainParticipantQos pqos;
        pqos.name(node_name_);
        
        // 增加传输层最大消息大小（默认是 65KB，增加到 1MB）
        pqos.transport().use_builtin_transports = true;
        pqos.transport().send_socket_buffer_size = 1048576;  // 1MB
        pqos.transport().listen_socket_buffer_size = 1048576;  // 1MB
        
        participant_ = DomainParticipantFactory::get_instance()->create_participant(
            TEST_DOMAIN_ID, pqos);
        
        if (participant_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, node_name_,
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
            Logger::instance().log(LogLevel::ERROR, node_name_,
                                  "Failed to create Topic");
            return false;
        }

        // 创建 Subscriber
        subscriber_ = participant_->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
        if (subscriber_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, node_name_,
                                  "Failed to create Subscriber");
            return false;
        }

        // 创建 DataReader
        DataReaderQos rqos = DATAREADER_QOS_DEFAULT;
        
        // 使用 BEST_EFFORT 模式，与 Publisher 匹配
        rqos.reliability().kind = BEST_EFFORT_RELIABILITY_QOS;
        rqos.durability().kind = VOLATILE_DURABILITY_QOS;
        
        // 使用 KEEP_LAST，接收端可以设置大一些
        rqos.history().kind = KEEP_LAST_HISTORY_QOS;
        rqos.history().depth = 50;  // 接收端缓冲更多消息
        
        // 设置资源限制
        rqos.resource_limits().max_samples = 100;
        rqos.resource_limits().max_instances = 1;
        rqos.resource_limits().max_samples_per_instance = 100;
        
        // 支持大型 payload
        rqos.endpoint().history_memory_policy = 
            eprosima::fastdds::rtps::PREALLOCATED_WITH_REALLOC_MEMORY_MODE;

        reader_ = subscriber_->create_datareader(topic_, rqos, &listener_);
        if (reader_ == nullptr)
        {
            Logger::instance().log(LogLevel::ERROR, node_name_,
                                  "Failed to create DataReader");
            return false;
        }

        Logger::instance().log(LogLevel::INFO, node_name_,
                              "Monitor node initialized successfully");
        return true;
    }

    void run()
    {
        Logger::instance().log(LogLevel::INFO, node_name_,
                              "Monitor node running...");
        
        // 主循环 - 等待接收数据
        while (!SignalHandler::should_stop())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        Logger::instance().log(LogLevel::INFO, node_name_,
                              "Monitor node stopping...");
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

    int monitor_id_;
    std::string node_name_;
    DomainParticipant* participant_;
    Subscriber* subscriber_;
    Topic* topic_;
    DataReader* reader_;
    MonitorListener listener_;
};

/**
 * @brief 主函数
 */
int main(int /*argc*/, char** /*argv*/)
{
    std::cout << "========================================" << std::endl;
    std::cout << "  DDS Fuzzing Test - Monitor Node " << MONITOR_ID << std::endl;
    
    #ifdef __SANITIZE_ADDRESS__
    std::cout << "  ASAN: ENABLED" << std::endl;
    #endif
    
    #ifdef __SANITIZE_UNDEFINED__
    std::cout << "  UBSAN: ENABLED" << std::endl;
    #endif
    
    std::cout << "========================================" << std::endl;

    // 设置日志文件
    std::stringstream log_filename;
    log_filename << "output/monitor_node_" << MONITOR_ID << ".log";
    Logger::instance().set_log_file(log_filename.str());

    // 设置信号处理
    SignalHandler::setup();

    // 创建并运行监控节点
    MonitorNode node(MONITOR_ID);
    
    if (!node.init())
    {
        std::cerr << "Failed to initialize monitor node" << std::endl;
        return EXIT_FAILURE;
    }

    node.run();

    Logger::instance().log(LogLevel::INFO, "MAIN",
                          "Monitor node shutdown complete");
    return EXIT_SUCCESS;
}

