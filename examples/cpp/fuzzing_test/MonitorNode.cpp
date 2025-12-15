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
 * 监控节点实现 - 接收消息，让 ASAN/UBSAN 检测 DDS 底层错误
 * 
 * 注意：此节点不做任何应用层检测，只是简单接收消息。
 * 真正的错误检测由 ASAN/UBSAN 在 DDS 底层（序列化/反序列化、
 * 内存管理、协议处理）自动完成。
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
 * 
 * 只做最基本的消息接收，不做任何应用层检测。
 * 让 ASAN/UBSAN 检测 DDS 底层的内存和未定义行为错误。
 */
class MonitorListener : public DataReaderListener
{
public:
    MonitorListener(int monitor_id)
        : monitor_id_(monitor_id)
        , messages_received_(0)
        , total_bytes_(0)
        , start_time_(std::chrono::steady_clock::now())
    {
        std::stringstream ss;
        ss << "Monitor-" << monitor_id_;
        node_name_ = ss.str();
        
        Logger::instance().log(LogLevel::INFO, node_name_,
                              "Listener initialized (passive mode - no app-level checks)");
    }

    ~MonitorListener() override
    {
        print_statistics();
    }

    void on_data_available(DataReader* reader) override
    {
        SimpleTestMessage msg;
        SampleInfo info;

        // 循环读取所有可用消息 - DDS 底层会在这里进行反序列化
        // 如果底层有内存问题，ASAN/UBSAN 会在此处检测到
        while (reader->take_next_sample(&msg, &info) == RETCODE_OK)
        {
            if (info.valid_data)
            {
                process_message(msg);
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
    /**
     * @brief 处理接收到的消息 - 只做统计，不做任何检测
     * 
     * 消息在到达这里之前，已经经过了 DDS 底层的完整处理：
     * - RTPS 协议解析
     * - CDR 反序列化  
     * - 内存分配和复制
     * 
     * 如果这些底层操作有问题，ASAN/UBSAN 会自动报告。
     */
    void process_message(const SimpleTestMessage& msg)
    {
        messages_received_++;
        
        // 获取消息内容 - 这会触发 DDS 内部的字符串处理
        // 不做任何检查，只是正常使用数据
        const std::string& message_str = msg.message();
        total_bytes_ += message_str.size();
        
        // 每 100 条消息打印一次进度
        if (messages_received_ % 100 == 0)
        {
            std::stringstream ss;
            ss << "Progress: " << messages_received_ << " messages received, "
               << total_bytes_ << " bytes total";
            Logger::instance().log(LogLevel::INFO, node_name_, ss.str());
        }
    }

    void print_statistics()
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - start_time_).count();
        
        std::stringstream ss;
        ss << "\n========== Statistics for " << node_name_ << " ==========";
        ss << "\n  Runtime: " << elapsed << " seconds";
        ss << "\n  Messages received: " << messages_received_;
        ss << "\n  Total bytes: " << total_bytes_;
        
        if (elapsed > 0)
        {
            ss << "\n  Messages/sec: " 
               << static_cast<double>(messages_received_) / elapsed;
            ss << "\n  Throughput: "
               << static_cast<double>(total_bytes_) / elapsed / 1024 / 1024
               << " MB/s";
        }
        
        ss << "\n  ASAN/UBSAN errors: Check stderr for any sanitizer reports";
        ss << "\n==================================================";
        
        Logger::instance().log(LogLevel::INFO, node_name_, ss.str());
    }

    int monitor_id_;
    std::string node_name_;
    uint64_t messages_received_;
    uint64_t total_bytes_;
    std::chrono::steady_clock::time_point start_time_;
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

