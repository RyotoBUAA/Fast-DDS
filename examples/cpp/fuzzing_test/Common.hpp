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
 * @file Common.hpp
 * DDS 模糊测试框架的公共定义和工具函数
 */

#ifndef FUZZING_TEST_COMMON_HPP
#define FUZZING_TEST_COMMON_HPP

#include <iostream>
#include <string>
#include <chrono>
#include <fstream>
#include <memory>
#include <atomic>

#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/topic/Topic.hpp>

// 主题名称定义
#define SIMPLE_TOPIC_NAME "SimpleTestTopic"
#define COMPLEX_TOPIC_NAME "ComplexTestTopic"
#define BOUNDARY_TOPIC_NAME "BoundaryTestTopic"

// DDS Domain ID
#define TEST_DOMAIN_ID 0

// 日志级别
enum class LogLevel
{
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

/**
 * @brief 日志记录类
 */
class Logger
{
public:
    static Logger& instance();
    
    void log(LogLevel level, const std::string& node_type, 
             const std::string& message);
    
    void log_anomaly(const std::string& anomaly_type,
                    const std::string& details);
    
    void set_log_file(const std::string& filename);
    
private:
    Logger();
    ~Logger();
    
    std::ofstream log_file_;
    std::string get_timestamp();
    std::string level_to_string(LogLevel level);
};

/**
 * @brief 异常检测器 - 监控节点使用
 */
class AnomalyDetector
{
public:
    AnomalyDetector(int monitor_id);
    
    // 检测内存异常
    void check_memory_corruption(const void* data, size_t size);
    
    // 检测数据完整性
    void check_data_integrity(const void* data, size_t expected_size, 
                             size_t actual_size);
    
    // 检测序列号异常
    void check_sequence_anomaly(uint32_t current_seq, uint32_t expected_seq);
    
    // 记录统计信息
    void record_message_received(size_t size);
    void record_error();
    
    // 获取统计信息
    void print_statistics();
    
private:
    int monitor_id_;
    std::atomic<uint64_t> messages_received_{0};
    std::atomic<uint64_t> errors_detected_{0};
    std::atomic<uint64_t> total_bytes_{0};
    std::chrono::steady_clock::time_point start_time_;
};

/**
 * @brief 性能监控器
 */
class PerformanceMonitor
{
public:
    void start_measurement();
    void end_measurement();
    double get_latency_ms();
    void print_stats();
    
private:
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point end_;
    std::vector<double> latencies_;
};

/**
 * @brief 信号处理器
 */
class SignalHandler
{
public:
    static void setup();
    static bool should_stop();
    static void trigger_stop();
    
private:
    static std::atomic<bool> stop_flag_;
    static void signal_callback(int signum);
};

#endif // FUZZING_TEST_COMMON_HPP

