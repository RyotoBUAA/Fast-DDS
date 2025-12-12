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
 * @file Common.cpp
 * 公共功能实现
 */

#include "Common.hpp"
#include <csignal>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <numeric>
#include <algorithm>

// ============================================================================
// Logger 实现
// ============================================================================

Logger& Logger::instance()
{
    static Logger instance;
    return instance;
}

Logger::Logger()
{
    // 默认日志文件
    log_file_.open("fuzzing_test.log", std::ios::app);
}

Logger::~Logger()
{
    if (log_file_.is_open())
    {
        log_file_.close();
    }
}

void Logger::set_log_file(const std::string& filename)
{
    if (log_file_.is_open())
    {
        log_file_.close();
    }
    log_file_.open(filename, std::ios::app);
}

std::string Logger::get_timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return ss.str();
}

std::string Logger::level_to_string(LogLevel level)
{
    switch (level)
    {
        case LogLevel::INFO: return "INFO";
        case LogLevel::WARNING: return "WARN";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::CRITICAL: return "CRIT";
        default: return "UNKNOWN";
    }
}

void Logger::log(LogLevel level, const std::string& node_type,
                const std::string& message)
{
    std::stringstream ss;
    ss << "[" << get_timestamp() << "] "
       << "[" << level_to_string(level) << "] "
       << "[" << node_type << "] "
       << message;
    
    std::string log_line = ss.str();
    std::cout << log_line << std::endl;
    
    if (log_file_.is_open())
    {
        log_file_ << log_line << std::endl;
        log_file_.flush();
    }
}

void Logger::log_anomaly(const std::string& anomaly_type,
                        const std::string& details)
{
    std::stringstream ss;
    ss << "!!! ANOMALY DETECTED !!! Type: " << anomaly_type
       << ", Details: " << details;
    log(LogLevel::CRITICAL, "DETECTOR", ss.str());
}

// ============================================================================
// AnomalyDetector 实现
// ============================================================================

AnomalyDetector::AnomalyDetector(int monitor_id)
    : monitor_id_(monitor_id)
    , start_time_(std::chrono::steady_clock::now())
{
    std::stringstream ss;
    ss << "Monitor-" << monitor_id_;
    Logger::instance().log(LogLevel::INFO, ss.str(), 
                          "Anomaly detector initialized");
}

void AnomalyDetector::check_memory_corruption(const void* data, size_t size)
{
    if (data == nullptr)
    {
        Logger::instance().log_anomaly("NULL_POINTER", 
            "Received null pointer in data");
        errors_detected_++;
        return;
    }
    
    // 简单的内存边界检查
    // 在实际使用中，ASAN/UBSAN 会自动检测更多问题
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    
    // 检查是否全是相同字节（可能是未初始化内存）
    bool all_same = true;
    for (size_t i = 1; i < std::min(size, size_t(16)); ++i)
    {
        if (bytes[i] != bytes[0])
        {
            all_same = false;
            break;
        }
    }
    
    if (all_same && size > 16)
    {
        std::stringstream ss;
        ss << "Possible uninitialized memory, size: " << size;
        Logger::instance().log_anomaly("MEMORY_PATTERN", ss.str());
    }
}

void AnomalyDetector::check_data_integrity(const void* data, 
                                          size_t expected_size,
                                          size_t actual_size)
{
    if (expected_size != actual_size)
    {
        std::stringstream ss;
        ss << "Size mismatch - Expected: " << expected_size
           << ", Actual: " << actual_size;
        Logger::instance().log_anomaly("SIZE_MISMATCH", ss.str());
        errors_detected_++;
    }
    
    check_memory_corruption(data, actual_size);
}

void AnomalyDetector::check_sequence_anomaly(uint32_t current_seq,
                                            uint32_t expected_seq)
{
    if (current_seq != expected_seq)
    {
        std::stringstream ss;
        ss << "Sequence number anomaly - Expected: " << expected_seq
           << ", Got: " << current_seq
           << ", Gap: " << static_cast<int64_t>(current_seq - expected_seq);
        Logger::instance().log_anomaly("SEQUENCE_ANOMALY", ss.str());
        errors_detected_++;
    }
}

void AnomalyDetector::record_message_received(size_t size)
{
    messages_received_++;
    total_bytes_ += size;
}

void AnomalyDetector::record_error()
{
    errors_detected_++;
}

void AnomalyDetector::print_statistics()
{
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - start_time_).count();
    
    std::stringstream ss;
    ss << "Monitor-" << monitor_id_;
    std::string node_name = ss.str();
    
    ss.str("");
    ss << "\n========== Statistics for " << node_name << " ==========";
    ss << "\n  Runtime: " << elapsed << " seconds";
    ss << "\n  Messages received: " << messages_received_;
    ss << "\n  Total bytes: " << total_bytes_;
    ss << "\n  Errors detected: " << errors_detected_;
    
    if (elapsed > 0)
    {
        ss << "\n  Messages/sec: " 
           << static_cast<double>(messages_received_) / elapsed;
        ss << "\n  Throughput: "
           << static_cast<double>(total_bytes_) / elapsed / 1024 / 1024
           << " MB/s";
    }
    
    if (messages_received_ > 0)
    {
        ss << "\n  Error rate: "
           << static_cast<double>(errors_detected_) * 100 / messages_received_
           << "%";
    }
    ss << "\n==================================================";
    
    Logger::instance().log(LogLevel::INFO, node_name, ss.str());
}

// ============================================================================
// PerformanceMonitor 实现
// ============================================================================

void PerformanceMonitor::start_measurement()
{
    start_ = std::chrono::steady_clock::now();
}

void PerformanceMonitor::end_measurement()
{
    end_ = std::chrono::steady_clock::now();
    double latency = std::chrono::duration<double, std::milli>(
        end_ - start_).count();
    latencies_.push_back(latency);
}

double PerformanceMonitor::get_latency_ms()
{
    if (latencies_.empty()) return 0.0;
    return latencies_.back();
}

void PerformanceMonitor::print_stats()
{
    if (latencies_.empty())
    {
        std::cout << "No latency data collected" << std::endl;
        return;
    }
    
    double sum = std::accumulate(latencies_.begin(), latencies_.end(), 0.0);
    double mean = sum / latencies_.size();
    
    auto sorted = latencies_;
    std::sort(sorted.begin(), sorted.end());
    double median = sorted[sorted.size() / 2];
    double p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
    double p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
    
    std::cout << "\n========== Latency Statistics ==========" << std::endl;
    std::cout << "  Samples: " << latencies_.size() << std::endl;
    std::cout << "  Mean: " << mean << " ms" << std::endl;
    std::cout << "  Median: " << median << " ms" << std::endl;
    std::cout << "  P95: " << p95 << " ms" << std::endl;
    std::cout << "  P99: " << p99 << " ms" << std::endl;
    std::cout << "  Min: " << sorted.front() << " ms" << std::endl;
    std::cout << "  Max: " << sorted.back() << " ms" << std::endl;
    std::cout << "=========================================" << std::endl;
}

// ============================================================================
// SignalHandler 实现
// ============================================================================

std::atomic<bool> SignalHandler::stop_flag_{false};

void SignalHandler::setup()
{
    signal(SIGINT, signal_callback);
    signal(SIGTERM, signal_callback);
#ifndef _WIN32
    signal(SIGQUIT, signal_callback);
    signal(SIGHUP, signal_callback);
#endif
}

bool SignalHandler::should_stop()
{
    return stop_flag_.load();
}

void SignalHandler::trigger_stop()
{
    stop_flag_.store(true);
}

void SignalHandler::signal_callback(int signum)
{
    std::cout << "\n收到信号 " << signum << "，准备停止..." << std::endl;
    stop_flag_.store(true);
}

