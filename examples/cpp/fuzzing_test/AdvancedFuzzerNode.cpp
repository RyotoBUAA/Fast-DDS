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
 * @file AdvancedFuzzerNode.cpp
 * @brief 高级模糊测试节点 - 集成协议感知模糊测试
 * 
 * 这个文件实现了一个高级的模糊测试节点，使用：
 * 1. RTPS 协议感知的结构化模糊测试
 * 2. 基于覆盖率的变异策略（模拟）
 * 3. 种子队列和语料库管理
 * 4. 多种 DDS 攻击模式
 */

#include <iostream>
#include <thread>
#include <chrono>
#include <random>
#include <vector>
#include <cstring>
#include <sstream>
#include <fstream>
#include <deque>
#include <set>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>

#include "Common.hpp"
#include "TestMessagePubSubTypes.hpp"
#include "RTPSProtocolFuzzer.hpp"

using namespace eprosima::fastdds::dds;

// ============================================================================
// 配置常量
// ============================================================================

constexpr size_t MAX_CORPUS_SIZE = 1000;
constexpr size_t MAX_SEED_SIZE = 65536;
constexpr int RTPS_DEFAULT_PORT = 7400;
constexpr int RTPS_MULTICAST_PORT = 7401;

// ============================================================================
// 种子管理
// ============================================================================

/**
 * @brief 种子条目
 */
struct SeedEntry {
    std::vector<uint8_t> data;
    double energy;           // 能量值（用于调度）
    size_t hit_count;        // 命中次数
    size_t exec_time_us;     // 平均执行时间
    bool is_favored;         // 是否是受青睐的种子
    
    SeedEntry() : energy(1.0), hit_count(0), exec_time_us(0), is_favored(false) {}
    explicit SeedEntry(std::vector<uint8_t> d) 
        : data(std::move(d)), energy(1.0), hit_count(0), exec_time_us(0), is_favored(false) {}
};

/**
 * @brief 种子队列管理器
 */
class SeedQueue {
public:
    SeedQueue() = default;
    
    void add_seed(std::vector<uint8_t> seed)
    {
        if (seed.empty() || seed.size() > MAX_SEED_SIZE) {
            return;
        }
        
        // 计算种子哈希，避免重复
        size_t hash = compute_hash(seed);
        if (seen_hashes_.count(hash) > 0) {
            return;
        }
        
        seen_hashes_.insert(hash);
        seeds_.emplace_back(std::move(seed));
        
        // 如果超出最大大小，移除最老的种子
        while (seeds_.size() > MAX_CORPUS_SIZE) {
            seen_hashes_.erase(compute_hash(seeds_.front().data));
            seeds_.pop_front();
        }
    }
    
    SeedEntry* select_seed()
    {
        if (seeds_.empty()) {
            return nullptr;
        }
        
        // 基于能量的选择
        double total_energy = 0;
        for (const auto& seed : seeds_) {
            total_energy += seed.energy;
        }
        
        if (total_energy <= 0) {
            return &seeds_[rand() % seeds_.size()];
        }
        
        double r = static_cast<double>(rand()) / RAND_MAX * total_energy;
        double cumulative = 0;
        
        for (auto& seed : seeds_) {
            cumulative += seed.energy;
            if (cumulative >= r) {
                return &seed;
            }
        }
        
        return &seeds_.back();
    }
    
    void update_energy(SeedEntry* seed, bool found_new_coverage)
    {
        if (seed == nullptr) return;
        
        seed->hit_count++;
        
        if (found_new_coverage) {
            // 发现新覆盖，增加能量
            seed->energy = std::min(seed->energy * 2.0, 100.0);
            seed->is_favored = true;
        } else {
            // 没有新覆盖，减少能量
            seed->energy = std::max(seed->energy * 0.9, 0.1);
        }
    }
    
    size_t size() const { return seeds_.size(); }
    
    void load_from_directory(const std::string& dir)
    {
        // 简单实现：加载目录下的所有文件作为种子
        // 实际使用时需要使用 dirent.h 或 filesystem
        std::cout << "Loading seeds from: " << dir << std::endl;
    }
    
    void save_to_directory(const std::string& dir)
    {
        // 创建目录（如果不存在）
        std::string mkdir_cmd = "mkdir -p " + dir;
        system(mkdir_cmd.c_str());
        
        // 保存语料库到目录
        std::cout << "Saving corpus to: " << dir << std::endl;
        
        size_t idx = 0;
        for (const auto& seed : seeds_) {
            std::string filename = dir + "/seed_" + std::to_string(idx++) + ".bin";
            std::ofstream file(filename, std::ios::binary);
            if (file) {
                file.write(reinterpret_cast<const char*>(seed.data.data()), seed.data.size());
            }
        }
    }

private:
    std::deque<SeedEntry> seeds_;
    std::set<size_t> seen_hashes_;
    
    static size_t compute_hash(const std::vector<uint8_t>& data)
    {
        size_t hash = 0;
        for (size_t i = 0; i < data.size(); ++i) {
            hash ^= static_cast<size_t>(data[i]) << (i % 56);
            hash = (hash << 7) | (hash >> 57);
        }
        return hash;
    }
};

// ============================================================================
// 覆盖率追踪（简化版）
// ============================================================================

/**
 * @brief 简化的覆盖率追踪器
 * 
 * 注意：这是一个简化实现。真正的覆盖率追踪需要编译时插桩。
 * 这里我们使用输出特征作为覆盖率的近似。
 */
class CoverageTracker {
public:
    CoverageTracker() : bitmap_(65536, 0) {}
    
    /**
     * @brief 记录一个覆盖点
     */
    void record_hit(size_t id)
    {
        size_t idx = id % bitmap_.size();
        if (bitmap_[idx] < 255) {
            bitmap_[idx]++;
        }
    }
    
    /**
     * @brief 记录消息响应特征
     */
    void record_response_features(
        bool success,
        size_t response_size,
        int error_code)
    {
        // 将响应特征映射到覆盖点
        size_t feature_hash = (success ? 0x1000 : 0) 
                            ^ (response_size << 4) 
                            ^ (error_code << 12);
        record_hit(feature_hash);
        
        // 记录特定错误代码
        if (error_code != 0) {
            record_hit(0x8000 | error_code);
        }
    }
    
    /**
     * @brief 检查是否发现了新覆盖
     */
    bool has_new_coverage()
    {
        bool new_coverage = false;
        
        for (size_t i = 0; i < bitmap_.size(); ++i) {
            if (bitmap_[i] > 0 && virgin_bitmap_[i] == 0) {
                virgin_bitmap_[i] = 1;
                new_coverage = true;
            }
        }
        
        return new_coverage;
    }
    
    /**
     * @brief 重置当前执行的覆盖
     */
    void reset_current()
    {
        std::fill(bitmap_.begin(), bitmap_.end(), 0);
    }
    
    /**
     * @brief 获取覆盖率统计
     */
    size_t get_covered_count() const
    {
        return std::count_if(virgin_bitmap_.begin(), virgin_bitmap_.end(),
                            [](uint8_t v) { return v > 0; });
    }

private:
    std::vector<uint8_t> bitmap_;
    std::vector<uint8_t> virgin_bitmap_{std::vector<uint8_t>(65536, 0)};
};

// ============================================================================
// 高级模糊测试引擎
// ============================================================================

/**
 * @brief 高级模糊测试引擎
 */
class AdvancedFuzzEngine {
public:
    enum class Mode {
        PROTOCOL_AWARE,     // 协议感知模式
        MUTATION_BASED,     // 变异模式
        GENERATION_BASED,   // 生成模式
        ATTACK_PATTERNS,    // 攻击模式
        HYBRID              // 混合模式
    };
    
    AdvancedFuzzEngine(uint64_t seed = 0)
        : rng_(seed ? seed : std::random_device{}())
        , protocol_fuzzer_(seed)
        , mode_(Mode::HYBRID)
        , iterations_(0)
        , crashes_(0)
        , hangs_(0)
    {
        initialize_seed_corpus();
    }
    
    void set_mode(Mode mode) { mode_ = mode; }
    
    /**
     * @brief 生成下一个测试用例
     */
    std::vector<uint8_t> generate_testcase()
    {
        iterations_++;
        
        switch (mode_) {
            case Mode::PROTOCOL_AWARE:
                return generate_protocol_aware();
            case Mode::MUTATION_BASED:
                return generate_mutation_based();
            case Mode::GENERATION_BASED:
                return generate_generation_based();
            case Mode::ATTACK_PATTERNS:
                return generate_attack();
            case Mode::HYBRID:
            default:
                return generate_hybrid();
        }
    }
    
    /**
     * @brief 处理测试结果
     */
    void process_result(
        const std::vector<uint8_t>& input,
        bool success,
        int error_code,
        uint64_t exec_time_us)
    {
        // 记录覆盖率特征
        coverage_.record_response_features(success, input.size(), error_code);
        
        // 检查新覆盖
        bool new_coverage = coverage_.has_new_coverage();
        
        if (new_coverage) {
            // 发现新覆盖，保存到语料库
            seed_queue_.add_seed(input);
            
            // 更新当前种子的能量
            if (current_seed_) {
                seed_queue_.update_energy(current_seed_, true);
            }
        }
        
        // 检测崩溃/挂起
        if (!success && error_code == -1) {
            crashes_++;
            save_crash(input);
        } else if (exec_time_us > 5000000) {  // 超过 5 秒
            hangs_++;
            save_hang(input);
        }
        
        // 重置覆盖率追踪
        coverage_.reset_current();
    }
    
    /**
     * @brief 打印统计信息
     */
    void print_stats() const
    {
        std::cout << "\n========== Advanced Fuzzer Statistics ==========" << std::endl;
        std::cout << "  Iterations: " << iterations_ << std::endl;
        std::cout << "  Corpus size: " << seed_queue_.size() << std::endl;
        std::cout << "  Coverage points: " << coverage_.get_covered_count() << std::endl;
        std::cout << "  Crashes found: " << crashes_ << std::endl;
        std::cout << "  Hangs found: " << hangs_ << std::endl;
        std::cout << "  Mode: " << mode_to_string(mode_) << std::endl;
        std::cout << "=================================================" << std::endl;
    }

private:
    std::mt19937_64 rng_;
    dds_fuzzing::RTPSProtocolFuzzer protocol_fuzzer_;
    SeedQueue seed_queue_;
    CoverageTracker coverage_;
    Mode mode_;
    SeedEntry* current_seed_ = nullptr;
    
    // 统计
    uint64_t iterations_;
    uint64_t crashes_;
    uint64_t hangs_;
    
    void initialize_seed_corpus()
    {
        // 添加一些初始种子
        
        // 1. 有效的 RTPS 消息
        seed_queue_.add_seed(protocol_fuzzer_.generate_valid_message());
        
        // 2. 最小有效消息（只有 header）
        std::vector<uint8_t> minimal = {'R', 'T', 'P', 'S', 2, 3, 1, 15};
        minimal.resize(20, 0);  // GUID prefix 填充 0
        seed_queue_.add_seed(minimal);
        
        // 3. 空 DATA 消息
        auto data_msg = protocol_fuzzer_.generate_valid_message();
        seed_queue_.add_seed(data_msg);
        
        // 4. 各种攻击模式的初始种子
        for (int i = 0; i < 5; ++i) {
            seed_queue_.add_seed(protocol_fuzzer_.generate_dds_attack());
        }
    }
    
    std::vector<uint8_t> generate_protocol_aware()
    {
        // 选择种子进行变异
        current_seed_ = seed_queue_.select_seed();
        
        if (current_seed_) {
            return protocol_fuzzer_.mutate(current_seed_->data);
        }
        
        return protocol_fuzzer_.generate_valid_message();
    }
    
    std::vector<uint8_t> generate_mutation_based()
    {
        current_seed_ = seed_queue_.select_seed();
        
        if (!current_seed_) {
            return protocol_fuzzer_.generate_valid_message();
        }
        
        // 多次变异
        std::vector<uint8_t> result = current_seed_->data;
        int mutations = 1 + (rng_() % 8);
        
        for (int i = 0; i < mutations; ++i) {
            result = protocol_fuzzer_.mutate(result);
        }
        
        return result;
    }
    
    std::vector<uint8_t> generate_generation_based()
    {
        return protocol_fuzzer_.generate_valid_message();
    }
    
    std::vector<uint8_t> generate_attack()
    {
        return protocol_fuzzer_.generate_dds_attack();
    }
    
    std::vector<uint8_t> generate_hybrid()
    {
        // 混合模式：根据概率选择不同策略
        int r = rng_() % 100;
        
        if (r < 30) {
            // 30%: 协议感知变异
            return generate_protocol_aware();
        } else if (r < 50) {
            // 20%: 基本变异
            return generate_mutation_based();
        } else if (r < 70) {
            // 20%: 生成
            return generate_generation_based();
        } else {
            // 30%: 攻击模式
            return generate_attack();
        }
    }
    
    void save_crash(const std::vector<uint8_t>& input)
    {
        // 创建目录（如果不存在）
        system("mkdir -p output/crashes");
        
        std::string filename = "output/crashes/crash_" + std::to_string(crashes_) + ".bin";
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(input.data()), input.size());
            Logger::instance().log(LogLevel::CRITICAL, "FUZZER", 
                "Crash saved to: " + filename);
        }
    }
    
    void save_hang(const std::vector<uint8_t>& input)
    {
        // 创建目录（如果不存在）
        system("mkdir -p output/hangs");
        
        std::string filename = "output/hangs/hang_" + std::to_string(hangs_) + ".bin";
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(input.data()), input.size());
            Logger::instance().log(LogLevel::WARNING, "FUZZER", 
                "Hang saved to: " + filename);
        }
    }
    
    static const char* mode_to_string(Mode mode)
    {
        switch (mode) {
            case Mode::PROTOCOL_AWARE: return "PROTOCOL_AWARE";
            case Mode::MUTATION_BASED: return "MUTATION_BASED";
            case Mode::GENERATION_BASED: return "GENERATION_BASED";
            case Mode::ATTACK_PATTERNS: return "ATTACK_PATTERNS";
            case Mode::HYBRID: return "HYBRID";
            default: return "UNKNOWN";
        }
    }
};

// ============================================================================
// 网络直接注入器
// ============================================================================

/**
 * @brief 直接向 RTPS 端口注入畸形数据包
 */
class RTPSInjector {
public:
    RTPSInjector(const std::string& target_ip = "127.0.0.1", int port = RTPS_DEFAULT_PORT)
        : target_ip_(target_ip)
        , target_port_(port)
        , sock_(-1)
    {
    }
    
    ~RTPSInjector()
    {
        close();
    }
    
    bool init()
    {
        sock_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock_ < 0) {
            Logger::instance().log(LogLevel::ERROR, "INJECTOR", 
                "Failed to create socket");
            return false;
        }
        
        // 设置目标地址
        memset(&target_addr_, 0, sizeof(target_addr_));
        target_addr_.sin_family = AF_INET;
        target_addr_.sin_port = htons(target_port_);
        inet_pton(AF_INET, target_ip_.c_str(), &target_addr_.sin_addr);
        
        Logger::instance().log(LogLevel::INFO, "INJECTOR", 
            "Initialized, target: " + target_ip_ + ":" + std::to_string(target_port_));
        
        return true;
    }
    
    bool inject(const std::vector<uint8_t>& data)
    {
        if (sock_ < 0 || data.empty()) {
            return false;
        }
        
        ssize_t sent = sendto(sock_, data.data(), data.size(), 0,
                             reinterpret_cast<const sockaddr*>(&target_addr_),
                             sizeof(target_addr_));
        
        return sent == static_cast<ssize_t>(data.size());
    }
    
    bool inject_to_multicast(const std::vector<uint8_t>& data)
    {
        // 向 DDS 发现多播地址发送
        sockaddr_in mcast_addr;
        memset(&mcast_addr, 0, sizeof(mcast_addr));
        mcast_addr.sin_family = AF_INET;
        mcast_addr.sin_port = htons(RTPS_MULTICAST_PORT);
        inet_pton(AF_INET, "239.255.0.1", &mcast_addr.sin_addr);  // DDS 默认多播地址
        
        ssize_t sent = sendto(sock_, data.data(), data.size(), 0,
                             reinterpret_cast<const sockaddr*>(&mcast_addr),
                             sizeof(mcast_addr));
        
        return sent == static_cast<ssize_t>(data.size());
    }
    
    void close()
    {
        if (sock_ >= 0) {
            ::close(sock_);
            sock_ = -1;
        }
    }

private:
    std::string target_ip_;
    int target_port_;
    int sock_;
    sockaddr_in target_addr_;
};

// ============================================================================
// DataWriter Listener
// ============================================================================

class AdvancedFuzzerListener : public DataWriterListener
{
public:
    AdvancedFuzzerListener() : matched_(0) {}
    
    void on_publication_matched(
            DataWriter* /*writer*/,
            const PublicationMatchedStatus& info) override
    {
        if (info.current_count_change == 1) {
            matched_++;
            std::cout << "Subscriber matched! Total: " << matched_ << std::endl;
        } else if (info.current_count_change == -1) {
            matched_--;
            std::cout << "Subscriber disconnected. Total: " << matched_ << std::endl;
        }
    }
    
    int get_matched() const { return matched_.load(); }

private:
    std::atomic<int> matched_;
};

// ============================================================================
// 高级模糊测试节点
// ============================================================================

class AdvancedFuzzerNode {
public:
    AdvancedFuzzerNode()
        : participant_(nullptr)
        , publisher_(nullptr)
        , topic_(nullptr)
        , writer_(nullptr)
        , use_network_injection_(false)
    {
    }
    
    ~AdvancedFuzzerNode()
    {
        cleanup();
    }
    
    bool init(bool use_injection = false)
    {
        use_network_injection_ = use_injection;
        
        Logger::instance().log(LogLevel::INFO, "ADV_FUZZER",
            "Initializing advanced fuzzer node...");
        
        if (use_network_injection_) {
            // 使用网络注入模式
            if (!injector_.init()) {
                return false;
            }
            Logger::instance().log(LogLevel::INFO, "ADV_FUZZER",
                "Using network injection mode");
            return true;
        }
        
        // 使用 DDS API 模式
        DomainParticipantQos pqos;
        pqos.name("AdvancedFuzzerNode");
        pqos.transport().use_builtin_transports = true;
        pqos.transport().send_socket_buffer_size = 1048576;
        pqos.transport().listen_socket_buffer_size = 1048576;
        
        participant_ = DomainParticipantFactory::get_instance()->create_participant(
            TEST_DOMAIN_ID, pqos);
        
        if (participant_ == nullptr) {
            Logger::instance().log(LogLevel::ERROR, "ADV_FUZZER",
                "Failed to create DomainParticipant");
            return false;
        }
        
        TypeSupport type(new SimpleTestMessagePubSubType());
        type.register_type(participant_);
        
        topic_ = participant_->create_topic(
            SIMPLE_TOPIC_NAME,
            type.get_type_name(),
            TOPIC_QOS_DEFAULT);
        
        if (topic_ == nullptr) {
            Logger::instance().log(LogLevel::ERROR, "ADV_FUZZER",
                "Failed to create Topic");
            return false;
        }
        
        publisher_ = participant_->create_publisher(PUBLISHER_QOS_DEFAULT);
        if (publisher_ == nullptr) {
            Logger::instance().log(LogLevel::ERROR, "ADV_FUZZER",
                "Failed to create Publisher");
            return false;
        }
        
        DataWriterQos wqos = DATAWRITER_QOS_DEFAULT;
        wqos.reliability().kind = BEST_EFFORT_RELIABILITY_QOS;
        wqos.durability().kind = VOLATILE_DURABILITY_QOS;
        wqos.history().kind = KEEP_LAST_HISTORY_QOS;
        wqos.history().depth = 1;
        
        writer_ = publisher_->create_datawriter(topic_, wqos, &listener_);
        if (writer_ == nullptr) {
            Logger::instance().log(LogLevel::ERROR, "ADV_FUZZER",
                "Failed to create DataWriter");
            return false;
        }
        
        Logger::instance().log(LogLevel::INFO, "ADV_FUZZER",
            "Advanced fuzzer node initialized successfully");
        return true;
    }
    
    void run(uint32_t iterations = 10000, uint32_t interval_ms = 50)
    {
        Logger::instance().log(LogLevel::INFO, "ADV_FUZZER",
            "Starting advanced fuzzing test with " + std::to_string(iterations) + " iterations");
        
        // 等待订阅者（如果使用 DDS 模式）
        if (!use_network_injection_) {
            std::cout << "Waiting for subscribers to match..." << std::endl;
            std::cout.flush();
            
            int wait_count = 0;
            while (listener_.get_matched() == 0 && !SignalHandler::should_stop()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                wait_count++;
                if (wait_count % 5 == 0) {
                    std::cout << "Still waiting for subscribers... (" << wait_count << "s)" << std::endl;
                    std::cout.flush();
                }
                if (wait_count > 30) {
                    std::cout << "Warning: No subscribers found after 30 seconds, continuing anyway..." << std::endl;
                    break;
                }
            }
            
            if (listener_.get_matched() > 0) {
                std::cout << "Found " << listener_.get_matched() << " subscriber(s), starting to send messages..." << std::endl;
            }
            std::cout.flush();
        }
        
        uint32_t sent = 0;
        uint32_t failed = 0;
        
        auto start_time = std::chrono::steady_clock::now();
        
        std::cout << "Entering main loop..." << std::endl;
        std::cout.flush();
        
        for (uint32_t i = 0; i < iterations && !SignalHandler::should_stop(); ++i) {
            if (i % 100 == 0) {
                std::cout << "Iteration " << i << "..." << std::endl;
                std::cout.flush();
            }
            
            auto iter_start = std::chrono::steady_clock::now();
            
            // 生成测试用例
            std::vector<uint8_t> testcase;
            try {
                testcase = engine_.generate_testcase();
            } catch (const std::exception& e) {
                std::cerr << "Exception in generate_testcase: " << e.what() << std::endl;
                continue;
            } catch (...) {
                std::cerr << "Unknown exception in generate_testcase" << std::endl;
                continue;
            }
            
            if (testcase.empty()) {
                std::cerr << "Warning: empty testcase at iteration " << i << std::endl;
            }
            
            bool success = false;
            int error_code = 0;
            
            if (use_network_injection_) {
                // 网络注入模式
                success = injector_.inject(testcase);
                
                // 也注入到多播地址
                if (i % 10 == 0) {
                    injector_.inject_to_multicast(testcase);
                }
            } else {
                // DDS API 模式 - 需要将 testcase 转换为消息
                SimpleTestMessage msg;
                msg.seq_num(i);
                
                // 将 testcase 的一部分用作消息内容
                if (!testcase.empty()) {
                    size_t content_len = std::min(testcase.size(), size_t(1000));
                    std::string content(reinterpret_cast<const char*>(testcase.data()), content_len);
                    msg.message(content);
                    msg.data_type(testcase[0]);
                } else {
                    msg.message("empty testcase");
                    msg.data_type(0);
                }
                
                ReturnCode_t ret = writer_->write(&msg);
                success = (ret == RETCODE_OK);
                error_code = success ? 0 : static_cast<int>(ret);
            }
            
            auto iter_end = std::chrono::steady_clock::now();
            uint64_t exec_time = std::chrono::duration_cast<std::chrono::microseconds>(
                iter_end - iter_start).count();
            
            // 处理结果
            engine_.process_result(testcase, success, error_code, exec_time);
            
            if (success) {
                sent++;
            } else {
                failed++;
            }
            
            // 定期打印进度
            if (i > 0 && i % 1000 == 0) {
                auto now = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(now - start_time).count();
                double rate = i / elapsed;
                
                std::stringstream ss;
                ss << "Progress: " << i << "/" << iterations 
                   << " (" << static_cast<int>(rate) << " exec/s)"
                   << ", sent: " << sent << ", failed: " << failed;
                Logger::instance().log(LogLevel::INFO, "ADV_FUZZER", ss.str());
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
        
        // 打印最终统计
        auto end_time = std::chrono::steady_clock::now();
        double total_time = std::chrono::duration<double>(end_time - start_time).count();
        
        std::stringstream ss;
        ss << "Fuzzing completed in " << total_time << " seconds\n"
           << "  Total iterations: " << sent + failed << "\n"
           << "  Successful: " << sent << "\n"
           << "  Failed: " << failed << "\n"
           << "  Rate: " << (sent + failed) / total_time << " exec/s";
        Logger::instance().log(LogLevel::INFO, "ADV_FUZZER", ss.str());
        
        engine_.print_stats();
    }
    
    void set_mode(AdvancedFuzzEngine::Mode mode)
    {
        engine_.set_mode(mode);
    }

private:
    void cleanup()
    {
        if (participant_ != nullptr) {
            participant_->delete_contained_entities();
            DomainParticipantFactory::get_instance()->delete_participant(participant_);
        }
        injector_.close();
    }
    
    DomainParticipant* participant_;
    Publisher* publisher_;
    Topic* topic_;
    DataWriter* writer_;
    AdvancedFuzzerListener listener_;
    
    AdvancedFuzzEngine engine_;
    RTPSInjector injector_;
    bool use_network_injection_;
};

// ============================================================================
// 主函数
// ============================================================================

void print_usage(const char* prog)
{
    std::cout << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  -n, --iterations N   Number of iterations (default: 10000)\n"
              << "  -i, --interval MS    Interval in milliseconds (default: 50)\n"
              << "  -m, --mode MODE      Fuzzing mode:\n"
              << "                         protocol - Protocol-aware fuzzing\n"
              << "                         mutation - Mutation-based fuzzing\n"
              << "                         generation - Generation-based fuzzing\n"
              << "                         attack - Attack pattern generation\n"
              << "                         hybrid - Hybrid mode (default)\n"
              << "  --inject             Use network injection mode\n"
              << "  -t, --target IP      Target IP for injection (default: 127.0.0.1)\n"
              << "  -p, --port PORT      Target port for injection (default: 7400)\n"
              << "  -h, --help           Show this help message\n";
}

int main(int argc, char** argv)
{
    std::cout << "========================================" << std::endl;
    std::cout << "  DDS Advanced Fuzzing Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // 默认参数
    uint32_t iterations = 10000;
    uint32_t interval_ms = 50;
    AdvancedFuzzEngine::Mode mode = AdvancedFuzzEngine::Mode::HYBRID;
    bool use_injection = false;
    
    // 简单的命令行解析
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if ((arg == "-n" || arg == "--iterations") && i + 1 < argc) {
            iterations = std::atoi(argv[++i]);
        } else if ((arg == "-i" || arg == "--interval") && i + 1 < argc) {
            interval_ms = std::atoi(argv[++i]);
        } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            std::string mode_str = argv[++i];
            if (mode_str == "protocol") {
                mode = AdvancedFuzzEngine::Mode::PROTOCOL_AWARE;
            } else if (mode_str == "mutation") {
                mode = AdvancedFuzzEngine::Mode::MUTATION_BASED;
            } else if (mode_str == "generation") {
                mode = AdvancedFuzzEngine::Mode::GENERATION_BASED;
            } else if (mode_str == "attack") {
                mode = AdvancedFuzzEngine::Mode::ATTACK_PATTERNS;
            } else {
                mode = AdvancedFuzzEngine::Mode::HYBRID;
            }
        } else if (arg == "--inject") {
            use_injection = true;
        }
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Iterations: " << iterations << std::endl;
    std::cout << "  Interval: " << interval_ms << " ms" << std::endl;
    std::cout << "  Mode: ";
    switch (mode) {
        case AdvancedFuzzEngine::Mode::PROTOCOL_AWARE: std::cout << "PROTOCOL_AWARE"; break;
        case AdvancedFuzzEngine::Mode::MUTATION_BASED: std::cout << "MUTATION_BASED"; break;
        case AdvancedFuzzEngine::Mode::GENERATION_BASED: std::cout << "GENERATION_BASED"; break;
        case AdvancedFuzzEngine::Mode::ATTACK_PATTERNS: std::cout << "ATTACK_PATTERNS"; break;
        default: std::cout << "HYBRID"; break;
    }
    std::cout << std::endl;
    std::cout << "  Injection mode: " << (use_injection ? "enabled" : "disabled") << std::endl;
    
    // 创建必要的目录
    system("mkdir -p output/crashes output/hangs output/corpus");
    
    // 设置日志文件
    Logger::instance().set_log_file("output/advanced_fuzzer.log");
    
    // 设置信号处理
    SignalHandler::setup();
    
    // 创建并运行高级模糊测试节点
    AdvancedFuzzerNode node;
    node.set_mode(mode);
    
    if (!node.init(use_injection)) {
        std::cerr << "Failed to initialize advanced fuzzer node" << std::endl;
        return EXIT_FAILURE;
    }
    
    node.run(iterations, interval_ms);
    
    Logger::instance().log(LogLevel::INFO, "MAIN",
        "Advanced fuzzer node shutdown complete");
    return EXIT_SUCCESS;
}

