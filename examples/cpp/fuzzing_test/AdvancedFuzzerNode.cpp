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
#include <iomanip>
#include <mutex>
#include <map>
#include <atomic>
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
// 网络响应特征 (参考 AFL-Net / Boofuzz 设计)
// ============================================================================

/**
 * @brief DDS 协议状态枚举（用于状态机覆盖率追踪）
 * 参考 StateAFL 的状态引导模糊测试思想
 */
enum class DDSProtocolState {
    INITIAL = 0,           // 初始状态
    DISCOVERING,           // 发现中
    MATCHED,              // 已匹配
    COMMUNICATING,        // 通信中
    WAITING_ACK,          // 等待确认
    ACK_RECEIVED,         // 收到确认
    NACK_RECEIVED,        // 收到否认
    HEARTBEAT_SENT,       // 心跳已发送
    DISCONNECTED,         // 断开连接
    ERROR_STATE,          // 错误状态
    TIMEOUT,              // 超时
    NUM_STATES            // 状态数量
};

/**
 * @brief 网络响应特征结构
 * 
 * 这是网络协议模糊测试的核心：不是追踪代码覆盖率，
 * 而是追踪目标系统的"响应行为覆盖率"。
 * 
 * 参考工具：
 * - Boofuzz: 基于响应差异的模糊测试
 * - AFL-Net: 基于响应码和状态的网络模糊测试
 * - StateAFL: 基于协议状态机的模糊测试
 */
struct NetworkResponseProfile {
    // === 第一层：DDS API 响应 ===
    ReturnCode_t write_result = RETCODE_OK;   // write() 返回码
    int matched_count = 0;                     // 当前匹配的订阅者数量
    int matched_count_change = 0;              // 匹配数量变化
    bool publication_matched_changed = false;  // 匹配状态是否变化
    
    // === 第二层：时间特征（重要！AFL-Net的关键指标）===
    uint64_t response_time_us = 0;            // 响应时间（微秒）
    int timing_bucket = 0;                    // 时间分桶（0-5）
    bool timeout_occurred = false;            // 是否超时
    
    // === 第三层：连接/系统状态 ===
    bool connection_alive = true;             // 连接是否存活
    bool connection_dropped = false;          // 连接是否断开（崩溃指标）
    bool target_responsive = true;            // 目标是否响应
    
    // === 第四层：协议状态（StateAFL 思想）===
    DDSProtocolState current_state = DDSProtocolState::INITIAL;
    DDSProtocolState previous_state = DDSProtocolState::INITIAL;
    bool state_changed = false;               // 状态是否变化
    
    // === 第五层：错误分类 ===
    int error_code = 0;                       // 错误码
    bool is_crash = false;                    // 是否崩溃
    bool is_hang = false;                     // 是否挂起
    
    // 计算响应时间分桶（用于区分快/慢响应，检测性能问题）
    static int compute_timing_bucket(uint64_t time_us) {
        if (time_us < 1000) return 0;          // <1ms: 极快
        if (time_us < 10000) return 1;         // 1-10ms: 快
        if (time_us < 100000) return 2;        // 10-100ms: 正常
        if (time_us < 1000000) return 3;       // 100ms-1s: 慢
        if (time_us < 5000000) return 4;       // 1-5s: 很慢
        return 5;                              // >5s: 超时/挂起
    }
};

/**
 * @brief 网络响应覆盖率追踪器
 * 
 * 实现了业界成熟的网络模糊测试算法：
 * 1. 响应哈希去重（Boofuzz 风格）
 * 2. 状态转换追踪（StateAFL 风格）
 * 3. 响应时间分桶（AFL-Net 风格）
 * 4. 多维度覆盖率位图（AFL 风格）
 */
class CoverageTracker {
public:
    static constexpr size_t BITMAP_SIZE = 65536;
    static constexpr size_t STATE_COUNT = static_cast<size_t>(DDSProtocolState::NUM_STATES);
    
    CoverageTracker() 
        : bitmap_(BITMAP_SIZE, 0)
        , virgin_bitmap_(BITMAP_SIZE, 0)
        , last_state_(DDSProtocolState::INITIAL)
        , last_matched_count_(0)
    {
    }
    
    /**
     * @brief 记录一个覆盖点（底层方法）
     */
    void record_hit(size_t id)
    {
        size_t idx = id % bitmap_.size();
        if (bitmap_[idx] < 255) {
            bitmap_[idx]++;
        }
    }
    
    /**
     * @brief 记录完整的网络响应特征
     * 
     * 这是核心方法：将多维度的响应特征映射到覆盖率位图
     */
    void record_response(const NetworkResponseProfile& profile)
    {
        // ========================================
        // 1. 基本响应特征哈希（Boofuzz 风格）
        // ========================================
        size_t base_hash = compute_response_hash(profile);
        record_hit(base_hash);
        
        // ========================================
        // 2. 状态转换边覆盖（StateAFL 风格）
        // ========================================
        // 记录状态转换边：from_state -> to_state
        if (profile.state_changed) {
            size_t from = static_cast<size_t>(profile.previous_state);
            size_t to = static_cast<size_t>(profile.current_state);
            size_t state_edge = (from << 4) | to;
            record_hit(0x10000 | state_edge);
            
            // 记录新的状态转换
            if (seen_state_transitions_.insert(state_edge).second) {
                new_state_transition_ = true;
            }
        }
        
        // ========================================
        // 3. 响应时间分桶（AFL-Net 风格）
        // ========================================
        record_hit(0x20000 | profile.timing_bucket);
        
        // 时间异常检测
        if (profile.timing_bucket >= 4) {  // 慢响应
            record_hit(0x28000 | profile.timing_bucket);
        }
        
        // ========================================
        // 4. 匹配状态变化（DDS 特定）
        // ========================================
        if (profile.matched_count_change != 0) {
            // 匹配数量变化是重要的行为特征
            int change_bucket = std::min(std::abs(profile.matched_count_change), 7);
            int direction = profile.matched_count_change > 0 ? 1 : 0;
            record_hit(0x30000 | (direction << 8) | change_bucket);
        }
        
        // ========================================
        // 5. 错误码分类（重要的行为差异）
        // ========================================
        if (profile.error_code != 0) {
            // 不同的错误码意味着不同的代码路径
            record_hit(0x40000 | (profile.error_code & 0xFFFF));
            
            // 按错误类型分类
            int error_category = categorize_error(profile.error_code);
            record_hit(0x48000 | error_category);
        }
        
        // ========================================
        // 6. 异常行为（崩溃/挂起检测）
        // ========================================
        if (profile.connection_dropped) {
            record_hit(0x50000);  // 连接断开（可能崩溃）
        }
        if (profile.timeout_occurred) {
            record_hit(0x50001);  // 超时（可能挂起）
        }
        if (!profile.target_responsive) {
            record_hit(0x50002);  // 目标无响应
        }
        
        // ========================================
        // 7. 响应内容哈希去重（如果需要）
        // ========================================
        size_t full_profile_hash = compute_full_hash(profile);
        if (seen_response_hashes_.insert(full_profile_hash).second) {
            new_unique_response_ = true;
            unique_responses_count_++;
        }
    }
    
    /**
     * @brief 兼容旧接口的方法
     */
    void record_response_features(
        bool success,
        size_t response_size,
        int error_code)
    {
        NetworkResponseProfile profile;
        profile.write_result = success ? RETCODE_OK : RETCODE_ERROR;
        profile.error_code = error_code;
        profile.response_time_us = 0;
        profile.timing_bucket = 0;
        record_response(profile);
    }
    
    /**
     * @brief 检查是否发现了新覆盖
     */
    bool has_new_coverage()
    {
        bool new_coverage = false;
        
        // 检查位图中的新覆盖点
        for (size_t i = 0; i < bitmap_.size(); ++i) {
            if (bitmap_[i] > 0 && virgin_bitmap_[i] == 0) {
                virgin_bitmap_[i] = 1;
                new_coverage = true;
            }
        }
        
        // 合并其他新发现
        if (new_state_transition_) {
            new_coverage = true;
            new_state_transition_ = false;
        }
        if (new_unique_response_) {
            new_coverage = true;
            new_unique_response_ = false;
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
    
    /**
     * @brief 获取状态转换覆盖率
     */
    double get_state_coverage() const
    {
        // 理论上最多 NUM_STATES * NUM_STATES 种转换
        size_t max_transitions = STATE_COUNT * STATE_COUNT;
        return static_cast<double>(seen_state_transitions_.size()) / max_transitions;
    }
    
    /**
     * @brief 获取唯一响应数量
     */
    size_t get_unique_responses() const
    {
        return unique_responses_count_;
    }
    
    /**
     * @brief 打印详细统计
     */
    void print_detailed_stats() const
    {
        std::cout << "\n--- Coverage Details ---" << std::endl;
        std::cout << "  Bitmap coverage points: " << get_covered_count() << std::endl;
        std::cout << "  State transitions seen: " << seen_state_transitions_.size() 
                  << " (" << std::fixed << std::setprecision(1) 
                  << (get_state_coverage() * 100) << "%)" << std::endl;
        std::cout << "  Unique response patterns: " << unique_responses_count_ << std::endl;
        std::cout << "  Unique response hashes: " << seen_response_hashes_.size() << std::endl;
        
        // 多节点统计
        if (!per_node_responses_.empty()) {
            std::cout << "\n--- Per-Node Coverage ---" << std::endl;
            for (const auto& pair : per_node_responses_) {
                std::cout << "  Node " << pair.first.substr(0, 16) << "..."
                          << " | unique responses: " << pair.second.size() << std::endl;
            }
        }
    }
    
    // ========================================
    // 多节点覆盖率追踪 (支持同时测试多个目标)
    // ========================================
    
    /**
     * @brief 记录多节点响应特征
     * 
     * 当同时向多个节点发送模糊测试数据时，分别追踪每个节点的响应
     */
    void record_multi_node_response(
        const std::vector<std::string>& disconnected_nodes,
        const std::vector<std::string>& new_nodes,
        size_t alive_count,
        size_t total_count)
    {
        // 1. 记录节点连接变化（重要的行为特征）
        for (const auto& node_id : disconnected_nodes) {
            // 节点断开 = 可能崩溃
            size_t node_hash = std::hash<std::string>{}(node_id);
            record_hit(0x60000 | (node_hash % 0x1000));  // 节点断开事件
            
            // 标记此节点的状态转换
            record_node_state_change(node_id, DDSProtocolState::DISCONNECTED);
            
            crashed_nodes_.insert(node_id);
        }
        
        for (const auto& node_id : new_nodes) {
            size_t node_hash = std::hash<std::string>{}(node_id);
            record_hit(0x68000 | (node_hash % 0x1000));  // 新节点连接事件
        }
        
        // 2. 记录存活节点比例变化
        int alive_bucket = static_cast<int>((alive_count * 10) / std::max(total_count, size_t(1)));
        record_hit(0x70000 | alive_bucket);
    }
    
    /**
     * @brief 记录单个节点的响应（用于多节点场景）
     */
    void record_node_response(const std::string& node_id, const NetworkResponseProfile& profile)
    {
        // 1. 计算此节点的响应哈希
        size_t node_hash = std::hash<std::string>{}(node_id);
        size_t response_hash = compute_full_hash(profile);
        size_t combined_hash = node_hash ^ response_hash;
        
        // 2. 检查此节点是否有新的响应模式
        auto& node_responses = per_node_responses_[node_id];
        if (node_responses.insert(response_hash).second) {
            // 此节点发现新的响应模式
            record_hit(0x78000 | (combined_hash % 0x8000));
            new_unique_response_ = true;
        }
        
        // 3. 记录此节点的状态转换
        record_node_state_change(node_id, profile.current_state);
    }
    
    /**
     * @brief 获取已崩溃的节点
     */
    const std::set<std::string>& get_crashed_nodes() const
    {
        return crashed_nodes_;
    }
    
    /**
     * @brief 获取每节点覆盖率
     */
    size_t get_per_node_coverage(const std::string& node_id) const
    {
        auto it = per_node_responses_.find(node_id);
        if (it != per_node_responses_.end()) {
            return it->second.size();
        }
        return 0;
    }

private:
    std::vector<uint8_t> bitmap_;
    std::vector<uint8_t> virgin_bitmap_;
    
    // 状态追踪
    DDSProtocolState last_state_;
    int last_matched_count_;
    
    // 去重集合
    std::set<size_t> seen_response_hashes_;
    std::set<size_t> seen_state_transitions_;
    
    // 新发现标记
    bool new_state_transition_ = false;
    bool new_unique_response_ = false;
    size_t unique_responses_count_ = 0;
    
    // 多节点追踪
    std::map<std::string, std::set<size_t>> per_node_responses_;      // 每节点的响应哈希集合
    std::map<std::string, DDSProtocolState> per_node_states_;         // 每节点的当前状态
    std::map<std::string, std::set<size_t>> per_node_state_edges_;    // 每节点的状态转换边
    std::set<std::string> crashed_nodes_;                              // 已崩溃的节点
    
    /**
     * @brief 记录节点状态变化
     */
    void record_node_state_change(const std::string& node_id, DDSProtocolState new_state)
    {
        DDSProtocolState old_state = DDSProtocolState::INITIAL;
        auto it = per_node_states_.find(node_id);
        if (it != per_node_states_.end()) {
            old_state = it->second;
        }
        
        if (old_state != new_state) {
            // 记录此节点的状态转换
            size_t from = static_cast<size_t>(old_state);
            size_t to = static_cast<size_t>(new_state);
            size_t edge = (from << 4) | to;
            
            auto& node_edges = per_node_state_edges_[node_id];
            if (node_edges.insert(edge).second) {
                // 新的状态转换
                new_state_transition_ = true;
            }
            
            per_node_states_[node_id] = new_state;
        }
    }
    
    /**
     * @brief 计算响应特征的快速哈希
     */
    size_t compute_response_hash(const NetworkResponseProfile& profile) const
    {
        size_t h = 0;
        h ^= static_cast<size_t>(profile.write_result) * 2654435761;
        h ^= static_cast<size_t>(profile.timing_bucket) << 8;
        h ^= static_cast<size_t>(profile.matched_count) << 12;
        h ^= static_cast<size_t>(profile.error_code) << 16;
        h ^= (profile.connection_dropped ? 1UL : 0UL) << 24;
        h ^= (profile.timeout_occurred ? 1UL : 0UL) << 25;
        return h % BITMAP_SIZE;
    }
    
    /**
     * @brief 计算完整响应的哈希（用于去重）
     */
    size_t compute_full_hash(const NetworkResponseProfile& profile) const
    {
        std::hash<size_t> hasher;
        size_t h = 17;
        h = h * 31 + hasher(static_cast<size_t>(profile.write_result));
        h = h * 31 + hasher(static_cast<size_t>(profile.timing_bucket));
        h = h * 31 + hasher(static_cast<size_t>(profile.matched_count));
        h = h * 31 + hasher(static_cast<size_t>(profile.current_state));
        h = h * 31 + hasher(static_cast<size_t>(profile.error_code));
        h = h * 31 + hasher(profile.connection_dropped ? 1 : 0);
        h = h * 31 + hasher(profile.timeout_occurred ? 1 : 0);
        return h;
    }
    
    /**
     * @brief 错误码分类
     */
    int categorize_error(int error_code) const
    {
        // 将错误码映射到类别，便于追踪
        if (error_code == 0) return 0;              // 无错误
        if (error_code == static_cast<int>(RETCODE_ERROR)) return 1;
        if (error_code == static_cast<int>(RETCODE_UNSUPPORTED)) return 2;
        if (error_code == static_cast<int>(RETCODE_BAD_PARAMETER)) return 3;
        if (error_code == static_cast<int>(RETCODE_PRECONDITION_NOT_MET)) return 4;
        if (error_code == static_cast<int>(RETCODE_OUT_OF_RESOURCES)) return 5;
        if (error_code == static_cast<int>(RETCODE_NOT_ENABLED)) return 6;
        if (error_code == static_cast<int>(RETCODE_TIMEOUT)) return 7;
        if (error_code == static_cast<int>(RETCODE_NO_DATA)) return 8;
        if (error_code < 0) return 15;              // 系统错误
        return 16;                                   // 未知错误
    }
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
     * @brief 处理测试结果（增强版 - 使用完整响应特征）
     * 
     * 这是网络模糊测试的核心：基于响应特征判断是否发现新行为
     * 参考: AFL-Net, Boofuzz, StateAFL
     */
    void process_result(
        const std::vector<uint8_t>& input,
        const NetworkResponseProfile& profile)
    {
        // 记录完整的响应特征
        coverage_.record_response(profile);
        
        // 检查新覆盖
        bool new_coverage = coverage_.has_new_coverage();
        
        if (new_coverage) {
            // 发现新覆盖/新响应模式，保存到语料库
            seed_queue_.add_seed(input);
            new_findings_++;
            
            // 更新当前种子的能量
            if (current_seed_) {
                seed_queue_.update_energy(current_seed_, true);
            }
            
            Logger::instance().log(LogLevel::DEBUG, "COVERAGE",
                "New coverage found! Unique responses: " + 
                std::to_string(coverage_.get_unique_responses()));
        }
        
        // 检测崩溃
        if (profile.is_crash || profile.connection_dropped) {
            crashes_++;
            save_crash(input);
            Logger::instance().log(LogLevel::CRITICAL, "CRASH",
                "Crash detected! Total crashes: " + std::to_string(crashes_));
        }
        
        // 检测挂起
        if (profile.is_hang || profile.timeout_occurred || 
            profile.response_time_us > 5000000) {
            hangs_++;
            save_hang(input);
            Logger::instance().log(LogLevel::WARNING, "HANG",
                "Hang detected! Response time: " + 
                std::to_string(profile.response_time_us / 1000) + "ms");
        }
        
        // 重置覆盖率追踪
        coverage_.reset_current();
    }
    
    /**
     * @brief 处理测试结果（多节点版本）
     * 
     * 支持同时向多个目标节点发送模糊测试数据
     */
    void process_result(
        const std::vector<uint8_t>& input,
        const NetworkResponseProfile& profile,
        const std::vector<std::string>& disconnected_nodes,
        const std::vector<std::string>& new_nodes,
        size_t alive_count,
        size_t total_count)
    {
        // 1. 记录基本响应特征
        coverage_.record_response(profile);
        
        // 2. 记录多节点事件
        coverage_.record_multi_node_response(disconnected_nodes, new_nodes, 
                                             alive_count, total_count);
        
        // 3. 检查新覆盖
        bool new_coverage = coverage_.has_new_coverage();
        
        if (new_coverage) {
            seed_queue_.add_seed(input);
            new_findings_++;
            
            if (current_seed_) {
                seed_queue_.update_energy(current_seed_, true);
            }
        }
        
        // 4. 处理崩溃节点（每个断开的节点都可能是崩溃）
        for (const auto& node_id : disconnected_nodes) {
            node_crashes_++;
            save_node_crash(input, node_id);
            
            Logger::instance().log(LogLevel::CRITICAL, "MULTI_CRASH",
                "Node crash detected: " + node_id.substr(0, 16) + "...");
        }
        
        // 5. 全局崩溃检测（所有节点都断开）
        if (alive_count == 0 && total_count > 0) {
            crashes_++;
            save_crash(input);
            Logger::instance().log(LogLevel::CRITICAL, "CRASH",
                "All target nodes crashed!");
        }
        
        // 6. 挂起检测
        if (profile.is_hang || profile.timeout_occurred) {
            hangs_++;
            save_hang(input);
        }
        
        // 重置覆盖率追踪
        coverage_.reset_current();
    }
    
    /**
     * @brief 处理测试结果（兼容旧接口）
     */
    void process_result(
        const std::vector<uint8_t>& input,
        bool success,
        int error_code,
        uint64_t exec_time_us)
    {
        // 构建响应特征（从旧参数）
        NetworkResponseProfile profile;
        profile.write_result = success ? RETCODE_OK : RETCODE_ERROR;
        profile.error_code = error_code;
        profile.response_time_us = exec_time_us;
        profile.timing_bucket = NetworkResponseProfile::compute_timing_bucket(exec_time_us);
        profile.timeout_occurred = (exec_time_us > 5000000);
        profile.connection_dropped = (!success && error_code == -1);
        profile.is_crash = profile.connection_dropped;
        profile.is_hang = profile.timeout_occurred;
        
        // 调用增强版
        process_result(input, profile);
    }
    
    /**
     * @brief 打印统计信息
     */
    void print_stats() const
    {
        std::cout << "\n========== Advanced Fuzzer Statistics ==========" << std::endl;
        std::cout << "  Iterations: " << iterations_ << std::endl;
        std::cout << "  Corpus size: " << seed_queue_.size() << std::endl;
        std::cout << "  New findings: " << new_findings_ << std::endl;
        std::cout << "  Crashes found: " << crashes_ << std::endl;
        std::cout << "  Hangs found: " << hangs_ << std::endl;
        std::cout << "  Mode: " << mode_to_string(mode_) << std::endl;
        std::cout << "\n--- Response Coverage (AFL-Net/Boofuzz style) ---" << std::endl;
        std::cout << "  Bitmap coverage points: " << coverage_.get_covered_count() << std::endl;
        std::cout << "  Unique response patterns: " << coverage_.get_unique_responses() << std::endl;
        std::cout << "  State transition coverage: " << std::fixed << std::setprecision(1) 
                  << (coverage_.get_state_coverage() * 100) << "%" << std::endl;
        
        // 多节点统计
        if (node_crashes_ > 0) {
            std::cout << "\n--- Multi-Node Statistics ---" << std::endl;
            std::cout << "  Individual node crashes: " << node_crashes_ << std::endl;
            std::cout << "  Crashed nodes: " << coverage_.get_crashed_nodes().size() << std::endl;
        }
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
    uint64_t new_findings_ = 0;    // 新发现的响应模式数
    uint64_t node_crashes_ = 0;    // 单节点崩溃计数（多节点模式）
    
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
    
    /**
     * @brief 保存导致特定节点崩溃的输入（多节点模式）
     */
    void save_node_crash(const std::vector<uint8_t>& input, const std::string& node_id)
    {
        // 创建目录（如果不存在）
        system("mkdir -p output/node_crashes");
        
        // 使用节点ID的短哈希作为文件名的一部分
        std::string short_id = node_id.substr(0, 8);
        std::string filename = "output/node_crashes/node_" + short_id + 
                               "_crash_" + std::to_string(node_crashes_) + ".bin";
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(input.data()), input.size());
            Logger::instance().log(LogLevel::CRITICAL, "FUZZER", 
                "Node crash saved to: " + filename);
        }
        
        // 同时保存节点信息
        std::string info_filename = "output/node_crashes/node_" + short_id + 
                                    "_crash_" + std::to_string(node_crashes_) + ".info";
        std::ofstream info_file(info_filename);
        if (info_file) {
            info_file << "Node ID: " << node_id << "\n";
            info_file << "Crash number: " << node_crashes_ << "\n";
            info_file << "Input size: " << input.size() << " bytes\n";
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
// 多节点响应追踪 (支持同时向多个目标节点发送模糊测试)
// ============================================================================

/**
 * @brief 单个目标节点的状态
 */
struct TargetNodeState {
    std::string node_id;                          // 节点标识（GUID 字符串）
    DDSProtocolState protocol_state = DDSProtocolState::INITIAL;
    bool is_alive = true;
    uint64_t last_response_time_us = 0;
    uint32_t message_count = 0;
    uint32_t error_count = 0;
    uint32_t timeout_count = 0;
    std::chrono::steady_clock::time_point last_seen;
    
    TargetNodeState() : last_seen(std::chrono::steady_clock::now()) {}
    explicit TargetNodeState(const std::string& id) 
        : node_id(id), last_seen(std::chrono::steady_clock::now()) {}
};

/**
 * @brief 多节点响应特征
 */
struct MultiNodeResponseProfile : public NetworkResponseProfile {
    std::string target_node_id;                   // 目标节点 ID
    std::vector<std::string> disconnected_nodes; // 本次断开的节点列表
    std::vector<std::string> new_nodes;          // 本次新连接的节点列表
    size_t total_targets = 0;                    // 总目标节点数
    size_t alive_targets = 0;                    // 存活节点数
};

// ============================================================================
// DataWriter Listener (增强版 - 支持多节点追踪)
// ============================================================================

class AdvancedFuzzerListener : public DataWriterListener
{
public:
    AdvancedFuzzerListener() : matched_(0) {}
    
    void on_publication_matched(
            DataWriter* /*writer*/,
            const PublicationMatchedStatus& info) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        
        // 从 info 获取订阅者的 GUID
        std::string node_id = guid_to_string(info.last_subscription_handle);
        
        if (info.current_count_change == 1) {
            // 新节点连接
            matched_++;
            TargetNodeState state(node_id);
            state.is_alive = true;
            state.protocol_state = DDSProtocolState::MATCHED;
            node_states_[node_id] = state;
            recent_new_nodes_.push_back(node_id);
            
            std::cout << "Subscriber matched! Node: " << node_id 
                      << ", Total: " << matched_ << std::endl;
                      
            Logger::instance().log(LogLevel::INFO, "MULTI_NODE",
                "New target node connected: " + node_id);
                
        } else if (info.current_count_change == -1) {
            // 节点断开
            matched_--;
            if (node_states_.count(node_id) > 0) {
                node_states_[node_id].is_alive = false;
                node_states_[node_id].protocol_state = DDSProtocolState::DISCONNECTED;
            }
            recent_disconnected_nodes_.push_back(node_id);
            
            std::cout << "Subscriber disconnected! Node: " << node_id 
                      << ", Total: " << matched_ << std::endl;
                      
            Logger::instance().log(LogLevel::WARNING, "MULTI_NODE",
                "Target node disconnected: " + node_id + " (possible crash!)");
        }
    }
    
    int get_matched() const { return matched_.load(); }
    
    /**
     * @brief 获取所有节点状态
     */
    std::map<std::string, TargetNodeState> get_node_states() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return node_states_;
    }
    
    /**
     * @brief 获取存活节点数
     */
    size_t get_alive_count() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& pair : node_states_) {
            if (pair.second.is_alive) count++;
        }
        return count;
    }
    
    /**
     * @brief 获取并清除最近断开的节点
     */
    std::vector<std::string> pop_disconnected_nodes()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result = std::move(recent_disconnected_nodes_);
        recent_disconnected_nodes_.clear();
        return result;
    }
    
    /**
     * @brief 获取并清除最近连接的节点
     */
    std::vector<std::string> pop_new_nodes()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> result = std::move(recent_new_nodes_);
        recent_new_nodes_.clear();
        return result;
    }
    
    /**
     * @brief 更新节点的响应统计
     */
    void update_node_response(const std::string& node_id, uint64_t response_time_us, bool is_error)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (node_states_.count(node_id) > 0) {
            auto& state = node_states_[node_id];
            state.message_count++;
            state.last_response_time_us = response_time_us;
            state.last_seen = std::chrono::steady_clock::now();
            if (is_error) {
                state.error_count++;
            }
            if (response_time_us > 5000000) {
                state.timeout_count++;
            }
        }
    }
    
    /**
     * @brief 检查并标记超时节点
     */
    std::vector<std::string> check_timeout_nodes(uint64_t timeout_ms = 10000)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> timeout_nodes;
        auto now = std::chrono::steady_clock::now();
        
        for (auto& pair : node_states_) {
            if (pair.second.is_alive) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - pair.second.last_seen).count();
                if (elapsed > static_cast<int64_t>(timeout_ms)) {
                    pair.second.protocol_state = DDSProtocolState::TIMEOUT;
                    timeout_nodes.push_back(pair.first);
                }
            }
        }
        return timeout_nodes;
    }
    
    /**
     * @brief 打印多节点统计
     */
    void print_node_stats() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "\n--- Multi-Node Statistics ---" << std::endl;
        std::cout << "  Total nodes seen: " << node_states_.size() << std::endl;
        std::cout << "  Currently alive: " << get_alive_count_unlocked() << std::endl;
        
        for (const auto& pair : node_states_) {
            const auto& state = pair.second;
            std::cout << "  Node " << pair.first.substr(0, 16) << "..."
                      << " | alive: " << (state.is_alive ? "yes" : "NO")
                      << " | msgs: " << state.message_count
                      << " | errs: " << state.error_count
                      << " | timeouts: " << state.timeout_count
                      << std::endl;
        }
    }

private:
    std::atomic<int> matched_;
    mutable std::mutex mutex_;
    std::map<std::string, TargetNodeState> node_states_;
    std::vector<std::string> recent_disconnected_nodes_;
    std::vector<std::string> recent_new_nodes_;
    
    size_t get_alive_count_unlocked() const
    {
        size_t count = 0;
        for (const auto& pair : node_states_) {
            if (pair.second.is_alive) count++;
        }
        return count;
    }
    
    static std::string guid_to_string(const eprosima::fastdds::rtps::InstanceHandle_t& handle)
    {
        std::stringstream ss;
        ss << std::hex;
        for (size_t i = 0; i < 16; ++i) {
            ss << std::setw(2) << std::setfill('0') 
               << static_cast<int>(handle.value[i]);
        }
        return ss.str();
    }
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
            
            // ================================================
            // 收集响应特征（AFL-Net / Boofuzz 风格）
            // ================================================
            NetworkResponseProfile profile;
            int prev_matched = listener_.get_matched();
            
            if (use_network_injection_) {
                // 网络注入模式
                bool success = injector_.inject(testcase);
                profile.write_result = success ? RETCODE_OK : RETCODE_ERROR;
                
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
                profile.write_result = ret;
                profile.error_code = (ret == RETCODE_OK) ? 0 : static_cast<int>(ret);
            }
            
            auto iter_end = std::chrono::steady_clock::now();
            uint64_t exec_time = std::chrono::duration_cast<std::chrono::microseconds>(
                iter_end - iter_start).count();
            
            // ================================================
            // 填充响应特征（网络模糊测试的关键指标）
            // ================================================
            
            // 时间特征
            profile.response_time_us = exec_time;
            profile.timing_bucket = NetworkResponseProfile::compute_timing_bucket(exec_time);
            profile.timeout_occurred = (exec_time > 5000000);  // > 5s
            
            // 匹配状态变化（重要！连接断开可能意味着崩溃）
            int curr_matched = listener_.get_matched();
            profile.matched_count = curr_matched;
            profile.matched_count_change = curr_matched - prev_matched;
            profile.publication_matched_changed = (profile.matched_count_change != 0);
            
            // ================================================
            // 多节点追踪（支持同时测试多个目标节点）
            // ================================================
            auto disconnected_nodes = listener_.pop_disconnected_nodes();
            auto new_nodes = listener_.pop_new_nodes();
            
            // 记录多节点事件
            if (!disconnected_nodes.empty()) {
                for (const auto& node_id : disconnected_nodes) {
                    Logger::instance().log(LogLevel::CRITICAL, "MULTI_NODE",
                        "Node " + node_id.substr(0, 16) + "... disconnected during fuzzing!");
                    node_crash_count_++;
                }
            }
            
            // 连接状态（StateAFL 风格的状态追踪）
            profile.connection_alive = (curr_matched > 0);
            profile.connection_dropped = !disconnected_nodes.empty();  // 有任何节点断开
            profile.target_responsive = !profile.timeout_occurred;
            
            // 协议状态推断
            profile.previous_state = current_protocol_state_;
            if (profile.connection_dropped) {
                current_protocol_state_ = DDSProtocolState::DISCONNECTED;
            } else if (profile.timeout_occurred) {
                current_protocol_state_ = DDSProtocolState::TIMEOUT;
            } else if (profile.error_code != 0) {
                current_protocol_state_ = DDSProtocolState::ERROR_STATE;
            } else if (curr_matched > 0) {
                current_protocol_state_ = DDSProtocolState::COMMUNICATING;
            } else {
                current_protocol_state_ = DDSProtocolState::DISCOVERING;
            }
            profile.current_state = current_protocol_state_;
            profile.state_changed = (profile.current_state != profile.previous_state);
            
            // 崩溃/挂起检测
            profile.is_crash = !disconnected_nodes.empty();
            profile.is_hang = profile.timeout_occurred;
            
            // 处理结果（使用增强版响应特征）
            engine_.process_result(testcase, profile, disconnected_nodes, new_nodes, 
                                   listener_.get_alive_count(), listener_.get_matched());
            
            bool success = (profile.write_result == RETCODE_OK);
            
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
    
    // 协议状态追踪（StateAFL 风格）
    DDSProtocolState current_protocol_state_ = DDSProtocolState::INITIAL;
    
    // 多节点统计
    uint32_t node_crash_count_ = 0;  // 累计节点崩溃次数
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

