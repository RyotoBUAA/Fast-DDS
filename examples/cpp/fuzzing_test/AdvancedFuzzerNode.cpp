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
 * @brief RTPS 协议层模糊测试节点 - 基于响应反馈的网络模糊测试
 * 
 * 实现了业界成熟的网络协议模糊测试技术：
 * 1. AFL-Net 风格：基于响应码和响应时间的覆盖率
 * 2. StateAFL 风格：基于协议状态机转换的覆盖率
 * 3. Boofuzz 风格：基于响应内容差异的去重
 * 4. 能量调度：优先变异有价值的种子
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
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include "Common.hpp"
#include "RTPSProtocolFuzzer.hpp"

// ============================================================================
// 配置常量
// ============================================================================

constexpr size_t MAX_CORPUS_SIZE = 1000;
constexpr size_t MAX_SEED_SIZE = 65536;

// RTPS 端口计算参数 (根据 RTPS 2.3 规范)
// 公式: port = PB + DG * domainId + offset + PG * participantId
constexpr int RTPS_PORT_BASE = 7400;           // PB
constexpr int RTPS_DOMAIN_GAIN = 250;          // DG
constexpr int RTPS_PARTICIPANT_GAIN = 2;       // PG
constexpr int RTPS_D0_SPDP_MULTICAST = 0;      // d0: SPDP multicast
constexpr int RTPS_D1_METATRAFFIC_UNICAST = 10; // d1: metatraffic unicast
constexpr int RTPS_D2_USER_MULTICAST = 1;      // d2: user data multicast
constexpr int RTPS_D3_USER_UNICAST = 11;       // d3: user data unicast

// 默认值 (domain 0)
constexpr int RTPS_SPDP_MULTICAST_PORT = 7400;     // 发现多播端口
constexpr int RTPS_USER_MULTICAST_PORT = 7401;     // 用户数据多播端口
constexpr const char* RTPS_MULTICAST_ADDR = "239.255.0.1";
constexpr int RESPONSE_TIMEOUT_MS = 100;

/**
 * @brief 计算 RTPS 端口
 */
inline int calculate_rtps_port(int domain_id, int participant_id, bool is_metatraffic, bool is_multicast)
{
    if (is_multicast) {
        if (is_metatraffic) {
            // SPDP 多播端口
            return RTPS_PORT_BASE + RTPS_DOMAIN_GAIN * domain_id + RTPS_D0_SPDP_MULTICAST;
        } else {
            // 用户数据多播端口
            return RTPS_PORT_BASE + RTPS_DOMAIN_GAIN * domain_id + RTPS_D2_USER_MULTICAST;
        }
    } else {
        if (is_metatraffic) {
            // Metatraffic 单播端口
            return RTPS_PORT_BASE + RTPS_DOMAIN_GAIN * domain_id + 
                   RTPS_D1_METATRAFFIC_UNICAST + RTPS_PARTICIPANT_GAIN * participant_id;
        } else {
            // 用户数据单播端口
            return RTPS_PORT_BASE + RTPS_DOMAIN_GAIN * domain_id + 
                   RTPS_D3_USER_UNICAST + RTPS_PARTICIPANT_GAIN * participant_id;
        }
    }
}

// ============================================================================
// RTPS 协议状态机 (StateAFL 风格)
// ============================================================================

/**
 * @brief RTPS 协议状态枚举
 * 
 * 参考 StateAFL：通过追踪协议状态转换来引导模糊测试
 * 不同的状态转换意味着触发了不同的代码路径
 */
enum class RTPSState : uint8_t {
    INITIAL = 0,            // 初始状态
    SENT_DISCOVERY,         // 发送了发现消息
    SENT_DATA,              // 发送了数据消息
    SENT_HEARTBEAT,         // 发送了心跳
    SENT_ACKNACK,           // 发送了确认
    SENT_GAP,               // 发送了间隙
    GOT_RESPONSE,           // 收到响应
    GOT_RTPS_RESPONSE,      // 收到有效 RTPS 响应
    GOT_ERROR_RESPONSE,     // 收到错误响应
    TIMEOUT,                // 超时
    TARGET_CRASHED,         // 目标崩溃
    NUM_STATES
};

/**
 * @brief 响应类型枚举
 */
enum class ResponseType : uint8_t {
    NONE = 0,
    TIMEOUT,
    VALID_RTPS,             // 有效的 RTPS 响应
    INVALID_RTPS,           // 无效的 RTPS（可能是错误处理响应）
    ICMP_UNREACHABLE,       // ICMP 不可达
    CONNECTION_REFUSED,
    SEND_ERROR,
    NUM_TYPES
};

// ============================================================================
// 种子管理 (AFL 风格能量调度)
// ============================================================================

struct SeedEntry {
    std::vector<uint8_t> data;
    double energy;              // 能量值：决定被选中的概率
    size_t exec_count;          // 执行次数
    size_t new_cov_count;       // 发现新覆盖的次数
    uint64_t avg_exec_time_us;  // 平均执行时间
    bool is_favored;            // 是否是最小化种子
    RTPSState last_state;       // 上次执行后的状态
    
    // 记录这个种子触发过的状态转换
    std::set<uint16_t> triggered_edges;
    
    SeedEntry() 
        : energy(1.0), exec_count(0), new_cov_count(0), avg_exec_time_us(0)
        , is_favored(false), last_state(RTPSState::INITIAL) {}
    
    explicit SeedEntry(std::vector<uint8_t> d) 
        : data(std::move(d)), energy(1.0), exec_count(0), new_cov_count(0)
        , avg_exec_time_us(0), is_favored(false), last_state(RTPSState::INITIAL) {}
};

/**
 * @brief 种子队列管理器 (AFL 风格)
 */
class SeedQueue {
public:
    SeedEntry* add_seed(std::vector<uint8_t> seed, bool is_interesting = true)
    {
        if (seed.empty() || seed.size() > MAX_SEED_SIZE) {
            return nullptr;
        }
        
        size_t hash = compute_hash(seed);
        if (seen_hashes_.count(hash) > 0) {
            return nullptr;  // 已存在
        }
        
        seen_hashes_.insert(hash);
        seeds_.emplace_back(std::move(seed));
        
        SeedEntry* new_seed = &seeds_.back();
        if (is_interesting) {
            new_seed->energy = 2.0;  // 有趣的种子初始能量更高
        }
        
        // 超出最大大小时移除最老的低能量种子
        while (seeds_.size() > MAX_CORPUS_SIZE) {
            remove_worst_seed();
        }
        
        return new_seed;
    }
    
    /**
     * @brief 基于能量的种子选择 (AFL 风格)
     */
    SeedEntry* select_seed()
    {
        if (seeds_.empty()) return nullptr;
        
        // 计算总能量
        double total_energy = 0;
        for (const auto& seed : seeds_) {
            total_energy += seed.energy;
        }
        
        if (total_energy <= 0) {
            return &seeds_[rand() % seeds_.size()];
        }
        
        // 轮盘赌选择
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
    
    /**
     * @brief 更新种子能量
     * 
     * 能量调度策略：
     * - 发现新覆盖：能量 x2
     * - 未发现新覆盖：能量 x0.9
     * - 触发新状态转换：额外 +0.5
     */
    void update_seed(SeedEntry* seed, bool found_new_coverage, bool found_new_state_edge)
    {
        if (!seed) return;
        
        seed->exec_count++;
        
        if (found_new_coverage) {
            seed->new_cov_count++;
            seed->energy = std::min(seed->energy * 2.0, 100.0);
            seed->is_favored = true;
        } else {
            seed->energy = std::max(seed->energy * 0.9, 0.1);
        }
        
        if (found_new_state_edge) {
            seed->energy = std::min(seed->energy + 0.5, 100.0);
        }
    }
    
    size_t size() const { return seeds_.size(); }
    
    void save_to_directory(const std::string& dir)
    {
        std::string mkdir_cmd = "mkdir -p " + dir;
        system(mkdir_cmd.c_str());
        
        size_t idx = 0;
        size_t favored_count = 0;
        
        for (const auto& seed : seeds_) {
            std::string prefix = seed.is_favored ? "fav_" : "";
            std::string filename = dir + "/" + prefix + "seed_" + std::to_string(idx++) + ".bin";
            std::ofstream file(filename, std::ios::binary);
            if (file) {
                file.write(reinterpret_cast<const char*>(seed.data.data()), seed.data.size());
            }
            if (seed.is_favored) favored_count++;
        }
        
        std::cout << "Saved " << seeds_.size() << " seeds (" << favored_count << " favored) to: " << dir << std::endl;
    }
    
    void print_stats() const
    {
        size_t favored = 0;
        double total_energy = 0;
        size_t total_new_cov = 0;
        
        for (const auto& seed : seeds_) {
            if (seed.is_favored) favored++;
            total_energy += seed.energy;
            total_new_cov += seed.new_cov_count;
        }
        
        std::cout << "  Seeds: " << seeds_.size() << " (favored: " << favored << ")" << std::endl;
        std::cout << "  Total energy: " << std::fixed << std::setprecision(1) << total_energy << std::endl;
        std::cout << "  Total new coverage discoveries: " << total_new_cov << std::endl;
    }

private:
    std::deque<SeedEntry> seeds_;
    std::set<size_t> seen_hashes_;
    
    void remove_worst_seed()
    {
        if (seeds_.empty()) return;
        
        // 找到能量最低且不是 favored 的种子
        auto worst = seeds_.begin();
        for (auto it = seeds_.begin(); it != seeds_.end(); ++it) {
            if (!it->is_favored && it->energy < worst->energy) {
                worst = it;
            }
        }
        
        seen_hashes_.erase(compute_hash(worst->data));
        seeds_.erase(worst);
    }
    
    static size_t compute_hash(const std::vector<uint8_t>& data)
    {
        size_t hash = 0x811c9dc5;  // FNV offset basis
        for (uint8_t b : data) {
            hash ^= b;
            hash *= 0x01000193;  // FNV prime
        }
        return hash;
    }
};

// ============================================================================
// 网络响应特征 (AFL-Net / Boofuzz 风格)
// ============================================================================

/**
 * @brief 网络响应特征
 * 
 * 这是网络模糊测试的核心：不追踪代码覆盖率，而是追踪响应行为
 */
struct NetworkResponseProfile {
    // === 基本响应信息 ===
    ResponseType response_type = ResponseType::NONE;
    bool send_success = false;
    int error_code = 0;
    
    // === 时间特征 (AFL-Net 关键指标) ===
    uint64_t response_time_us = 0;
    int timing_bucket = 0;  // 0-5 分桶
    
    // === 响应内容特征 (Boofuzz 风格) ===
    size_t response_size = 0;
    size_t response_hash = 0;           // 完整响应哈希
    size_t response_prefix_hash = 0;    // 前 64 字节哈希（快速比较）
    
    // === RTPS 协议特征 ===
    bool is_valid_rtps = false;
    uint8_t rtps_version_major = 0;
    uint8_t rtps_version_minor = 0;
    std::vector<uint8_t> submessage_ids;  // 响应中的 submessage 类型列表
    
    // === 状态机特征 (StateAFL 风格) ===
    RTPSState inferred_state = RTPSState::INITIAL;
    
    static int compute_timing_bucket(uint64_t time_us) {
        if (time_us < 1000) return 0;       // <1ms
        if (time_us < 10000) return 1;      // 1-10ms
        if (time_us < 100000) return 2;     // 10-100ms
        if (time_us < 1000000) return 3;    // 100ms-1s
        if (time_us < 5000000) return 4;    // 1-5s
        return 5;                            // >5s (超时/挂起)
    }
};

// ============================================================================
// 覆盖率追踪器 (AFL-Net + StateAFL 风格)
// ============================================================================

/**
 * @brief 多维度覆盖率追踪器
 * 
 * 追踪多个维度的"覆盖率"：
 * 1. 响应类型覆盖
 * 2. 响应时间分桶覆盖
 * 3. 响应内容差异覆盖 (Boofuzz)
 * 4. 状态转换边覆盖 (StateAFL)
 * 5. Submessage 序列覆盖
 */
class ResponseCoverageTracker {
public:
    static constexpr size_t BITMAP_SIZE = 65536;
    static constexpr size_t STATE_COUNT = static_cast<size_t>(RTPSState::NUM_STATES);
    
    ResponseCoverageTracker()
        : bitmap_(BITMAP_SIZE, 0)
        , virgin_bitmap_(BITMAP_SIZE, 0)
        , current_state_(RTPSState::INITIAL)
    {
    }
    
    /**
     * @brief 记录响应特征到覆盖率位图
     */
    void record_response(const NetworkResponseProfile& profile, 
                        const std::vector<uint8_t>& input)
    {
        new_coverage_found_ = false;
        new_state_edge_found_ = false;
        
        // =============================================
        // 1. 响应类型覆盖 (基础)
        // =============================================
        record_hit(static_cast<size_t>(profile.response_type));
        
        // =============================================
        // 2. 响应时间分桶覆盖 (AFL-Net 风格)
        // =============================================
        record_hit(0x100 | profile.timing_bucket);
        
        // 时间异常检测
        if (profile.timing_bucket >= 4) {
            record_hit(0x180 | profile.timing_bucket);  // 慢响应单独追踪
        }
        
        // =============================================
        // 3. 响应大小分桶覆盖
        // =============================================
        int size_bucket = 0;
        if (profile.response_size > 0) size_bucket = 1;
        if (profile.response_size > 64) size_bucket = 2;
        if (profile.response_size > 256) size_bucket = 3;
        if (profile.response_size > 1024) size_bucket = 4;
        if (profile.response_size > 4096) size_bucket = 5;
        record_hit(0x200 | size_bucket);
        
        // =============================================
        // 4. 响应内容差异覆盖 (Boofuzz 风格)
        // =============================================
        if (profile.response_hash != 0) {
            // 完整响应去重
            if (seen_response_hashes_.insert(profile.response_hash).second) {
                unique_responses_++;
                new_coverage_found_ = true;
            }
            
            // 响应前缀哈希（快速分类）
            record_hit(0x1000 | (profile.response_prefix_hash % 0x1000));
            
            // 响应哈希分桶
            record_hit(0x2000 | (profile.response_hash % 0x1000));
        }
        
        // =============================================
        // 5. 状态转换边覆盖 (StateAFL 风格)
        // =============================================
        RTPSState new_state = profile.inferred_state;
        if (new_state != current_state_) {
            // 状态转换边: from_state -> to_state
            uint16_t edge = (static_cast<uint8_t>(current_state_) << 8) | 
                           static_cast<uint8_t>(new_state);
            
            record_hit(0x4000 | edge);
            
            // 追踪新的状态转换
            if (seen_state_edges_.insert(edge).second) {
                new_state_edge_found_ = true;
                new_coverage_found_ = true;
            }
            
            current_state_ = new_state;
        }
        
        // =============================================
        // 6. RTPS Submessage 序列覆盖
        // =============================================
        if (!profile.submessage_ids.empty()) {
            // 记录 submessage 序列的哈希
            size_t seq_hash = 0;
            for (uint8_t id : profile.submessage_ids) {
                seq_hash = (seq_hash * 31) + id;
            }
            record_hit(0x8000 | (seq_hash % 0x1000));
            
            // 新的 submessage 组合
            if (seen_submsg_sequences_.insert(seq_hash).second) {
                new_coverage_found_ = true;
            }
        }
        
        // =============================================
        // 7. 输入特征 -> 响应特征 关联 (AFL-Net 风格)
        // =============================================
        // 将输入的某些特征与响应关联，追踪因果关系
        if (input.size() >= 20) {
            uint8_t input_submsg_id = (input.size() > 20) ? input[20] : 0;
            uint16_t input_response_pair = (input_submsg_id << 8) | 
                                          static_cast<uint8_t>(profile.response_type);
            record_hit(0xC000 | input_response_pair);
        }
        
        // =============================================
        // 8. 错误码覆盖
        // =============================================
        if (profile.error_code != 0) {
            int error_bucket = categorize_error(profile.error_code);
            record_hit(0xE000 | error_bucket);
        }
    }
    
    /**
     * @brief 检查是否发现了新覆盖
     */
    bool has_new_coverage()
    {
        // 检查位图中的新覆盖
        for (size_t i = 0; i < bitmap_.size(); ++i) {
            if (bitmap_[i] > 0 && virgin_bitmap_[i] == 0) {
                virgin_bitmap_[i] = 1;
                new_coverage_found_ = true;
            }
        }
        
        bool result = new_coverage_found_;
        return result;
    }
    
    bool has_new_state_edge() const { return new_state_edge_found_; }
    
    void reset_current()
    {
        std::fill(bitmap_.begin(), bitmap_.end(), 0);
    }
    
    RTPSState get_current_state() const { return current_state_; }
    
    void set_current_state(RTPSState state) { current_state_ = state; }
    
    // === 统计信息 ===
    size_t get_bitmap_coverage() const
    {
        return std::count_if(virgin_bitmap_.begin(), virgin_bitmap_.end(),
                            [](uint8_t v) { return v > 0; });
    }
    
    size_t get_unique_responses() const { return unique_responses_; }
    size_t get_state_edges() const { return seen_state_edges_.size(); }
    size_t get_submsg_sequences() const { return seen_submsg_sequences_.size(); }
    
    double get_state_coverage_percent() const
    {
        // 理论最大状态转换数
        size_t max_edges = STATE_COUNT * STATE_COUNT;
        return 100.0 * seen_state_edges_.size() / max_edges;
    }
    
    void print_stats() const
    {
        std::cout << "\n--- Response Coverage (AFL-Net/StateAFL style) ---" << std::endl;
        std::cout << "  Bitmap coverage points: " << get_bitmap_coverage() << std::endl;
        std::cout << "  Unique response patterns: " << unique_responses_ << std::endl;
        std::cout << "  State transition edges: " << seen_state_edges_.size() 
                  << " (" << std::fixed << std::setprecision(1) 
                  << get_state_coverage_percent() << "%)" << std::endl;
        std::cout << "  Submessage sequences: " << seen_submsg_sequences_.size() << std::endl;
    }

private:
    std::vector<uint8_t> bitmap_;
    std::vector<uint8_t> virgin_bitmap_;
    
    RTPSState current_state_;
    
    std::set<size_t> seen_response_hashes_;
    std::set<uint16_t> seen_state_edges_;
    std::set<size_t> seen_submsg_sequences_;
    
    size_t unique_responses_ = 0;
    bool new_coverage_found_ = false;
    bool new_state_edge_found_ = false;
    
    void record_hit(size_t id)
    {
        size_t idx = id % bitmap_.size();
        if (bitmap_[idx] < 255) {
            bitmap_[idx]++;
        }
    }
    
    static int categorize_error(int error_code)
    {
        if (error_code == ECONNREFUSED) return 1;
        if (error_code == EHOSTUNREACH) return 2;
        if (error_code == ENETUNREACH) return 3;
        if (error_code == ETIMEDOUT) return 4;
        if (error_code == ENOBUFS) return 5;
        if (error_code < 0) return 15;
        return error_code % 16;
    }
};

// ============================================================================
// RTPS 网络注入器 (增强版 - 支持多端口多目标)
// ============================================================================

/**
 * @brief 目标端点信息
 */
struct TargetEndpoint {
    sockaddr_in addr;
    int participant_id;
    bool is_metatraffic;
    std::string description;
};

/**
 * @brief RTPS 网络注入器
 * 
 * 响应检测机制：
 * 1. 主 socket：发送到目标端口，同时接收来自目标的响应
 *    （UDP 发送后，响应会返回到源端口）
 * 2. 多播监听 socket：加入 RTPS 发现多播组，监听目标的广播
 *    （目标的 SPDP 心跳等会广播到多播地址）
 * 3. 响应特征：响应时间、响应内容、是否有响应
 * 
 * 多目标支持：
 * - 自动计算多个 MonitorNode 的端口
 * - 同时向多个端点发送测试报文
 * - 支持单播和多播两种模式
 */
class RTPSInjector {
public:
    RTPSInjector(const std::string& target_ip = "127.0.0.1", 
                 int domain_id = 0,
                 int num_participants = 1)
        : target_ip_(target_ip)
        , domain_id_(domain_id)
        , num_participants_(num_participants)
        , main_sock_(-1)
        , multicast_sock_(-1)
        , target_alive_(false)
        , last_target_response_time_(std::chrono::steady_clock::now())
    {
    }
    
    ~RTPSInjector() { close(); }
    
    bool init()
    {
        // =============================================
        // 1. 主 socket：发送 + 接收响应
        // =============================================
        main_sock_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (main_sock_ < 0) {
            std::cerr << "Failed to create main socket: " << strerror(errno) << std::endl;
            return false;
        }
        
        // 绑定到固定端口（模拟一个 RTPS 参与者）
        // 使用 7500-7600 范围内的端口，避免与目标冲突
        sockaddr_in local_addr = {};
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        
        bool bound = false;
        for (int port = 7500; port < 7600; ++port) {
            local_addr.sin_port = htons(port);
            if (bind(main_sock_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) >= 0) {
                local_port_ = port;
                bound = true;
                break;
            }
        }
        
        if (!bound) {
            // 如果固定端口都被占用，使用系统分配
            local_addr.sin_port = 0;
            if (bind(main_sock_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
                std::cerr << "Failed to bind main socket" << std::endl;
                return false;
            }
            socklen_t len = sizeof(local_addr);
            getsockname(main_sock_, reinterpret_cast<sockaddr*>(&local_addr), &len);
            local_port_ = ntohs(local_addr.sin_port);
        }
        
        // 设置非阻塞
        int flags = fcntl(main_sock_, F_GETFL, 0);
        fcntl(main_sock_, F_SETFL, flags | O_NONBLOCK);
        
        // =============================================
        // 2. 构建目标端点列表 (多 MonitorNode 支持)
        // =============================================
        build_target_endpoints();
        
        // =============================================
        // 3. 多播监听 socket：监听 RTPS 发现广播
        // =============================================
        int spdp_multicast_port = calculate_rtps_port(domain_id_, 0, true, true);
        int user_multicast_port = calculate_rtps_port(domain_id_, 0, false, true);
        
        multicast_sock_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (multicast_sock_ >= 0) {
            // 允许地址重用
            int reuse = 1;
            setsockopt(multicast_sock_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
            setsockopt(multicast_sock_, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
            
            // 绑定到 SPDP 多播端口
            sockaddr_in mcast_addr = {};
            mcast_addr.sin_family = AF_INET;
            mcast_addr.sin_addr.s_addr = INADDR_ANY;
            mcast_addr.sin_port = htons(spdp_multicast_port);
            
            if (bind(multicast_sock_, reinterpret_cast<sockaddr*>(&mcast_addr), sizeof(mcast_addr)) >= 0) {
                // 加入多播组
                struct ip_mreq mreq = {};
                inet_pton(AF_INET, RTPS_MULTICAST_ADDR, &mreq.imr_multiaddr);
                mreq.imr_interface.s_addr = INADDR_ANY;
                
                if (setsockopt(multicast_sock_, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                              &mreq, sizeof(mreq)) < 0) {
                    std::cerr << "Warning: Failed to join multicast group" << std::endl;
                }
                
                // 非阻塞
                flags = fcntl(multicast_sock_, F_GETFL, 0);
                fcntl(multicast_sock_, F_SETFL, flags | O_NONBLOCK);
                
                std::cout << "Multicast listener ready on " << RTPS_MULTICAST_ADDR 
                          << ":" << spdp_multicast_port << std::endl;
            } else {
                std::cerr << "Warning: Failed to bind multicast socket" << std::endl;
                ::close(multicast_sock_);
                multicast_sock_ = -1;
            }
        }
        
        // 多播发送地址 (用户数据多播)
        memset(&multicast_user_addr_, 0, sizeof(multicast_user_addr_));
        multicast_user_addr_.sin_family = AF_INET;
        multicast_user_addr_.sin_port = htons(user_multicast_port);
        inet_pton(AF_INET, RTPS_MULTICAST_ADDR, &multicast_user_addr_.sin_addr);
        
        // SPDP 多播地址 (发现)
        memset(&multicast_spdp_addr_, 0, sizeof(multicast_spdp_addr_));
        multicast_spdp_addr_.sin_family = AF_INET;
        multicast_spdp_addr_.sin_port = htons(spdp_multicast_port);
        inet_pton(AF_INET, RTPS_MULTICAST_ADDR, &multicast_spdp_addr_.sin_addr);
        
        // 打印配置信息
        std::cout << "\n========== RTPS Fuzzer Configuration ==========" << std::endl;
        std::cout << "  Fuzzer listening on port: " << local_port_ << std::endl;
        std::cout << "  Target IP: " << target_ip_ << std::endl;
        std::cout << "  Domain ID: " << domain_id_ << std::endl;
        std::cout << "  Number of participants: " << num_participants_ << std::endl;
        std::cout << "\n  Target endpoints:" << std::endl;
        for (const auto& ep : target_endpoints_) {
            std::cout << "    - " << ep.description << std::endl;
        }
        std::cout << "\n  Multicast addresses:" << std::endl;
        std::cout << "    - SPDP: " << RTPS_MULTICAST_ADDR << ":" << spdp_multicast_port << std::endl;
        std::cout << "    - User: " << RTPS_MULTICAST_ADDR << ":" << user_multicast_port << std::endl;
        std::cout << "================================================\n" << std::endl;
        
        return true;
    }
    
    /**
     * @brief 构建目标端点列表
     * 
     * 为每个 MonitorNode 计算正确的 RTPS 端口
     */
    void build_target_endpoints()
    {
        target_endpoints_.clear();
        
        for (int pid = 0; pid < num_participants_; ++pid) {
            // Metatraffic 单播端口 (用于发现和控制消息)
            int meta_port = calculate_rtps_port(domain_id_, pid, true, false);
            TargetEndpoint meta_ep;
            meta_ep.addr.sin_family = AF_INET;
            meta_ep.addr.sin_port = htons(meta_port);
            inet_pton(AF_INET, target_ip_.c_str(), &meta_ep.addr.sin_addr);
            meta_ep.participant_id = pid;
            meta_ep.is_metatraffic = true;
            meta_ep.description = "Participant " + std::to_string(pid) + 
                                 " metatraffic unicast :" + std::to_string(meta_port);
            target_endpoints_.push_back(meta_ep);
            
            // 用户数据单播端口 (用于数据传输)
            int user_port = calculate_rtps_port(domain_id_, pid, false, false);
            TargetEndpoint user_ep;
            user_ep.addr.sin_family = AF_INET;
            user_ep.addr.sin_port = htons(user_port);
            inet_pton(AF_INET, target_ip_.c_str(), &user_ep.addr.sin_addr);
            user_ep.participant_id = pid;
            user_ep.is_metatraffic = false;
            user_ep.description = "Participant " + std::to_string(pid) + 
                                 " user data unicast :" + std::to_string(user_port);
            target_endpoints_.push_back(user_ep);
        }
    }
    
    /**
     * @brief 发送并收集响应特征 (多端点版本)
     * 
     * 响应来源：
     * 1. 直接响应：目标收到我们的包后，回复到我们的源端口
     * 2. 多播响应：目标广播的 SPDP/SEDP 等发现消息
     * 
     * 发送策略：
     * 1. 向所有目标端点发送测试报文
     * 2. 同时发送到多播地址
     * 
     * 响应特征：
     * 1. 有无响应：有响应说明目标活着且在处理
     * 2. 响应时间：时间变化可能意味着不同的处理路径
     * 3. 响应内容：不同的响应内容 = 不同的行为
     */
    NetworkResponseProfile inject_and_analyze(const std::vector<uint8_t>& data, 
                                              int timeout_ms = RESPONSE_TIMEOUT_MS)
    {
        NetworkResponseProfile profile;
        
        if (main_sock_ < 0 || data.empty()) {
            profile.response_type = ResponseType::SEND_ERROR;
            return profile;
        }
        
        auto start_time = std::chrono::steady_clock::now();
        
        // =============================================
        // 1. 发送到所有目标端点 (单播)
        // =============================================
        int success_count = 0;
        int send_errors = 0;
        
        for (const auto& endpoint : target_endpoints_) {
            ssize_t sent = sendto(main_sock_, data.data(), data.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&endpoint.addr),
                                 sizeof(endpoint.addr));
            
            if (sent > 0) {
                success_count++;
                packets_sent_++;
            } else {
                send_errors++;
                if (errno == ECONNREFUSED) {
                    // 某个端点拒绝连接
                }
            }
        }
        
        if (success_count == 0) {
            profile.response_type = ResponseType::SEND_ERROR;
            profile.error_code = errno;
            if (errno == ECONNREFUSED) {
                profile.inferred_state = RTPSState::TARGET_CRASHED;
            }
            return profile;
        }
        
        profile.send_success = true;
        
        // 推断发送状态（基于我们发送的消息类型）
        if (data.size() >= 21) {
            uint8_t submsg_id = data[20];
            switch (submsg_id) {
                case 0x15: profile.inferred_state = RTPSState::SENT_DATA; break;
                case 0x07: profile.inferred_state = RTPSState::SENT_HEARTBEAT; break;
                case 0x06: profile.inferred_state = RTPSState::SENT_ACKNACK; break;
                case 0x08: profile.inferred_state = RTPSState::SENT_GAP; break;
                default: profile.inferred_state = RTPSState::SENT_DISCOVERY; break;
            }
        }
        
        // =============================================
        // 2. 等待响应（来自主 socket 或多播 socket）
        // =============================================
        std::vector<uint8_t> recv_buffer(65536);
        
        // 准备 poll 的文件描述符
        struct pollfd pfds[2];
        int nfds = 0;
        
        pfds[nfds].fd = main_sock_;
        pfds[nfds].events = POLLIN;
        nfds++;
        
        if (multicast_sock_ >= 0) {
            pfds[nfds].fd = multicast_sock_;
            pfds[nfds].events = POLLIN;
            nfds++;
        }
        
        int poll_result = poll(pfds, nfds, timeout_ms);
        
        auto end_time = std::chrono::steady_clock::now();
        profile.response_time_us = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time).count();
        profile.timing_bucket = NetworkResponseProfile::compute_timing_bucket(profile.response_time_us);
        
        if (poll_result > 0) {
            // 检查主 socket 的响应（直接响应）
            if (pfds[0].revents & POLLIN) {
                sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);
                
                ssize_t recv_len = recvfrom(main_sock_, recv_buffer.data(), recv_buffer.size(), 0,
                                           reinterpret_cast<sockaddr*>(&from_addr), &from_len);
                
                if (recv_len > 0) {
                    profile.response_size = recv_len;
                    profile.inferred_state = RTPSState::GOT_RESPONSE;
                    
                    // 检查是否来自任一目标端点
                    if (is_from_target(from_addr)) {
                        target_alive_ = true;
                        last_target_response_time_ = end_time;
                        analyze_response(recv_buffer.data(), recv_len, profile);
                    }
                }
            }
            
            // 检查多播 socket 的响应（发现广播）
            if (nfds > 1 && (pfds[1].revents & POLLIN)) {
                sockaddr_in from_addr;
                socklen_t from_len = sizeof(from_addr);
                
                ssize_t recv_len = recvfrom(multicast_sock_, recv_buffer.data(), recv_buffer.size(), 0,
                                           reinterpret_cast<sockaddr*>(&from_addr), &from_len);
                
                if (recv_len > 0) {
                    // 检查是否来自目标
                    if (is_from_target(from_addr)) {
                        target_alive_ = true;
                        last_target_response_time_ = end_time;
                        multicast_responses_++;
                        
                        // 如果主 socket 没有收到响应，使用多播响应
                        if (profile.response_size == 0) {
                            profile.response_size = recv_len;
                            profile.inferred_state = RTPSState::GOT_RESPONSE;
                            analyze_response(recv_buffer.data(), recv_len, profile);
                        }
                    }
                }
            }
        } else if (poll_result == 0) {
            profile.response_type = ResponseType::TIMEOUT;
            profile.inferred_state = RTPSState::TIMEOUT;
            
            // 检查目标是否长时间无响应（可能崩溃）
            auto since_last = std::chrono::duration_cast<std::chrono::seconds>(
                end_time - last_target_response_time_).count();
            if (target_alive_ && since_last > 5) {
                // 目标之前活着，但现在超过 5 秒无响应
                profile.inferred_state = RTPSState::TARGET_CRASHED;
                target_alive_ = false;
            }
        }
        
        return profile;
    }
    
    /**
     * @brief 发送到用户数据多播地址
     * 
     * 用于向所有监听用户数据多播的 DataReader 发送测试报文
     */
    bool inject_to_user_multicast(const std::vector<uint8_t>& data)
    {
        if (main_sock_ < 0 || data.empty()) return false;
        
        ssize_t sent = sendto(main_sock_, data.data(), data.size(), 0,
                             reinterpret_cast<const sockaddr*>(&multicast_user_addr_),
                             sizeof(multicast_user_addr_));
        if (sent > 0) {
            packets_sent_++;
        }
        return sent == static_cast<ssize_t>(data.size());
    }
    
    /**
     * @brief 发送到 SPDP 发现多播地址
     * 
     * 用于发送伪造的发现消息
     */
    bool inject_to_spdp_multicast(const std::vector<uint8_t>& data)
    {
        if (main_sock_ < 0 || data.empty()) return false;
        
        ssize_t sent = sendto(main_sock_, data.data(), data.size(), 0,
                             reinterpret_cast<const sockaddr*>(&multicast_spdp_addr_),
                             sizeof(multicast_spdp_addr_));
        if (sent > 0) {
            packets_sent_++;
        }
        return sent == static_cast<ssize_t>(data.size());
    }
    
    /**
     * @brief 发送到多播 (兼容旧接口)
     */
    bool inject_to_multicast(const std::vector<uint8_t>& data)
    {
        return inject_to_user_multicast(data);
    }
    
    /**
     * @brief 检查目标是否存活
     */
    bool is_target_alive() const { return target_alive_; }
    
    /**
     * @brief 获取多播响应计数
     */
    size_t get_multicast_responses() const { return multicast_responses_; }
    
    /**
     * @brief 获取总发送包数
     */
    size_t get_packets_sent() const { return packets_sent_; }
    
    /**
     * @brief 获取目标端点数量
     */
    size_t get_endpoint_count() const { return target_endpoints_.size(); }
    
    void close()
    {
        if (main_sock_ >= 0) { ::close(main_sock_); main_sock_ = -1; }
        if (multicast_sock_ >= 0) { 
            // 离开多播组
            struct ip_mreq mreq = {};
            inet_pton(AF_INET, RTPS_MULTICAST_ADDR, &mreq.imr_multiaddr);
            mreq.imr_interface.s_addr = INADDR_ANY;
            setsockopt(multicast_sock_, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
            
            ::close(multicast_sock_); 
            multicast_sock_ = -1; 
        }
    }
    
    std::string get_target_info() const
    {
        std::string info = target_ip_ + " domain=" + std::to_string(domain_id_) + 
                          " participants=" + std::to_string(num_participants_) +
                          " endpoints=" + std::to_string(target_endpoints_.size());
        return info;
    }

private:
    std::string target_ip_;
    int domain_id_;
    int num_participants_;
    int local_port_ = 0;
    int main_sock_;           // 发送 + 接收直接响应
    int multicast_sock_;      // 接收多播响应
    
    // 目标端点列表
    std::vector<TargetEndpoint> target_endpoints_;
    
    // 多播地址
    sockaddr_in multicast_user_addr_;   // 用户数据多播
    sockaddr_in multicast_spdp_addr_;   // SPDP 发现多播
    
    // 目标状态追踪
    bool target_alive_;
    std::chrono::steady_clock::time_point last_target_response_time_;
    size_t multicast_responses_ = 0;
    size_t packets_sent_ = 0;
    
    /**
     * @brief 检查地址是否来自目标
     */
    bool is_from_target(const sockaddr_in& from_addr) const
    {
        // 检查 IP 地址是否匹配目标
        for (const auto& ep : target_endpoints_) {
            if (from_addr.sin_addr.s_addr == ep.addr.sin_addr.s_addr) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * @brief 分析响应内容，提取 RTPS 特征
     */
    void analyze_response(const uint8_t* data, size_t len, NetworkResponseProfile& profile)
    {
        // 计算响应哈希
        profile.response_hash = compute_hash(data, len);
        profile.response_prefix_hash = compute_hash(data, std::min(len, size_t(64)));
        
        // 检查是否是有效的 RTPS 响应
        if (len >= 20 && data[0] == 'R' && data[1] == 'T' && data[2] == 'P' && data[3] == 'S') {
            profile.is_valid_rtps = true;
            profile.response_type = ResponseType::VALID_RTPS;
            profile.rtps_version_major = data[4];
            profile.rtps_version_minor = data[5];
            profile.inferred_state = RTPSState::GOT_RTPS_RESPONSE;
            
            // 提取 submessage IDs
            size_t offset = 20;
            while (offset + 4 <= len) {
                uint8_t submsg_id = data[offset];
                profile.submessage_ids.push_back(submsg_id);
                
                uint16_t submsg_len = *reinterpret_cast<const uint16_t*>(&data[offset + 2]);
                offset += 4 + submsg_len;
                
                if (profile.submessage_ids.size() > 16) break;  // 防止无限循环
            }
        } else {
            profile.response_type = ResponseType::INVALID_RTPS;
            profile.inferred_state = RTPSState::GOT_ERROR_RESPONSE;
        }
    }
    
    static size_t compute_hash(const uint8_t* data, size_t len)
    {
        size_t hash = 0x811c9dc5;
        for (size_t i = 0; i < len; ++i) {
            hash ^= data[i];
            hash *= 0x01000193;
        }
        return hash;
    }
};

// ============================================================================
// 高级模糊测试引擎
// ============================================================================

class AdvancedFuzzEngine {
public:
    enum class Mode {
        PROTOCOL_AWARE,
        MUTATION_BASED,
        GENERATION_BASED,
        ATTACK_PATTERNS,
        HYBRID
    };
    
    AdvancedFuzzEngine(uint64_t seed = 0)
        : rng_(seed ? seed : std::random_device{}())
        , protocol_fuzzer_(seed)
        , mode_(Mode::HYBRID)
        , iterations_(0)
    {
        initialize_corpus();
    }
    
    void set_mode(Mode mode) { mode_ = mode; }
    
    std::vector<uint8_t> generate_testcase()
    {
        iterations_++;
        
        switch (mode_) {
            case Mode::PROTOCOL_AWARE: return generate_protocol_aware();
            case Mode::MUTATION_BASED: return generate_mutation_based();
            case Mode::GENERATION_BASED: return protocol_fuzzer_.generate_valid_message();
            case Mode::ATTACK_PATTERNS: return protocol_fuzzer_.generate_dds_attack();
            case Mode::HYBRID:
            default: return generate_hybrid();
        }
    }
    
    /**
     * @brief 处理测试结果，更新覆盖率和种子能量
     */
    void process_result(const std::vector<uint8_t>& input, const NetworkResponseProfile& profile)
    {
        // 记录响应到覆盖率追踪器
        coverage_.record_response(profile, input);
        
        bool new_coverage = coverage_.has_new_coverage();
        bool new_state_edge = coverage_.has_new_state_edge();
        
        // 发现新覆盖 -> 添加到语料库
        if (new_coverage) {
            SeedEntry* new_seed = seed_queue_.add_seed(input, true);
            if (new_seed) {
                new_seed->last_state = profile.inferred_state;
                new_findings_++;
            }
        }
        
        // 更新当前种子的能量
        if (current_seed_) {
            seed_queue_.update_seed(current_seed_, new_coverage, new_state_edge);
            current_seed_->last_state = profile.inferred_state;
        }
        
        // 检测崩溃/挂起
        if (profile.timing_bucket >= 5) {
            hangs_++;
            save_testcase(input, "hangs", "hang_" + std::to_string(hangs_));
        }
        
        if (profile.response_type == ResponseType::CONNECTION_REFUSED ||
            profile.error_code == ECONNREFUSED) {
            // 可能目标崩溃了
            crashes_++;
            save_testcase(input, "crashes", "crash_" + std::to_string(crashes_));
        }
        
        coverage_.reset_current();
    }
    
    void print_stats() const
    {
        std::cout << "\n==================== Fuzzer Statistics ====================" << std::endl;
        std::cout << "  Iterations: " << iterations_ << std::endl;
        std::cout << "  New findings (interesting inputs): " << new_findings_ << std::endl;
        std::cout << "  Potential crashes: " << crashes_ << std::endl;
        std::cout << "  Hangs/timeouts: " << hangs_ << std::endl;
        std::cout << "  Mode: " << mode_to_string(mode_) << std::endl;
        
        std::cout << "\n--- Corpus ---" << std::endl;
        seed_queue_.print_stats();
        
        coverage_.print_stats();
        std::cout << "=============================================================" << std::endl;
    }
    
    void save_corpus(const std::string& dir)
    {
        seed_queue_.save_to_directory(dir);
    }
    
    SeedEntry* get_current_seed() const { return current_seed_; }

private:
    std::mt19937_64 rng_;
    dds_fuzzing::RTPSProtocolFuzzer protocol_fuzzer_;
    SeedQueue seed_queue_;
    ResponseCoverageTracker coverage_;
    Mode mode_;
    SeedEntry* current_seed_ = nullptr;
    
    uint64_t iterations_ = 0;
    uint64_t new_findings_ = 0;
    uint64_t crashes_ = 0;
    uint64_t hangs_ = 0;
    
    void initialize_corpus()
    {
        // 初始种子
        seed_queue_.add_seed(protocol_fuzzer_.generate_valid_message(), false);
        
        // 最小有效消息
        std::vector<uint8_t> minimal = {'R', 'T', 'P', 'S', 2, 3, 1, 15};
        minimal.resize(20, 0);
        seed_queue_.add_seed(minimal, false);
        
        // 各种攻击模式
        for (int i = 0; i < 5; ++i) {
            seed_queue_.add_seed(protocol_fuzzer_.generate_dds_attack(), false);
        }
        
        // 边界情况
        std::vector<uint8_t> bad_magic = {0, 0, 0, 0, 2, 3, 1, 15};
        bad_magic.resize(20, 0);
        seed_queue_.add_seed(bad_magic, false);
    }
    
    std::vector<uint8_t> generate_protocol_aware()
    {
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
        
        std::vector<uint8_t> result = current_seed_->data;
        int mutations = 1 + (rng_() % 8);
        for (int i = 0; i < mutations; ++i) {
            result = protocol_fuzzer_.mutate(result);
        }
        return result;
    }
    
    std::vector<uint8_t> generate_hybrid()
    {
        int r = rng_() % 100;
        if (r < 40) return generate_protocol_aware();
        if (r < 60) return generate_mutation_based();
        if (r < 80) return protocol_fuzzer_.generate_valid_message();
        return protocol_fuzzer_.generate_dds_attack();
    }
    
    void save_testcase(const std::vector<uint8_t>& input, const std::string& subdir, 
                      const std::string& name)
    {
        std::string dir = "output/" + subdir;
        std::string mkdir_cmd = "mkdir -p " + dir;
        system(mkdir_cmd.c_str());
        
        std::string filename = dir + "/" + name + ".bin";
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(input.data()), input.size());
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
// 模糊测试节点
// ============================================================================

class AdvancedFuzzerNode {
public:
    /**
     * @brief 构造函数
     * 
     * @param target_ip 目标 IP 地址
     * @param domain_id DDS Domain ID (影响端口计算)
     * @param num_participants 目标参与者数量 (如：3 个 MonitorNode)
     */
    AdvancedFuzzerNode(const std::string& target_ip = "127.0.0.1", 
                       int domain_id = 0,
                       int num_participants = 1)
        : injector_(target_ip, domain_id, num_participants)
        , domain_id_(domain_id)
        , num_participants_(num_participants)
    {
    }
    
    bool init()
    {
        std::cout << "Initializing RTPS protocol fuzzer..." << std::endl;
        
        if (!injector_.init()) {
            std::cerr << "Failed to initialize network injector" << std::endl;
            return false;
        }
        
        std::cout << "Target: " << injector_.get_target_info() << std::endl;
        return true;
    }
    
    void run(uint32_t iterations = 10000, uint32_t interval_ms = 10)
    {
        std::cout << "\n========================================" << std::endl;
        std::cout << "  RTPS Protocol Fuzzer" << std::endl;
        std::cout << "  Target: " << injector_.get_target_info() << std::endl;
        std::cout << "  Iterations: " << iterations << std::endl;
        std::cout << "  Target endpoints: " << injector_.get_endpoint_count() << std::endl;
        std::cout << "========================================\n" << std::endl;
        
        auto start_time = std::chrono::steady_clock::now();
        
        uint32_t sent = 0, responses = 0, timeouts = 0;
        
        for (uint32_t i = 0; i < iterations && !SignalHandler::should_stop(); ++i) {
            // 生成测试用例
            std::vector<uint8_t> testcase = engine_.generate_testcase();
            if (testcase.empty()) continue;
            
            // 发送并分析响应 (会发送到所有目标端点)
            NetworkResponseProfile profile = injector_.inject_and_analyze(testcase);
            
            // 统计
            if (profile.send_success) sent++;
            if (profile.response_type == ResponseType::VALID_RTPS) responses++;
            if (profile.response_type == ResponseType::TIMEOUT) timeouts++;
            
            // 处理结果（更新覆盖率和种子能量）
            engine_.process_result(testcase, profile);
            
            // 每 10 次发送多播 (覆盖所有监听多播的端点)
            if (i % 10 == 0) {
                // 交替发送用户数据多播和 SPDP 发现多播
                if (i % 20 == 0) {
                    injector_.inject_to_user_multicast(testcase);
                } else {
                    injector_.inject_to_spdp_multicast(testcase);
                }
            }
            
            // 进度输出
            if (i > 0 && i % 1000 == 0) {
                auto now = std::chrono::steady_clock::now();
                double elapsed = std::chrono::duration<double>(now - start_time).count();
                std::cout << "[" << i << "/" << iterations << "] "
                          << std::fixed << std::setprecision(1) << (i / elapsed) << " exec/s"
                          << ", packets: " << injector_.get_packets_sent()
                          << ", responses: " << responses
                          << ", timeouts: " << timeouts << std::endl;
            }
            
            if (interval_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
            }
        }
        
        // 最终统计
        auto end_time = std::chrono::steady_clock::now();
        double total_time = std::chrono::duration<double>(end_time - start_time).count();
        
        std::cout << "\n--- Execution Summary ---" << std::endl;
        std::cout << "  Time: " << std::fixed << std::setprecision(2) << total_time << "s" << std::endl;
        std::cout << "  Test cases: " << sent << " (" << (sent / total_time) << "/s)" << std::endl;
        std::cout << "  Total packets sent: " << injector_.get_packets_sent() << std::endl;
        std::cout << "  Responses: " << responses << std::endl;
        std::cout << "  Multicast responses: " << injector_.get_multicast_responses() << std::endl;
        std::cout << "  Timeouts: " << timeouts << std::endl;
        
        engine_.print_stats();
        engine_.save_corpus("output/corpus");
    }
    
    void set_mode(AdvancedFuzzEngine::Mode mode) { engine_.set_mode(mode); }

private:
    RTPSInjector injector_;
    AdvancedFuzzEngine engine_;
    int domain_id_;
    int num_participants_;
};

// ============================================================================
// 主函数
// ============================================================================

void print_usage(const char* prog)
{
    std::cout << "RTPS Protocol Fuzzer - Response-guided network fuzzing\n\n"
              << "Based on AFL-Net/StateAFL/Boofuzz techniques:\n"
              << "  - Response content hashing (Boofuzz style)\n"
              << "  - Response timing buckets (AFL-Net style)\n"
              << "  - Protocol state machine coverage (StateAFL style)\n"
              << "  - Energy-based seed scheduling (AFL style)\n\n"
              << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -t, --target IP         Target IP (default: 127.0.0.1)\n"
              << "  -d, --domain ID         DDS Domain ID (default: 0)\n"
              << "  -P, --participants N    Number of target participants/MonitorNodes (default: 3)\n"
              << "  -n, --iterations N      Iterations (default: 10000)\n"
              << "  -i, --interval MS       Interval in ms (default: 10)\n"
              << "  -m, --mode MODE         Mode: protocol/mutation/generation/attack/hybrid\n"
              << "  -h, --help              Show this help\n\n"
              << "Port calculation (RTPS 2.3 spec):\n"
              << "  For Domain 0, the ports are:\n"
              << "    SPDP Multicast:     7400\n"
              << "    User Multicast:     7401\n"
              << "    Participant 0:      7410 (meta), 7411 (user)\n"
              << "    Participant 1:      7412 (meta), 7413 (user)\n"
              << "    Participant 2:      7414 (meta), 7415 (user)\n\n"
              << "Example:\n"
              << "  " << prog << " -t 127.0.0.1 -d 0 -P 3 -n 10000\n"
              << "  (Fuzz 3 MonitorNodes on domain 0)\n";
}

int main(int argc, char** argv)
{
    std::string target_ip = "127.0.0.1";
    int domain_id = 0;
    int num_participants = 3;  // 默认 3 个 MonitorNode
    uint32_t iterations = 10000;
    uint32_t interval_ms = 10;
    AdvancedFuzzEngine::Mode mode = AdvancedFuzzEngine::Mode::HYBRID;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if ((arg == "-t" || arg == "--target") && i + 1 < argc) {
            target_ip = argv[++i];
        } else if ((arg == "-d" || arg == "--domain") && i + 1 < argc) {
            domain_id = std::atoi(argv[++i]);
        } else if ((arg == "-P" || arg == "--participants") && i + 1 < argc) {
            num_participants = std::atoi(argv[++i]);
        } else if ((arg == "-n" || arg == "--iterations") && i + 1 < argc) {
            iterations = std::atoi(argv[++i]);
        } else if ((arg == "-i" || arg == "--interval") && i + 1 < argc) {
            interval_ms = std::atoi(argv[++i]);
        } else if ((arg == "-m" || arg == "--mode") && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "protocol") mode = AdvancedFuzzEngine::Mode::PROTOCOL_AWARE;
            else if (m == "mutation") mode = AdvancedFuzzEngine::Mode::MUTATION_BASED;
            else if (m == "generation") mode = AdvancedFuzzEngine::Mode::GENERATION_BASED;
            else if (m == "attack") mode = AdvancedFuzzEngine::Mode::ATTACK_PATTERNS;
        }
    }
    
    // 打印端口信息
    std::cout << "\n========== RTPS Port Configuration ==========" << std::endl;
    std::cout << "Domain ID: " << domain_id << std::endl;
    std::cout << "SPDP Multicast Port: " << calculate_rtps_port(domain_id, 0, true, true) << std::endl;
    std::cout << "User Multicast Port: " << calculate_rtps_port(domain_id, 0, false, true) << std::endl;
    std::cout << "\nTarget Participants (" << num_participants << "):" << std::endl;
    for (int p = 0; p < num_participants; ++p) {
        std::cout << "  Participant " << p << ": "
                  << "meta=" << calculate_rtps_port(domain_id, p, true, false) << ", "
                  << "user=" << calculate_rtps_port(domain_id, p, false, false) << std::endl;
    }
    std::cout << "=============================================\n" << std::endl;
    
    system("mkdir -p output/crashes output/hangs output/corpus");
    
    SignalHandler::setup();
    
    AdvancedFuzzerNode node(target_ip, domain_id, num_participants);
    node.set_mode(mode);
    
    if (!node.init()) {
        return EXIT_FAILURE;
    }
    
    node.run(iterations, interval_ms);
    
    return EXIT_SUCCESS;
}
