# 项目结构说明

## 目录结构

```
fuzzing_test/
├── CMakeLists.txt              # CMake 构建配置
├── Makefile                    # 便捷命令（make test, make build 等）
├── README.md                   # 完整项目文档
├── QUICKSTART.md               # 快速入门指南
├── PROJECT_STRUCTURE.md        # 本文件：项目结构说明
│
├── TestMessage.idl             # DDS 消息类型定义（IDL）
│
├── Common.hpp                  # 公共头文件
├── Common.cpp                  # 公共实现（日志、检测器、性能监控等）
│
├── FuzzerNode.cpp              # 模糊测试节点实现
├── MonitorNode.cpp             # 监控节点实现
│
├── fuzzing_test_profile.xml    # DDS QoS 配置文件
│
├── tools/                      # 构建和测试工具脚本
│   ├── build_all.sh            # 一键构建脚本
│   ├── build_advanced.sh       # 高级构建脚本
│   ├── run_test.sh             # 测试运行脚本
│   └── run_advanced_test.sh    # 高级测试运行脚本
│
└── .gitignore                  # Git 忽略文件配置
```

## 构建产物

运行 `./tools/build_all.sh` 后会生成以下目录：

```
fuzzing_test/
├── build/                      # 标准构建
│   └── fuzzer_node             # Fuzzer 可执行文件
│
├── build_asan/                 # ASAN 构建
│   └── monitor_node_asan       # Monitor 1 可执行文件
│
├── build_ubsan/                # UBSAN 构建
│   └── monitor_node_ubsan      # Monitor 2 可执行文件
│
└── build_full/                 # Full Sanitizer 构建
    └── monitor_node_full       # Monitor 3 可执行文件
```

## 运行时产物

运行测试后会生成：

```
fuzzing_test/
├── fuzzer_node.log            # Fuzzer 日志
├── monitor_node_1.log         # Monitor 1 日志
├── monitor_node_2.log         # Monitor 2 日志
├── monitor_node_3.log         # Monitor 3 日志
│
├── monitor1.out               # Monitor 1 标准输出
├── monitor2.out               # Monitor 2 标准输出
├── monitor3.out               # Monitor 3 标准输出
│
└── .pids/                     # 运行时 PID 文件（临时）
    ├── monitor1.pid
    ├── monitor2.pid
    └── monitor3.pid
```

## 核心文件说明

### 1. TestMessage.idl

定义了三种测试消息类型：

- **SimpleTestMessage**: 基础测试消息（序列号、字符串、类型）
- **ComplexTestMessage**: 复杂嵌套消息（数组、嵌套结构）
- **BoundaryTestMessage**: 边界测试消息（固定缓冲区、大数字）

### 2. Common.hpp/cpp

提供通用功能：

- **Logger**: 日志记录系统
  - 多级别日志（INFO, WARNING, ERROR, CRITICAL）
  - 异常检测专用日志
  - 文件和控制台双输出

- **AnomalyDetector**: 异常检测器
  - 内存异常检测
  - 数据完整性检查
  - 序列号异常检测
  - 统计信息收集

- **PerformanceMonitor**: 性能监控
  - 延迟测量
  - 统计分析（均值、中位数、P95、P99）

- **SignalHandler**: 信号处理
  - 优雅关闭
  - SIGINT/SIGTERM 处理

### 3. FuzzerNode.cpp

模糊测试节点：

- **FuzzEngine**: 模糊测试引擎
  - 10 种模糊测试策略
  - 随机策略选择
  - 可扩展的变异逻辑

- **FuzzerNode**: DDS 发布者
  - 创建 DataWriter
  - 按配置速率发送消息
  - 等待订阅者连接

### 4. MonitorNode.cpp

监控节点：

- **MonitorListener**: 数据接收监听器
  - 实时消息处理
  - 异常检测触发
  - 统计信息更新

- **MonitorNode**: DDS 订阅者
  - 创建 DataReader
  - 注册监听器
  - 持续运行直到信号中断

### 5. CMakeLists.txt

构建配置：

- 支持 4 个独立的可执行文件
- 可选的 ASAN/UBSAN 编译选项
- 自动复制 XML 配置文件
- 跨平台支持（Linux/macOS/Windows）

### 6. tools/build_all.sh

自动化构建：

- 清理旧构建
- 创建 4 个独立的构建目录
- 分别编译各个节点
- 显示构建进度和结果

### 7. tools/run_test.sh

测试自动化：

- 启动所有监控节点（后台）
- 启动 Fuzzer 节点（前台）
- 信号处理和优雅关闭
- 测试结果摘要
- 日志收集和展示

### 8. fuzzing_test_profile.xml

DDS QoS 配置：

- Participant 配置
- DataWriter/DataReader QoS
- 可靠性、持久性、历史策略
- 资源限制
- 传输配置（UDP、SHM）

## 编译流程

1. **CMake 配置阶段**
   - 检测 Fast-DDS 和 FastCDR
   - 配置编译选项（ASAN/UBSAN）
   - 设置包含路径和链接库

2. **编译阶段**
   - 编译 Common.cpp
   - 分别编译各个节点
   - 应用 Sanitizer 标志
   - 链接 Fast-DDS 库

3. **安装阶段**（可选）
   - 复制可执行文件
   - 复制 XML 配置文件

## 运行流程

1. **初始化阶段**
   - 创建 DomainParticipant
   - 注册消息类型
   - 创建 Topic

2. **通信建立阶段**
   - Fuzzer 创建 Publisher/DataWriter
   - Monitor 创建 Subscriber/DataReader
   - 自动发现和匹配

3. **测试执行阶段**
   - Fuzzer 发送模糊消息
   - Monitor 接收并检测异常
   - 实时日志记录

4. **清理阶段**
   - 停止所有节点
   - 输出统计信息
   - 清理 DDS 实体

## 扩展点

### 添加新的模糊测试策略

在 `FuzzerNode.cpp` 中：

1. 在 `FuzzStrategy` 枚举添加新策略
2. 在 `generate_fuzzed_message()` 添加 case 分支
3. 实现对应的生成函数

### 添加新的检测规则

在 `MonitorNode.cpp` 中：

1. 在 `MonitorListener::process_simple_message()` 添加检测逻辑
2. 使用 `detector_.check_*()` 或自定义检查
3. 调用 `Logger::instance().log_anomaly()` 记录

### 添加新的消息类型

1. 在 `TestMessage.idl` 定义新结构
2. 重新编译生成 PubSub 类型
3. 在 Fuzzer 添加生成逻辑
4. 在 Monitor 添加处理逻辑

### 集成外部 Fuzzer

在 `FuzzerNode.cpp` 中集成 libFuzzer/AFL++：

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // 使用 data/size 生成消息
    // 发送到 DDS
}
```

## 依赖关系

```
FuzzerNode
    ├── Common (Logger, PerformanceMonitor)
    ├── TestMessagePubSubTypes (IDL 生成)
    ├── Fast-DDS (DDS API)
    └── FastCDR (序列化)

MonitorNode
    ├── Common (Logger, AnomalyDetector)
    ├── TestMessagePubSubTypes (IDL 生成)
    ├── Fast-DDS (DDS API)
    └── FastCDR (序列化)
```

## 性能考虑

- **内存**: 每个 Monitor 节点约 50-100 MB（取决于 Sanitizer）
- **CPU**: Fuzzer 可配置发送速率以控制 CPU 使用
- **网络**: 默认使用 UDP + SHM，本地测试优先使用 SHM
- **延迟**: 典型延迟 < 1ms（本地 SHM），< 10ms（UDP）

## 安全考虑

- Sanitizer 会显著降低性能（2-5x），仅用于测试
- 大负载消息可能消耗大量内存
- 建议在隔离环境中运行测试
- 监控系统资源使用情况

## 故障诊断

### 查看详细日志

```bash
# 实时监控日志
tail -f fuzzer_node.log monitor_node_*.log

# 查看特定类型的日志
grep "ERROR\|CRITICAL" *.log
```

### 调试单个节点

```bash
# 使用 gdb 调试
gdb ./build/fuzzer_node
(gdb) run

# 使用 valgrind 检查内存
valgrind --leak-check=full ./build_asan/monitor_node_asan
```

### 检查 DDS 发现

```bash
# 设置环境变量显示详细 DDS 日志
export FASTDDS_LOGLEVEL=INFO
export FASTDDS_LOGCATEGORY=DISCOVERY

./build/fuzzer_node
```

## 相关资源

- Fast-DDS 文档: https://fast-dds.docs.eprosima.com/
- ASAN 使用指南: https://github.com/google/sanitizers/wiki/AddressSanitizer
- DDS 规范: https://www.omg.org/spec/DDS/

