# Fast-DDS Fuzzing 测试策略总结

## 概述

该目录包含了一个完整的 Fast-DDS 协议模糊测试框架，实现了多种 fuzzing 策略来检测 DDS 协议实现中的安全漏洞和异常行为。

---

## 一、基础模糊测试策略（FuzzerNode.cpp）

### 测试架构

- **1 个异常节点**（Fuzzer Node）：生成和发送畸形数据包
- **3 个监控节点**（Monitor Nodes）：接收并检测异常
  - Monitor 1: 启用 AddressSanitizer (ASAN)
  - Monitor 2: 启用 UndefinedBehaviorSanitizer (UBSAN)
  - Monitor 3: 同时启用 ASAN + UBSAN

### 10 种模糊测试策略

| 策略名称             | 描述                              | 是否涉及节点通信 | 实现方式                                         |
| -------------------- | --------------------------------- | ---------------- | ------------------------------------------------ |
| **NORMAL**           | 正常消息 - 用于基线测试           | ✅ 是            | 通过 DDS DataWriter 发送正常的 SimpleTestMessage |
| **BIT_FLIP**         | 位翻转 - 随机翻转消息中的位       | ✅ 是            | 随机选择字节和位进行翻转，通过 DDS 发送          |
| **BOUNDARY_VALUES**  | 边界值测试 - 测试整数边界值       | ✅ 是            | 使用 INT_MAX, INT_MIN 等极值，通过 DDS 发送      |
| **LARGE_PAYLOAD**    | 超大负载 - 发送超大字符串         | ✅ 是            | 创建 10MB 大小的字符串消息，通过 DDS 发送        |
| **RANDOM_DATA**      | 随机数据 - 完全随机的数据         | ✅ 是            | 生成随机二进制数据，通过 DDS 发送                |
| **SEQUENCE_CHAOS**   | 序列号混乱 - 打乱消息序列号       | ✅ 是            | 使用负数、大数值作为序列号，通过 DDS 发送        |
| **SPECIAL_CHARS**    | 特殊字符 - 注入控制字符和特殊字符 | ✅ 是            | 注入 Unicode、控制字符、emoji 等，通过 DDS 发送  |
| **NULL_INJECTION**   | 空字符注入 - 在字符串中注入空字符 | ✅ 是            | 在字符串中插入\x00 等空字符，通过 DDS 发送       |
| **OVERFLOW_ATTEMPT** | 溢出尝试 - 尝试触发溢出           | ✅ 是            | 构造可能导致溢出的数据结构，通过 DDS 发送        |
| **FORMAT_STRING**    | 格式字符串攻击尝试                | ✅ 是            | 注入%s、%x 等格式化字符串，通过 DDS 发送         |

**通信方式**：所有策略都通过 Fast-DDS 的 DataWriter API 发送消息，使用 DDS Publisher-Subscriber 模式进行节点间通信。

---

## 二、高级模糊测试策略（AdvancedFuzzerNode.cpp）

### 测试特性

- RTPS 协议感知的结构化模糊测试
- 基于覆盖率的变异策略（模拟）
- 种子队列和语料库管理
- 多种 DDS 攻击模式
- 两种工作模式：DDS API 模式 和 网络直接注入模式

### 5 种高级测试模式

| 模式名称             | 描述                               | 是否涉及节点通信  | 实现方式                                                             |
| -------------------- | ---------------------------------- | ----------------- | -------------------------------------------------------------------- |
| **PROTOCOL_AWARE**   | 协议感知模式 - RTPS 协议结构化变异 | ✅ 是（两种方式） | 1. 通过 DDS DataWriter 发送<br>2. 或通过 UDP socket 直接注入 RTPS 包 |
| **MUTATION_BASED**   | 变异模式 - 基于种子的多次变异      | ✅ 是（两种方式） | 对现有种子进行 1-8 次随机变异后发送                                  |
| **GENERATION_BASED** | 生成模式 - 从头生成有效 RTPS 消息  | ✅ 是（两种方式） | 使用 RTPSProtocolFuzzer 生成合法 RTPS 消息                           |
| **ATTACK_PATTERNS**  | 攻击模式 - 专门的 DDS 攻击模式     | ✅ 是（两种方式） | 生成针对 DDS 的特定攻击载荷                                          |
| **HYBRID**           | 混合模式 - 组合多种策略            | ✅ 是（两种方式） | 按概率选择不同策略（30%协议感知，20%变异，20%生成，30%攻击）         |

**通信方式**：

1. **DDS API 模式**：通过 Fast-DDS DataWriter 正常发送消息
2. **网络注入模式**：使用 RTPSInjector 直接向 UDP 端口注入原始 RTPS 数据包，绕过 DDS API

### 种子管理策略

- **SeedQueue**：管理测试语料库
  - 基于哈希去重
  - 基于能量的种子调度
  - 动态更新种子能量值
  - 支持从文件加载/保存

### 覆盖率引导

- **CoverageTracker**：追踪代码覆盖情况
  - 记录执行路径特征
  - 识别新覆盖路径
  - 保存触发新覆盖的输入

---

## 三、AFL++ 集成（AFLHarness.cpp）

### 测试目标

专门用于与 AFL++ 模糊测试工具集成，对 Fast-DDS 内部解析器进行测试。

| 测试函数                 | 描述                        | 是否涉及节点通信 | 实现方式                                          |
| ------------------------ | --------------------------- | ---------------- | ------------------------------------------------- |
| **test_cdr_deserialize** | CDR 反序列化测试            | ❌ 否            | 直接调用 FastCDR 库的反序列化函数，不涉及网络通信 |
| **test_rtps_parse**      | RTPS 消息解析测试           | ❌ 否            | 解析 RTPS 协议头和 submessages，纯内存操作        |
| **test_payload**         | SerializedPayload 处理测试  | ❌ 否            | 测试序列化/反序列化，无网络通信                   |
| **test_all**             | 综合测试 - 组合上述所有测试 | ❌ 否            | 根据输入选择测试函数，所有测试都是本地的          |

**通信方式**：AFL++ harness **不涉及节点通信**，它直接测试库函数的健壮性，输入来自：

- 标准输入（stdin）
- 文件输入
- AFL++ 的持久模式（\_\_AFL_LOOP）

### AFL++ 特性

- 支持持久模式（高效 fuzzing）
- 支持延迟 fork 服务器（\_\_AFL_INIT）
- 可与 ASAN/UBSAN 配合使用

---

## 四、LibFuzzer 集成（LibFuzzerHarness.cpp）

### 测试目标

专门用于与 LLVM LibFuzzer 集成，进行细粒度的模糊测试。

| 测试函数                           | 描述                           | 是否涉及节点通信 | 实现方式                              |
| ---------------------------------- | ------------------------------ | ---------------- | ------------------------------------- |
| **LLVMFuzzerTestOneInput_CDR**     | CDR 反序列化健壮性测试         | ❌ 否            | 使用 FastCDR 直接反序列化，无网络通信 |
| **LLVMFuzzerTestOneInput_RTPS**    | RTPS Header 和 Submessage 解析 | ❌ 否            | 解析 RTPS 协议结构，纯内存操作        |
| **LLVMFuzzerTestOneInput_Payload** | SerializedPayload 处理测试     | ❌ 否            | 测试序列化/反序列化的健壮性           |
| **LLVMFuzzerTestOneInput_String**  | 字符串处理健壮性测试           | ❌ 否            | 测试各种字符串边界情况                |
| **LLVMFuzzerTestOneInput**         | 主入口 - 多目标 fuzzing        | ❌ 否            | 根据输入字节选择上述测试之一          |

**通信方式**：LibFuzzer harness **不涉及节点通信**，它是：

- 单进程内的库函数测试
- 输入由 LibFuzzer 引擎自动生成
- 专注于发现解析器漏洞（缓冲区溢出、越界读取等）

### RTPS 协议支持

- 完整的 RTPS Header 结构（20 字节）
- Submessage 解析（DATA, HEARTBEAT, ACKNACK 等）
- 支持多种 Submessage 类型

---

## 五、通信模式对比

### 涉及节点通信的测试

| 组件                              | 通信方式       | 通信协议      | 用途                                         |
| --------------------------------- | -------------- | ------------- | -------------------------------------------- |
| **FuzzerNode**                    | DDS DataWriter | RTPS/DDS      | 通过正常 DDS API 向 Monitor 节点发送畸形消息 |
| **AdvancedFuzzerNode (DDS 模式)** | DDS DataWriter | RTPS/DDS      | 使用 DDS API 发送协议感知的测试用例          |
| **AdvancedFuzzerNode (注入模式)** | UDP Socket     | RTPS (原始包) | 绕过 DDS API，直接注入原始 RTPS 包到网络     |
| **MonitorNode**                   | DDS DataReader | RTPS/DDS      | 接收 Fuzzer 发送的消息，检测异常             |

### 不涉及节点通信的测试

| 组件                 | 测试方式     | 输入来源             | 用途                           |
| -------------------- | ------------ | -------------------- | ------------------------------ |
| **AFLHarness**       | 直接函数调用 | AFL++引擎/文件/stdin | 测试反序列化和解析函数的健壮性 |
| **LibFuzzerHarness** | 直接函数调用 | LibFuzzer 引擎       | 细粒度的库函数 fuzzing         |

---

## 六、检测机制

### 运行时检测器

- **AddressSanitizer (ASAN)**：检测内存错误

  - 堆/栈缓冲区溢出
  - Use-after-free
  - Double-free
  - 内存泄漏

- **UndefinedBehaviorSanitizer (UBSAN)**：检测未定义行为
  - 整数溢出
  - 除零错误
  - 空指针解引用
  - 类型转换错误

### 自定义异常检测

- 空指针检测
- 超大消息检测
- 非法字符检测
- 序列号异常检测
- 数据完整性检查

---

## 七、测试覆盖范围

### 协议层面

- ✅ RTPS Header 篡改
- ✅ Submessage 篡改
- ✅ 序列号混乱
- ✅ QoS 参数异常

### 数据层面

- ✅ CDR 序列化数据篡改
- ✅ 长度字段篡改
- ✅ 类型信息篡改
- ✅ 字符串边界测试

### 通信层面

- ✅ 传输层参数篡改
- ✅ 发现数据篡改（可通过注入模式）
- ✅ 多播消息注入

---

## 八、使用场景

### 场景 1：端到端节点通信测试

**使用工具**：FuzzerNode + MonitorNode

**目的**：测试完整的 DDS 通信链路，发现端到端的安全问题

**涉及通信**：✅ 是

### 场景 2：协议感知的高级测试

**使用工具**：AdvancedFuzzerNode (DDS 模式)

**目的**：使用覆盖率引导和种子管理进行智能 fuzzing

**涉及通信**：✅ 是

### 场景 3：网络层注入测试

**使用工具**：AdvancedFuzzerNode (注入模式)

**目的**：绕过 DDS API，直接在网络层注入畸形 RTPS 包

**涉及通信**：✅ 是（网络层）

### 场景 4：库函数健壮性测试

**使用工具**：AFLHarness 或 LibFuzzerHarness

**目的**：独立测试反序列化和解析函数，快速发现库级别的漏洞

**涉及通信**：❌ 否

---

## 九、总结

### 涉及节点通信的策略（15 种）

1. 基础 10 种策略（FuzzerNode）- 都通过 DDS 通信
2. 高级 5 种模式（AdvancedFuzzerNode）- 支持 DDS 或网络注入

**特点**：

- 测试完整的通信链路
- 可以发现协议实现、网络传输、序列化等各层的问题
- 需要运行多个节点（Fuzzer + Monitor）
- 更接近真实使用场景

### 不涉及节点通信的策略（9 种）

1. AFL++ 4 种测试函数（AFLHarness）
2. LibFuzzer 5 种测试函数（LibFuzzerHarness）

**特点**：

- 直接测试库函数
- 单进程运行，效率更高
- 专注于发现解析器漏洞
- 不需要网络通信和节点发现
- 适合快速的回归测试

### 推荐使用组合

1. **快速漏洞发现**：使用 LibFuzzer/AFL++ harness 进行快速本地测试
2. **深度协议测试**：使用 AdvancedFuzzerNode 进行协议感知 fuzzing
3. **实战验证**：使用 FuzzerNode + MonitorNode 进行端到端测试
4. **网络攻击模拟**：使用 AdvancedFuzzerNode 的注入模式绕过 API 限制

---

## 十、文件说明

| 文件                   | 功能                       | 节点通信              |
| ---------------------- | -------------------------- | --------------------- |
| FuzzerNode.cpp         | 基础模糊测试节点           | ✅                    |
| AdvancedFuzzerNode.cpp | 高级模糊测试节点           | ✅                    |
| MonitorNode.cpp        | 监控节点（接收端）         | ✅                    |
| AFLHarness.cpp         | AFL++ 集成                 | ❌                    |
| LibFuzzerHarness.cpp   | LibFuzzer 集成             | ❌                    |
| RTPSProtocolFuzzer.hpp | RTPS 协议 fuzzing 库       | N/A（被其他组件使用） |
| Common.hpp/cpp         | 公共功能（日志、检测器等） | N/A（工具类）         |

---

_生成时间：2024_
_基于 Fast-DDS fuzzing_test 项目分析_
