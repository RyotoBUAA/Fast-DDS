# DDS 模糊测试策略文档

## 概述

本文档详细描述了 Fast-DDS 模糊测试框架中实现的 10 种模糊测试策略。这些策略旨在发现 DDS 协议实现中可能存在的安全漏洞、内存错误和异常行为。

**测试配置**：
- 总消息数：1000 条
- 每种策略：100 条消息（均匀分布）
- 发送间隔：50ms
- 测试模式：轮询策略，确保每种策略使用次数相同

---

## 策略列表

### 策略 0：正常消息（NORMAL）

**目的**：基线测试，验证系统正常处理流程

**实现方式**：
```cpp
void generate_normal(SimpleTestMessage& msg)
{
    msg.seq_num(sequence_num_++);
    msg.message("Normal test message");
    msg.data_type(1);
}
```

**测试内容**：
- 顺序递增的序列号
- 标准文本消息
- 正常的数据类型标识

**预期行为**：
- 所有监控节点应正常接收并处理
- 不应触发任何异常检测
- 用作其他策略的对比基准

**风险等级**：⭐ 无风险

---

### 策略 1：位翻转（BIT_FLIP）

**目的**：模拟数据传输过程中的位损坏，测试容错能力

**实现方式**：
```cpp
void generate_bit_flip(SimpleTestMessage& msg)
{
    msg.seq_num(sequence_num_++);
    
    std::string message = "Test message with bit flip";
    if (!message.empty())
    {
        size_t pos = dist_byte_(rng_) % message.length();
        size_t bit = dist_byte_(rng_) % 8;
        message[pos] ^= (1 << bit);  // XOR 翻转单个位
    }
    
    msg.message(message);
    msg.data_type(dist_byte_(rng_));
}
```

**测试内容**：
- 随机选择字符串中的一个字符
- 随机翻转该字符的一个位（0→1 或 1→0）
- 数据类型字段也随机化

**可能触发的问题**：
- 字符编码错误
- UTF-8 序列损坏
- 字符串解析异常
- 类型检查失败

**风险等级**：⭐⭐ 低风险

---

### 策略 2：边界值测试（BOUNDARY_VALUES）

**目的**：测试整数类型的边界值处理，发现溢出漏洞

**实现方式**：
```cpp
void generate_boundary_values(SimpleTestMessage& msg)
{
    static uint32_t boundary_values[] = {
        0, 1, 127, 128, 255, 256,
        32767, 32768, 65535, 65536,
        0x7FFFFFFF, 0x80000000, 0xFFFFFFFF
    };
    
    uint32_t val = boundary_values[dist_byte_(rng_) % 13];
    msg.seq_num(val);
    msg.message("Boundary value test");
    msg.data_type(255);
}
```

**测试内容**：
- **0**：最小值
- **1**：最小正整数
- **127/128**：int8_t 边界
- **255/256**：uint8_t 边界
- **32767/32768**：int16_t 边界
- **65535/65536**：uint16_t 边界
- **0x7FFFFFFF**：int32_t 最大值
- **0x80000000**：int32_t 最小值（负数）
- **0xFFFFFFFF**：uint32_t 最大值

**可能触发的问题**：
- 整数溢出
- 符号位处理错误
- 数组索引越界
- 缓冲区分配错误

**风险等级**：⭐⭐⭐ 中风险

---

### 策略 3：超大负载（LARGE_PAYLOAD）

**目的**：测试大消息处理能力，发现缓冲区溢出和内存分配问题

**实现方式**：
```cpp
void generate_large_payload(SimpleTestMessage& msg)
{
    msg.seq_num(sequence_num_++);
    
    // 生成 1KB-10KB 范围的字符串
    size_t size = 1000 + (dist_byte_(rng_) * 35);
    std::string large_str(size, 'A');
    
    msg.message(large_str);
    msg.data_type(2);
    
    Logger::instance().log(LogLevel::INFO, "FUZZER",
                          "Generated large payload: " + 
                          std::to_string(size) + " bytes");
}
```

**测试内容**：
- 消息大小：1,000 - 10,000 字节
- 填充字符：'A'（0x41）
- 测试内存分配和拷贝操作

**可能触发的问题**：
- 堆缓冲区溢出
- 内存分配失败
- 栈溢出（如果栈上分配）
- OOM（内存耗尽）
- DDS 传输层限制

**ASAN 可能检测**：
- `heap-buffer-overflow`
- `heap-use-after-free`
- `alloc-dealloc-mismatch`

**风险等级**：⭐⭐⭐⭐ 高风险

---

### 策略 4：随机数据（RANDOM_DATA）

**目的**：完全随机的数据，测试对非预期输入的处理

**实现方式**：
```cpp
void generate_random_data(SimpleTestMessage& msg)
{
    // 随机序列号
    msg.seq_num(dist_byte_(rng_) | (dist_byte_(rng_) << 8) | 
               (dist_byte_(rng_) << 16) | (dist_byte_(rng_) << 24));
    
    // 完全随机的字符串（10-110 字节）
    size_t len = 10 + (dist_byte_(rng_) % 100);
    std::string random_str;
    for (size_t i = 0; i < len; ++i)
    {
        random_str += static_cast<char>(dist_byte_(rng_));
    }
    
    msg.message(random_str);
    msg.data_type(dist_byte_(rng_));
}
```

**测试内容**：
- 随机序列号（全范围）
- 随机长度字符串
- 随机字节内容（包括不可打印字符）
- 随机数据类型

**可能触发的问题**：
- UTF-8 验证失败
- 字符串终止符处理
- 非法字符导致的解析错误
- 类型验证失败

**风险等级**：⭐⭐⭐ 中风险

---

### 策略 5：序列号混乱（SEQUENCE_CHAOS）

**目的**：测试序列号验证和顺序处理逻辑

**实现方式**：
```cpp
void generate_sequence_chaos(SimpleTestMessage& msg)
{
    static int chaos_counter = 0;
    
    switch (chaos_counter++ % 4)
    {
        case 0: msg.seq_num(0xFFFFFFFF); break;      // 最大值
        case 1: msg.seq_num(sequence_num_ + 1000); break;  // 大幅跳跃
        case 2: msg.seq_num(sequence_num_ - 100); break;   // 回退
        case 3: msg.seq_num(0); break;                // 重置为零
    }
    
    msg.message("Sequence chaos test");
    msg.data_type(3);
}
```

**测试内容**：
- **情况 1**：突然跳到最大值（0xFFFFFFFF）
- **情况 2**：序列号大幅跳跃（+1000）
- **情况 3**：序列号回退（-100，可能导致负数/下溢）
- **情况 4**：序列号重置为 0

**可能触发的问题**：
- 序列号验证逻辑错误
- 整数下溢（减法导致）
- 重复消息检测失败
- 队列排序错误

**UBSAN 可能检测**：
- `signed integer overflow`
- `unsigned integer overflow`

**风险等级**：⭐⭐⭐ 中风险

---

### 策略 6：特殊字符注入（SPECIAL_CHARS）

**目的**：测试控制字符、ANSI 转义序列的处理

**实现方式**：
```cpp
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
```

**测试内容**：
- **空字符**：`\x00`（字符串终止符）
- **控制字符**：`\x01`, `\x02` 等
- **高位字符**：`\xff`, `\xfe`, `\xfd`
- **转义字符**：`\n`, `\r`, `\t`, `\b`, `\a`
- **ANSI 转义序列**：`\x1b[31m`（红色）、`\x1b[0m`（重置）

**可能触发的问题**：
- 字符串截断（遇到 `\x00`）
- 日志注入攻击
- 终端控制劫持
- UTF-8 验证失败
- 字符编码混乱

**风险等级**：⭐⭐⭐ 中风险

---

### 策略 7：空字符注入（NULL_INJECTION）

**目的**：专门测试空字符（`\0`）在字符串中间的处理

**实现方式**：
```cpp
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
```

**测试内容**：
- 字符串结构：`"Before\0After\0End"`
- 实际长度：14 字节
- C 风格字符串长度：6 字节（遇到第一个 `\0` 停止）

**可能触发的问题**：
- C 字符串函数（`strlen`, `strcpy`）截断
- 字符串比较错误
- 序列化/反序列化长度不一致
- 数据丢失

**典型漏洞场景**：
```cpp
// 危险代码示例
char buffer[100];
strcpy(buffer, msg.message().c_str());  // 只拷贝到第一个 \0
```

**风险等级**：⭐⭐⭐⭐ 高风险

---

### 策略 8：溢出尝试（OVERFLOW_ATTEMPT）

**目的**：尝试触发各种溢出情况

**实现方式**：
```cpp
void generate_overflow_attempt(SimpleTestMessage& msg)
{
    msg.seq_num(0xDEADBEEF);  // 特殊标记值
    
    // 创建可能导致溢出的模式
    std::string overflow_pattern;
    for (int i = 0; i < 100; ++i)
    {
        overflow_pattern += std::to_string(i) + " ";
    }
    
    msg.message(overflow_pattern);
    msg.data_type(200);  // 超出正常范围
}
```

**测试内容**：
- 序列号：`0xDEADBEEF`（魔术数字，调试标记）
- 消息内容：`"0 1 2 3 ... 98 99 "`（约 291 字节）
- 数据类型：200（可能超出枚举范围）

**可能触发的问题**：
- 固定大小缓冲区溢出
- 类型值超出有效范围
- 数组索引越界
- 循环缓冲区溢出

**ASAN 可能检测**：
- `stack-buffer-overflow`
- `global-buffer-overflow`

**风险等级**：⭐⭐⭐⭐ 高风险

---

### 策略 9：格式字符串攻击（FORMAT_STRING）

**目的**：测试格式字符串漏洞

**实现方式**：
```cpp
void generate_format_string(SimpleTestMessage& msg)
{
    msg.seq_num(sequence_num_++);
    
    // 格式字符串攻击载荷
    msg.message("%s%s%s%s%s%s%s%s%s%s%n%n%n%n%n%n");
    msg.data_type(6);
}
```

**测试内容**：
- **`%s`**：读取栈上的指针，尝试当作字符串打印
- **`%n`**：写入已输出字符数到指针指向的地址（极其危险）

**危险代码示例**：
```cpp
// 危险！不要这样写
printf(msg.message().c_str());  // 格式字符串漏洞

// 安全写法
printf("%s", msg.message().c_str());
```

**可能触发的问题**：
- 信息泄露（读取栈内存）
- 任意地址写入（`%n`）
- 程序崩溃（访问非法地址）
- 远程代码执行（在极端情况下）

**ASAN 可能检测**：
- `stack-buffer-overflow`
- `SEGV on unknown address`

**风险等级**：⭐⭐⭐⭐⭐ 极高风险

---

## 测试配置说明

### 策略分配方式

**轮询模式**（当前实现）：
```
消息 0: NORMAL
消息 1: BIT_FLIP
消息 2: BOUNDARY_VALUES
...
消息 9: FORMAT_STRING
消息 10: NORMAL
...
消息 999: FORMAT_STRING
```

**结果**：每种策略恰好使用 **100 次**

### 统计输出示例

```
========== 模糊测试策略统计 ==========
  NORMAL (正常消息): 100 条
  BIT_FLIP (位翻转): 100 条
  BOUNDARY_VALUES (边界值): 100 条
  LARGE_PAYLOAD (超大负载): 100 条
  RANDOM_DATA (随机数据): 100 条
  SEQUENCE_CHAOS (序列号混乱): 100 条
  SPECIAL_CHARS (特殊字符): 100 条
  NULL_INJECTION (空字符注入): 100 条
  OVERFLOW_ATTEMPT (溢出尝试): 100 条
  FORMAT_STRING (格式字符串): 100 条
========================================
```

---

## 监控节点检测能力

### Monitor Node 1 (ASAN)

**检测能力**：
- ✅ 堆缓冲区溢出（策略 3, 8）
- ✅ 栈缓冲区溢出（策略 8, 9）
- ✅ Use-after-free
- ✅ 内存泄漏
- ✅ 全局缓冲区溢出

**可能触发的策略**：3, 7, 8, 9

### Monitor Node 2 (UBSAN)

**检测能力**：
- ✅ 整数溢出（策略 2, 5）
- ✅ 除零错误
- ✅ 空指针解引用
- ✅ 类型转换错误
- ✅ 数组越界

**可能触发的策略**：2, 4, 5, 8

### Monitor Node 3 (ASAN + UBSAN)

**检测能力**：
- ✅ 综合所有 ASAN 和 UBSAN 检测
- ✅ 最全面的运行时检测

**可能触发的策略**：全部

---

## 异常检测规则

### 应用层检测（MonitorNode.cpp）

```cpp
// 1. 空指针检测
if (msg.message().empty())
{
    log_anomaly("NULL_POINTER", "Empty message");
}

// 2. 大消息检测
if (msg.message().length() > 5000)
{
    log_anomaly("LARGE_MESSAGE", "Size: " + std::to_string(size));
}

// 3. 非法字符检测
for (char c : msg.message())
{
    if (c == '\0' || (c > 0 && c < 32 && c != '\n' && c != '\r' && c != '\t'))
    {
        log_anomaly("INVALID_CHAR", "ASCII: " + std::to_string((int)c));
    }
}

// 4. 数据类型检测
if (msg.data_type() > 100)
{
    log_anomaly("INVALID_DATA_TYPE", "Type: " + std::to_string(type));
}

// 5. 序列号检测
if (current_seq != expected_seq)
{
    log_anomaly("SEQUENCE_ANOMALY", "Expected: " + std::to_string(expected) + 
                ", Got: " + std::to_string(current));
}
```

---

## 运行测试

### 快速开始

```bash
cd examples/cpp/fuzzing_test

# 1. 构建所有版本
./tools/build_all.sh

# 2. 运行测试（1000 条消息）
./tools/run_test.sh

# 3. 查看结果
cat monitor_node_*.log | grep ANOMALY
```

### 自定义参数

```bash
# 发送 2000 条消息，间隔 100ms
./tools/run_test.sh 2000 100
```

### 查看统计

测试结束后会自动显示：
- 发送统计（成功/失败率）
- 策略使用统计（每种策略的使用次数）
- 性能统计（延迟、吞吐量）
- 异常检测摘要

---

## 扩展开发

### 添加新策略

1. **在 `FuzzerNode.cpp` 中添加新枚举**：
```cpp
enum class FuzzStrategy
{
    // ... 现有策略 ...
    NEW_STRATEGY,        // 新策略
};
```

2. **实现生成函数**：
```cpp
void generate_new_strategy(SimpleTestMessage& msg)
{
    // 实现你的策略逻辑
}
```

3. **添加到 switch 语句**：
```cpp
case FuzzStrategy::NEW_STRATEGY:
    generate_new_strategy(msg);
    break;
```

4. **更新计数器和统计**：
- 修改 `dist_strategy_(0, 10)` 为新范围
- 在 `print_strategy_stats()` 中添加名称

### 策略建议

可以考虑添加的新策略：
- **时间戳攻击**：负数时间戳、未来时间戳
- **XML/JSON 注入**：如果消息使用结构化数据
- **SQL 注入模式**：`'; DROP TABLE--`
- **路径遍历**：`../../etc/passwd`
- **RTPS 协议畸形**：直接操作 RTPS 层
- **QoS 攻击**：极端的 QoS 参数

---

## 参考资料

### 模糊测试相关
- [AFL++ 文档](https://github.com/AFLplusplus/AFLplusplus)
- [libFuzzer 教程](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)

### Sanitizer 文档
- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [MemorySanitizer](https://github.com/google/sanitizers/wiki/MemorySanitizer)

### DDS 相关
- [OMG DDS 规范](https://www.omg.org/spec/DDS/)
- [Fast-DDS 文档](https://fast-dds.docs.eprosima.com/)
- [RTPS 协议](https://www.omg.org/spec/DDSI-RTPS/)

### 安全测试
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CERT C Coding Standard](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard)

---

## 许可证

Apache License 2.0

---

## 更新日志

### v1.0 (2024-12-12)
- ✅ 实现 10 种基础模糊测试策略
- ✅ 轮询模式确保策略均匀分布
- ✅ 集成 ASAN/UBSAN 检测
- ✅ 完整的统计和日志系统

### 未来计划
- [ ] 集成 AFL++ 进行演化式模糊测试
- [ ] RTPS 协议层直接注入
- [ ] 分布式多节点压力测试
- [ ] 自动化回归测试套件
- [ ] CI/CD 集成

