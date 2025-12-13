# DDS 协议模糊测试框架

## 概述

这是一个用于 Fast-DDS 协议模糊测试的完整框架，包含一个异常节点（Fuzzer）和三个监控节点（Monitor），用于检测 DDS 协议实现中可能存在的安全漏洞和异常行为。

## 架构

### 节点组成

1. **Fuzzer Node（异常节点）**
   - 生成和发送各种畸形数据包
   - 实现多种模糊测试策略
   - 可配置发送速率和消息数量

2. **Monitor Node 1（ASAN）**
   - 启用 AddressSanitizer
   - 检测内存错误：缓冲区溢出、UAF、内存泄漏等

3. **Monitor Node 2（UBSAN）**
   - 启用 UndefinedBehaviorSanitizer
   - 检测未定义行为：整数溢出、除零、类型错误等

4. **Monitor Node 3（ASAN + UBSAN）**
   - 同时启用两种 Sanitizer
   - 提供全面的运行时检测

## 模糊测试策略

框架实现了以下模糊测试策略：

1. **正常消息（NORMAL）** - 基线测试
2. **位翻转（BIT_FLIP）** - 随机翻转消息中的位
3. **边界值（BOUNDARY_VALUES）** - 测试整数边界值
4. **超大负载（LARGE_PAYLOAD）** - 发送超大字符串
5. **随机数据（RANDOM_DATA）** - 完全随机的数据
6. **序列号混乱（SEQUENCE_CHAOS）** - 打乱消息序列号
7. **特殊字符（SPECIAL_CHARS）** - 注入控制字符和特殊字符
8. **空字符注入（NULL_INJECTION）** - 在字符串中注入空字符
9. **溢出尝试（OVERFLOW_ATTEMPT）** - 尝试触发溢出
10. **格式字符串（FORMAT_STRING）** - 格式字符串攻击尝试

## 构建

### 前置要求

- CMake 3.20+
- C++11 编译器（GCC/Clang）
- Fast-DDS 3.x
- FastCDR 2.x

### 编译步骤

```bash
cd examples/cpp/fuzzing_test

# 标准编译（不启用 Sanitizers）
mkdir build && cd build
cmake ..
make

# 启用 ASAN 编译
mkdir build_asan && cd build_asan
cmake -DENABLE_ASAN=ON ..
make

# 启用 UBSAN 编译
mkdir build_ubsan && cd build_ubsan
cmake -DENABLE_UBSAN=ON ..
make

# 启用全部 Sanitizers
mkdir build_full && cd build_full
cmake -DENABLE_ASAN=ON -DENABLE_UBSAN=ON ..
make
```

### 快速编译（推荐）

```bash
# 使用提供的脚本一键编译所有版本
./tools/build_all.sh
```

## 运行

### 手动运行

在不同的终端中分别启动各个节点：

```bash
# 终端 1 - 启动 Fuzzer 节点
./build/fuzzer_node [消息数量] [发送间隔ms]
# 例如: ./build/fuzzer_node 1000 100

# 终端 2 - 启动 ASAN 监控节点
./build_asan/monitor_node_asan

# 终端 3 - 启动 UBSAN 监控节点
./build_ubsan/monitor_node_ubsan

# 终端 4 - 启动完整监控节点
./build_full/monitor_node_full
```

### 使用启动脚本

```bash
# 启动所有节点（在后台运行监控节点）
./tools/run_test.sh

# 指定参数运行
./tools/run_test.sh 2000 50  # 发送2000条消息，间隔50ms
```

## 输出和日志

### 日志文件

每个节点都会生成独立的日志文件：

- `fuzzer_node.log` - Fuzzer 节点日志
- `monitor_node_1.log` - Monitor 1 日志（ASAN）
- `monitor_node_2.log` - Monitor 2 日志（UBSAN）
- `monitor_node_3.log` - Monitor 3 日志（ASAN+UBSAN）

### 控制台输出

- 实时显示关键信息
- 异常检测警告
- 统计信息

### 异常检测

当检测到异常时，日志会包含：

```
[时间戳] [CRIT] [DETECTOR] !!! ANOMALY DETECTED !!! Type: ANOMALY_TYPE, Details: ...
```

常见异常类型：

- `NULL_POINTER` - 空指针
- `LARGE_MESSAGE` - 超大消息
- `INVALID_CHAR` - 非法字符
- `INVALID_DATA_TYPE` - 非法数据类型
- `SIZE_MISMATCH` - 大小不匹配
- `SEQUENCE_ANOMALY` - 序列号异常

## 数据分析

### 统计信息

每个监控节点运行结束时会输出统计信息：

```
========== Statistics for Monitor-X ==========
  Runtime: X seconds
  Messages received: X
  Total bytes: X
  Errors detected: X
  Messages/sec: X
  Throughput: X MB/s
  Error rate: X%
==================================================
```

### Sanitizer 输出

如果触发 Sanitizer 检测，会看到详细的错误报告：

**ASAN 示例：**
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
==12345==READ of size 4 at ...
    #0 0x... in function_name
    ...
=================================================================
```

**UBSAN 示例：**
```
runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
```

## 扩展开发

### 添加新的模糊测试策略

在 `FuzzerNode.cpp` 中：

1. 在 `FuzzStrategy` 枚举中添加新策略
2. 在 `FuzzEngine::generate_fuzzed_message()` 中添加处理
3. 实现对应的生成函数

### 添加新的检测逻辑

在 `MonitorNode.cpp` 中：

1. 在 `MonitorListener::process_simple_message()` 中添加检测逻辑
2. 使用 `Logger::instance().log_anomaly()` 记录异常

### 添加新的消息类型

1. 在 `TestMessage.idl` 中定义新的消息结构
2. 重新编译生成 PubSub 类型
3. 在 Fuzzer 和 Monitor 中添加对应的处理逻辑

## 故障排查

### 节点无法启动

- 检查 Fast-DDS 是否正确安装
- 确认 domain ID 一致（默认为 0）
- 查看日志文件获取详细错误信息

### 节点无法互相发现

- 检查网络配置
- 确认防火墙设置
- 验证 DDS Discovery 配置

### Sanitizer 未生效

- 确认使用了正确的构建目录
- 检查编译选项是否正确设置
- 验证编译器是否支持 Sanitizer

## 下一步计划

- [ ] 集成 libFuzzer 或 AFL++ 进行更深入的模糊测试
- [ ] 添加网络抓包和重放功能
- [ ] 实现协议层面的 RTPS 消息篡改
- [ ] 添加更多的异常检测规则
- [ ] 支持多 Domain 和多 Topic 测试
- [ ] 机器人平台（机器狗）实战测试

## 相关文档

- [Fast-DDS 官方文档](https://fast-dds.docs.eprosima.com/)
- [AddressSanitizer 文档](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [UndefinedBehaviorSanitizer 文档](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- [DDS 协议规范](https://www.omg.org/spec/DDS/)

## 许可证

Apache License 2.0

## 贡献

欢迎提交 Issue 和 Pull Request！

