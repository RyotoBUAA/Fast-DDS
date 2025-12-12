# 快速入门指南

## 5 分钟快速开始

### 1. 构建项目

```bash
cd examples/cpp/fuzzing_test
./build_all.sh
```

等待编译完成（可能需要几分钟）。

### 2. 运行测试

```bash
./run_test.sh
```

这会启动所有四个节点并开始模糊测试。

### 3. 查看结果

测试结束后，检查生成的日志文件：

```bash
# 查看所有日志中的异常检测
grep "ANOMALY" *.log

# 查看错误信息
grep "ERROR" *.log

# 查看统计信息
grep "Statistics" *.log -A 10
```

## 自定义测试

### 修改测试参数

```bash
# 发送 2000 条消息，每条间隔 50ms
./run_test.sh 2000 50

# 发送 500 条消息，每条间隔 200ms
./run_test.sh 500 200
```

### 单独运行节点

如果你想更细粒度地控制测试，可以在不同终端手动启动节点：

**终端 1 - Monitor 1 (ASAN):**
```bash
cd build_asan
./monitor_node_asan
```

**终端 2 - Monitor 2 (UBSAN):**
```bash
cd build_ubsan
./monitor_node_ubsan
```

**终端 3 - Monitor 3 (Full):**
```bash
cd build_full
./monitor_node_full
```

**终端 4 - Fuzzer:**
```bash
cd build
# 参数: [消息数量] [间隔ms]
./fuzzer_node 1000 100
```

## 理解输出

### 正常输出示例

```
[2024-12-12 10:30:45.123] [INFO] [FUZZER] Matched with subscriber
[2024-12-12 10:30:45.456] [INFO] [Monitor-1] Received message #100
```

### 异常检测示例

```
[2024-12-12 10:30:50.789] [CRIT] [DETECTOR] !!! ANOMALY DETECTED !!! 
Type: SEQUENCE_ANOMALY, Details: Sequence number anomaly - Expected: 100, Got: 1000, Gap: 900
```

### Sanitizer 错误示例

如果触发内存错误，ASAN 会输出：

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4 at 0x...
...
=================================================================
```

## 下一步

1. **分析日志** - 查看检测到的异常模式
2. **调整策略** - 修改 `FuzzerNode.cpp` 中的模糊测试策略
3. **添加检测** - 在 `MonitorNode.cpp` 中添加自定义检测逻辑
4. **扩展消息** - 在 `TestMessage.idl` 中定义新的测试消息类型

## 常见问题

### Q: 编译失败？

A: 确保已安装 Fast-DDS 和 FastCDR：
```bash
# 检查是否安装
pkg-config --modversion fastdds
```

### Q: 节点无法互相发现？

A: 
1. 检查防火墙设置
2. 确认所有节点使用相同的 Domain ID（默认为 0）
3. 尝试禁用 SHM 传输，只使用 UDP

### Q: 没有检测到异常？

A: 这是好事！说明 Fast-DDS 在处理畸形数据时很健壮。你可以：
1. 增加消息数量
2. 添加更激进的模糊测试策略
3. 尝试协议层面的消息篡改

### Q: 如何停止测试？

A: 按 `Ctrl+C`，脚本会自动清理所有节点。

## 技术支持

查看详细文档：[README.md](README.md)

