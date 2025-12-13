# DDS 高级模糊测试指南

本文档介绍了集成到 Fast-DDS 的高级模糊测试工具，包括覆盖率引导模糊测试、协议感知模糊测试和多种攻击模式。

## 目录

1. [工具概述](#工具概述)
2. [安装依赖](#安装依赖)
3. [构建方法](#构建方法)
4. [使用指南](#使用指南)
5. [模糊测试策略](#模糊测试策略)
6. [最佳实践](#最佳实践)

---

## 工具概述

### 1. 高级模糊测试节点 (AdvancedFuzzerNode)

协议感知的智能模糊测试器，理解 RTPS/DDS 协议结构。

**特性：**
- RTPS 协议感知的消息生成
- 结构化变异策略
- 种子队列管理
- 覆盖率追踪（简化版）
- 多种 DDS 攻击模式

### 2. libFuzzer Harness

基于 LLVM libFuzzer 的覆盖率引导模糊测试器。

**特性：**
- 代码覆盖率引导
- 自动种子进化
- 与 ASAN/UBSAN 深度集成
- 高效的持久模式

### 3. AFL++ Harness

支持 AFL++ 的模糊测试 harness。

**特性：**
- AFL++ 持久模式支持
- 并行模糊测试
- 崩溃去重
- 字典支持

### 4. 网络注入模糊测试器

直接向 RTPS 端口发送畸形数据包。

**特性：**
- 直接 UDP 注入
- 多播支持
- 不依赖 DDS API

---

## 安装依赖

### macOS

```bash
# 安装 Clang (libFuzzer)
xcode-select --install

# 安装 AFL++
brew install aflplusplus

# 安装依赖
brew install cmake ninja
```

### Ubuntu/Debian

```bash
# 安装 Clang
sudo apt install clang llvm

# 安装 AFL++
sudo apt install afl++

# 或从源码安装最新版 AFL++
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus
make distrib
sudo make install
```

### 验证安装

```bash
# 检查 Clang
clang++ --version

# 检查 libFuzzer 支持
echo "int LLVMFuzzerTestOneInput(const char *data, long size) { return 0; }" > test.cpp
clang++ -fsanitize=fuzzer test.cpp -o test_fuzzer && rm test.cpp test_fuzzer

# 检查 AFL++
afl-clang-fast++ --version
```

---

## 构建方法

### 快速构建

```bash
cd examples/cpp/fuzzing_test

# 基础构建（包含高级模糊器）
./tools/build_advanced.sh --basic

# 启用 libFuzzer
./tools/build_advanced.sh --libfuzzer

# 启用 AFL++
./tools/build_advanced.sh --afl

# 构建所有工具
./tools/build_advanced.sh --all
```

### 手动构建

#### 基础构建

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON -DENABLE_UBSAN=ON
make -j$(nproc)
```

#### libFuzzer 构建

```bash
mkdir build_libfuzzer && cd build_libfuzzer
CC=clang CXX=clang++ cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_LIBFUZZER=ON \
    -DENABLE_ASAN=ON \
    -DENABLE_UBSAN=ON
make -j$(nproc)
```

#### AFL++ 构建

```bash
mkdir build_afl && cd build_afl
CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_AFL=ON
make -j$(nproc)
```

---

## 使用指南

### 1. 高级协议感知模糊测试

```bash
# 混合模式（推荐）
./build/advanced_fuzzer_node --mode hybrid -n 10000 -i 50

# 协议感知模式
./build/advanced_fuzzer_node --mode protocol -n 5000

# 攻击模式
./build/advanced_fuzzer_node --mode attack -n 5000

# 网络注入模式
./build/advanced_fuzzer_node --inject -t 127.0.0.1 -p 7400
```

**参数说明：**
- `-n, --iterations N`: 迭代次数
- `-i, --interval MS`: 发送间隔（毫秒）
- `-m, --mode MODE`: 模糊测试模式
  - `protocol`: 协议感知模式
  - `mutation`: 变异模式
  - `generation`: 生成模式
  - `attack`: 攻击模式
  - `hybrid`: 混合模式（默认）
- `--inject`: 启用网络注入
- `-t, --target IP`: 目标 IP
- `-p, --port PORT`: 目标端口

### 2. libFuzzer 覆盖率引导测试

```bash
# 基本运行
./build_libfuzzer/libfuzzer_harness seeds/

# 使用字典
./build_libfuzzer/libfuzzer_harness seeds/ -dict=dictionaries/rtps.dict

# 限制输入大小
./build_libfuzzer/libfuzzer_harness seeds/ -max_len=65536

# 多工作进程
./build_libfuzzer/libfuzzer_harness seeds/ -jobs=4 -workers=4

# 限时运行
./build_libfuzzer/libfuzzer_harness seeds/ -max_total_time=3600
```

**常用选项：**
- `-max_len=N`: 最大输入大小
- `-dict=FILE`: 字典文件
- `-jobs=N`: 并行任务数
- `-workers=N`: 工作进程数
- `-max_total_time=N`: 最大运行时间（秒）
- `-print_final_stats=1`: 打印最终统计

### 3. AFL++ 模糊测试

```bash
# 基本运行
afl-fuzz -i seeds/ -o output/ -- ./build_afl/afl_harness @@

# 使用字典
afl-fuzz -i seeds/ -o output/ -x dictionaries/rtps.dict -- ./build_afl/afl_harness @@

# 并行模糊测试（主节点）
afl-fuzz -i seeds/ -o output/ -M main -- ./build_afl/afl_harness @@

# 并行模糊测试（从节点）
afl-fuzz -i seeds/ -o output/ -S slave1 -- ./build_afl/afl_harness @@

# 持久模式（更高效）
AFL_PERSISTENT=1 afl-fuzz -i seeds/ -o output/ -- ./build_afl/afl_harness
```

### 4. 配合监控节点使用

```bash
# 终端 1: 启动监控节点
./build/monitor_node_asan

# 终端 2: 启动模糊器
./build/advanced_fuzzer_node --mode attack -n 10000
```

---

## 模糊测试策略

### 协议感知变异策略

| 策略 | 描述 | 适用场景 |
|------|------|----------|
| BIT_FLIP | 随机翻转单个位 | 发现位敏感的边界条件 |
| BYTE_FLIP | 随机翻转单个字节 | 发现字节级错误 |
| INT_BOUNDARY | 整数边界值 | 发现整数溢出 |
| SWAP_SUBMESSAGES | 交换子消息顺序 | 测试消息处理顺序 |
| CORRUPT_LENGTH | 破坏长度字段 | 测试长度验证 |
| CORRUPT_SEQNUM | 破坏序列号 | 测试序列号处理 |

### DDS 攻击模式

| 攻击 | 描述 | 目标 |
|------|------|------|
| SPDP_ATTACK | 伪造发现消息 | 发现协议 |
| HEARTBEAT_ATTACK | 伪造心跳消息 | 可靠性协议 |
| GAP_ATTACK | 声明数据间隙 | 重传逻辑 |
| DATA_INJECTION | 伪造数据消息 | 数据处理 |
| SEQNUM_ATTACK | 异常序列号 | 序列号处理 |
| FRAGMENT_ATTACK | 畸形分片 | 分片重组 |
| SECURITY_ATTACK | 伪造安全消息 | 安全扩展 |

---

## 最佳实践

### 1. 种子选择

- 使用 `seeds/` 目录中的预置种子
- 添加实际的 DDS 通信抓包作为种子
- 保持种子多样性

### 2. 字典使用

```bash
# 合并多个字典
cat dictionaries/*.dict > combined.dict
```

### 3. 覆盖率分析

```bash
# 使用 llvm-cov 分析覆盖率
LLVM_PROFILE_FILE="coverage.profraw" ./libfuzzer_harness seeds/ -runs=10000
llvm-profdata merge -sparse coverage.profraw -o coverage.profdata
llvm-cov show ./libfuzzer_harness -instr-profile=coverage.profdata
```

### 4. 崩溃分析

```bash
# 查看崩溃文件
ls crashes/

# 重现崩溃
./build/advanced_fuzzer_node < crashes/crash_0.bin

# 使用 GDB 分析
gdb --args ./build/monitor_node_asan < crashes/crash_0.bin
```

### 5. 长时间运行

```bash
# 使用 screen 或 tmux
screen -S fuzzing
./build_libfuzzer/libfuzzer_harness seeds/ -max_total_time=86400  # 24小时

# 定期保存语料库
./build_libfuzzer/libfuzzer_harness seeds/ -merge=1 corpus/
```

---

## 输出解释

### libFuzzer 输出

```
#12345  INITED cov: 1234 ft: 567 corp: 100/50Kb exec/s: 1000
#12350  NEW    cov: 1235 ft: 568 corp: 101/51Kb exec/s: 999 L: 234
```

- `#12345`: 执行次数
- `INITED/NEW/REDUCE`: 事件类型
- `cov`: 覆盖的基本块数
- `ft`: 覆盖的特征数
- `corp`: 语料库大小
- `exec/s`: 每秒执行次数

### AFL++ 输出

```
       american fuzzy lop ++4.0
┌─ process timing ─────────────────────────────────────┐
│  run time : 0 days, 1 hrs, 23 min, 45 sec            │
│  last path : 0 sec ago                               │
├─ stage progress ─────────────────────────────────────┤
│  now trying : havoc                                  │
│  stage execs : 1234/5000                             │
├─ findings ───────────────────────────────────────────┤
│  unique crashes : 3                                  │
│  unique hangs : 0                                    │
└──────────────────────────────────────────────────────┘
```

---

## 故障排除

### libFuzzer 编译错误

```
error: undefined reference to '__sanitizer_cov_trace_pc_guard_init'
```

**解决方案：** 确保使用 Clang 编译器：
```bash
CC=clang CXX=clang++ cmake ..
```

### AFL++ 报错

```
[-] Hmm, your system is configured to send core dump notifications to an external utility.
```

**解决方案：**
```bash
# Linux
echo core | sudo tee /proc/sys/kernel/core_pattern
```

### 找不到 Fast-DDS 库

```
Could NOT find fastdds
```

**解决方案：**
```bash
# 设置 PKG_CONFIG_PATH
export PKG_CONFIG_PATH=/path/to/fastdds/lib/pkgconfig:$PKG_CONFIG_PATH

# 或者设置 CMAKE_PREFIX_PATH
cmake .. -DCMAKE_PREFIX_PATH=/path/to/fastdds
```

---

## 参考资料

- [libFuzzer 文档](https://llvm.org/docs/LibFuzzer.html)
- [AFL++ 文档](https://aflplus.plus/)
- [AddressSanitizer](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [RTPS 规范](https://www.omg.org/spec/DDSI-RTPS/)
- [Fast-DDS 文档](https://fast-dds.docs.eprosima.com/)

---

## 许可证

Apache License 2.0

