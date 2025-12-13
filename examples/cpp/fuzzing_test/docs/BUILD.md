# 构建说明

## 方法一：在 Fast-DDS 主项目中构建（推荐）

这是最简单的方法，因为所有依赖都已经包含在主项目中。

### 步骤：

1. **回到 Fast-DDS 根目录**
```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS
```

2. **创建构建目录**
```bash
mkdir -p build && cd build
```

3. **配置 CMake（启用示例）**
```bash
cmake -DCOMPILE_EXAMPLES=ON ..
```

4. **编译整个项目（包括我们的 fuzzing_test）**
```bash
make -j$(sysctl -n hw.ncpu)
```

5. **查找生成的可执行文件**
```bash
# 可执行文件会在
find . -name "fuzzer_node" -o -name "monitor_node_*"
```

6. **运行测试**
```bash
cd examples/cpp/fuzzing_test

# 启动监控节点（在不同终端）
./monitor_node_asan &
./monitor_node_ubsan &
./monitor_node_full &

# 启动 fuzzer
./fuzzer_node 1000 100
```

### 使用 ASAN/UBSAN

如果要启用 sanitizers，需要在配置时添加编译选项：

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/build

# 启用 ASAN
cmake -DCOMPILE_EXAMPLES=ON \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address" \
      ..

make -j$(sysctl -n hw.ncpu)
```

## 方法二：独立构建（需要先安装 Fast-DDS）

如果你已经在系统中安装了 Fast-DDS，可以独立构建：

### 前置条件：

1. **安装 Fast-DDS**
```bash
# 从源码安装 Fast-DDS
cd /Users/ruanyangdong/Desktop/program/Fast-DDS
mkdir -p build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

2. **生成 IDL 类型代码**

fuzzing_test 依赖 IDL 生成的代码，需要先生成：

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/examples/cpp/fuzzing_test

# 使用 fastddsgen 生成类型支持代码
fastddsgen -replace TestMessage.idl
```

这会生成以下文件：
- `TestMessage.hpp`
- `TestMessagePubSubTypes.cxx`
- `TestMessagePubSubTypes.hpp`
- `TestMessageCdrAux.hpp`
- `TestMessageCdrAux.ipp`
- `TestMessageTypeObjectSupport.cxx`
- `TestMessageTypeObjectSupport.hpp`

3. **独立构建**
```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/examples/cpp/fuzzing_test

# 方法 1：使用我们的构建脚本
./tools/build_all.sh

# 方法 2：手动 CMake
mkdir -p build && cd build
cmake ..
make -j$(sysctl -n hw.ncpu)
```

## 当前问题分析

你遇到的错误是因为：

1. ❌ 直接在 `fuzzing_test` 目录运行 `make build` 
2. ❌ Fast-DDS 依赖库还没有构建
3. ❌ IDL 生成的类型代码还不存在

## 推荐的构建流程

```bash
# 1. 回到 Fast-DDS 根目录
cd /Users/ruanyangdong/Desktop/program/Fast-DDS

# 2. 创建并进入构建目录
mkdir -p build && cd build

# 3. 配置（启用示例编译）
cmake -DCOMPILE_EXAMPLES=ON ..

# 4. 编译
make -j$(sysctl -n hw.ncpu)

# 5. 可执行文件位置
# Fast-DDS/build/examples/cpp/fuzzing_test/fuzzer_node
# Fast-DDS/build/examples/cpp/fuzzing_test/monitor_node_asan
# Fast-DDS/build/examples/cpp/fuzzing_test/monitor_node_ubsan
# Fast-DDS/build/examples/cpp/fuzzing_test/monitor_node_full
```

## 快速测试

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/build/examples/cpp/fuzzing_test

# 在后台启动监控节点
./monitor_node_asan > monitor1.log 2>&1 &
./monitor_node_ubsan > monitor2.log 2>&1 &
./monitor_node_full > monitor3.log 2>&1 &

# 等待几秒让节点启动
sleep 3

# 运行 fuzzer（发送100条消息，快速测试）
./fuzzer_node 100 50

# 查看日志
tail -f *.log
```

## 故障排查

### 问题：找不到 fastddsgen

如果需要独立构建，但没有 `fastddsgen`：

```bash
# 安装 Fast-DDS-Gen
git clone https://github.com/eProsima/Fast-DDS-Gen.git
cd Fast-DDS-Gen
./gradlew assemble
sudo cp share/fastddsgen /usr/local/bin/
```

### 问题：找不到 fastcdr

确保在主项目构建中包含了 fastcdr：

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS
git submodule update --init --recursive
```

### 问题：Sanitizer 链接错误

在 macOS 上，Clang 的 sanitizer 可能需要特殊处理：

```bash
# 检查编译器版本
clang++ --version

# 如果遇到链接问题，可能需要使用系统的 sanitizer 库
export DYLD_INSERT_LIBRARIES=/usr/lib/clang/XX.X.X/lib/darwin/libclang_rt.asan_osx_dynamic.dylib
```

## 下一步

构建成功后，参考 [QUICKSTART.md](QUICKSTART.md) 开始测试！

