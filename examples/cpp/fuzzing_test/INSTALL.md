# 安装和构建指南

## 问题说明

构建 Fast-DDS 需要几个依赖库：
1. ✅ **fastcdr** - 已通过 git submodule 初始化
2. ✅ **asio** - 已通过 git submodule 初始化  
3. ✅ **tinyxml2** - 已通过 git submodule 初始化
4. ❌ **foonathan_memory** - 需要单独安装

## 解决方案

### 方案 1：从源码构建 foonathan_memory（推荐，无需认证）

```bash
# 1. 克隆并构建 foonathan_memory
cd /tmp
git clone https://github.com/foonathan/memory.git foonathan_memory
cd foonathan_memory
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(sysctl -n hw.ncpu)
sudo make install

# 2. 回到 Fast-DDS 目录构建
cd /Users/ruanyangdong/Desktop/program/Fast-DDS
mkdir -p build && cd build

# 3. 配置（使用系统的 foonathan_memory）
cmake -DCOMPILE_EXAMPLES=ON -DTHIRDPARTY=FORCE -DTHIRDPARTY_UPDATE=OFF ..

# 4. 编译（这会需要一些时间）
make -j$(sysctl -n hw.ncpu)

# 5. 可执行文件在
cd examples/cpp/fuzzing_test
ls -la
```

### 方案 2：使用 Homebrew 安装（可能需要认证）

**注意**：此方法可能遇到 GitHub 认证问题。如果失败，请使用方案 1。

```bash
# 如果遇到认证问题，先手动克隆 tap
mkdir -p /opt/homebrew/Library/Taps/foonathan
git clone https://github.com/foonathan/homebrew-memory.git \
  /opt/homebrew/Library/Taps/foonathan/homebrew-memory

# 然后安装
brew install foonathan_memory

# 回到 Fast-DDS 构建
cd /Users/ruanyangdong/Desktop/program/Fast-DDS
mkdir -p build && cd build
cmake -DCOMPILE_EXAMPLES=ON -DTHIRDPARTY=FORCE -DTHIRDPARTY_UPDATE=OFF ..
make -j$(sysctl -n hw.ncpu)
```

### 方案 3：使用 colcon 构建（ROS 用户推荐）

```bash
# 1. 安装 colcon
pip3 install colcon-common-extensions

# 2. 在 Fast-DDS 父目录创建工作空间
cd /Users/ruanyangdong/Desktop/program
mkdir -p fastdds_ws/src && cd fastdds_ws
ln -s /Users/ruanyangdong/Desktop/program/Fast-DDS src/

# 3. 使用 colcon 构建
colcon build --cmake-args -DCOMPILE_EXAMPLES=ON

# 4. Source 环境
source install/setup.bash

# 5. 可执行文件在
cd build/Fast-DDS/examples/cpp/fuzzing_test
```

## 当前推荐：从源码构建（一步到位）

**这是最可靠的方法，不需要任何认证：**

```bash
# 一步到位 - 构建 foonathan_memory 和 Fast-DDS
cd /tmp && \
git clone https://github.com/foonathan/memory.git foonathan_memory && \
cd foonathan_memory && \
mkdir build && cd build && \
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
make -j$(sysctl -n hw.ncpu) && \
sudo make install && \
\
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/build && \
rm -rf * && \
cmake -DCOMPILE_EXAMPLES=ON -DTHIRDPARTY=FORCE -DTHIRDPARTY_UPDATE=OFF .. && \
make -j$(sysctl -n hw.ncpu) && \
\
echo "✅ 构建完成！" && \
echo "可执行文件位置: $(pwd)/examples/cpp/fuzzing_test/"
```

**时间估计**：5-15 分钟（取决于电脑性能）

## 验证安装

构建成功后，验证可执行文件：

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/build/examples/cpp/fuzzing_test

# 应该看到这些文件
ls -la | grep node

# 输出类似：
# fuzzer_node
# monitor_node_asan
# monitor_node_ubsan  
# monitor_node_full
```

## 快速测试

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/build/examples/cpp/fuzzing_test

# 后台启动监控节点
./monitor_node_asan > m1.log 2>&1 &
./monitor_node_ubsan > m2.log 2>&1 &
./monitor_node_full > m3.log 2>&1 &

# 等待启动
sleep 3

# 运行 fuzzer（发送 10 条消息快速测试）
./fuzzer_node 10 100

# 查看日志
cat *.log
```

## 如果还有问题

### 检查系统是否已有 foonathan_memory

```bash
# 查找 foonathan_memory
find /usr/local -name "*foonathan*" 2>/dev/null
find /opt/homebrew -name "*foonathan*" 2>/dev/null
```

### 查看详细的 CMake 错误

```bash
cd /Users/ruanyangdong/Desktop/program/Fast-DDS/build
cmake -DCOMPILE_EXAMPLES=ON -DTHIRDPARTY=FORCE -DTHIRDPARTY_UPDATE=OFF .. 2>&1 | tee cmake_output.log
cat cmake_output.log
```

### 设置 CMAKE_PREFIX_PATH

如果 foonathan_memory 安装在非标准位置：

```bash
export CMAKE_PREFIX_PATH="/usr/local:$CMAKE_PREFIX_PATH"
# 或者
export CMAKE_PREFIX_PATH="/opt/homebrew:$CMAKE_PREFIX_PATH"

cmake -DCOMPILE_EXAMPLES=ON ..
```

## 下一步

成功构建后，参考：
- [QUICKSTART.md](QUICKSTART.md) - 快速开始测试
- [README.md](README.md) - 完整使用文档
- [BUILD.md](BUILD.md) - 详细构建说明

