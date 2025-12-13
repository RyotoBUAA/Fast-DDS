#!/bin/bash

# DDS Fuzzing Test - 一键构建脚本
# 构建所有版本的可执行文件

set -e

echo "========================================="
echo "  DDS Fuzzing Test - 构建所有版本"
echo "========================================="

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
FUZZING_TEST_DIR="$SCRIPT_DIR/.."
cd "$FUZZING_TEST_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 清理旧的构建
echo -e "${YELLOW}清理旧的构建目录...${NC}"
rm -rf build build_asan build_ubsan build_full

# 1. 标准构建（Fuzzer Node）
echo ""
echo -e "${GREEN}=== 构建 Fuzzer Node ===${NC}"
mkdir -p build && cd build
cmake ..
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
cd ..
echo -e "${GREEN}✓ Fuzzer Node 构建完成${NC}"

# 2. ASAN 构建（Monitor Node 1）
echo ""
echo -e "${GREEN}=== 构建 Monitor Node (ASAN) ===${NC}"
mkdir -p build_asan && cd build_asan
cmake -DENABLE_ASAN=ON ..
make monitor_node_asan -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
cd ..
echo -e "${GREEN}✓ Monitor Node (ASAN) 构建完成${NC}"

# 3. UBSAN 构建（Monitor Node 2）
echo ""
echo -e "${GREEN}=== 构建 Monitor Node (UBSAN) ===${NC}"
mkdir -p build_ubsan && cd build_ubsan
cmake -DENABLE_UBSAN=ON ..
make monitor_node_ubsan -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
cd ..
echo -e "${GREEN}✓ Monitor Node (UBSAN) 构建完成${NC}"

# 4. 完整 Sanitizer 构建（Monitor Node 3）
echo ""
echo -e "${GREEN}=== 构建 Monitor Node (ASAN+UBSAN) ===${NC}"
mkdir -p build_full && cd build_full
cmake -DENABLE_ASAN=ON -DENABLE_UBSAN=ON ..
make monitor_node_full -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
cd ..
echo -e "${GREEN}✓ Monitor Node (ASAN+UBSAN) 构建完成${NC}"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  构建完成！${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "可执行文件位置："
echo "  - Fuzzer Node:        build/fuzzer_node"
echo "  - Monitor Node 1:     build_asan/monitor_node_asan"
echo "  - Monitor Node 2:     build_ubsan/monitor_node_ubsan"
echo "  - Monitor Node 3:     build_full/monitor_node_full"
echo ""
echo "运行测试："
echo "  ./tools/run_test.sh"
echo ""


