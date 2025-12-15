#!/bin/bash

# DDS Fuzzing Test - 测试启动脚本
# 启动所有节点进行模糊测试
#
# 使用方法:
#   ./run_test.sh [消息数量] [间隔ms] [模式]
#
# 模式:
#   basic    - 基础模糊测试（默认）
#   advanced - 高级协议感知模糊测试
#   attack   - 攻击模式测试
#
# 示例:
#   ./run_test.sh 1000 50           # 基础模式
#   ./run_test.sh 5000 50 advanced  # 高级模式
#   ./run_test.sh 2000 50 attack    # 攻击模式

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
FUZZING_TEST_DIR="$SCRIPT_DIR/.."

# 项目根目录（相对于 examples/cpp/fuzzing_test/tools）
PROJECT_ROOT="$FUZZING_TEST_DIR/../../.."
BUILD_DIR="$PROJECT_ROOT/build"
EXAMPLE_BUILD_DIR="$BUILD_DIR/examples/cpp/fuzzing_test"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认参数
MESSAGE_COUNT=${1:-1000}  # 1000 条消息，每种策略 100 条
INTERVAL_MS=${2:-50}      # 发送间隔 50ms
TEST_MODE=${3:-basic}     # 测试模式: basic, advanced, attack

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  DDS Fuzzing Test - 启动测试${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "测试配置："
echo "  消息数量: $MESSAGE_COUNT"
echo "  发送间隔: ${INTERVAL_MS}ms"
echo "  测试模式: $TEST_MODE"
echo ""

# 检查基础可执行文件是否存在
check_basic_binaries() {
    if [ ! -f "$EXAMPLE_BUILD_DIR/fuzzer_node" ]; then
        echo -e "${RED}错误: 找不到 fuzzer_node${NC}"
        echo "路径: $EXAMPLE_BUILD_DIR/fuzzer_node"
        echo ""
        echo "请先在项目根目录构建项目:"
        echo "  cd $PROJECT_ROOT"
        echo "  mkdir -p build && cd build"
        echo "  cmake .. -DENABLE_ASAN=ON -DENABLE_UBSAN=ON"
        echo "  make -j\$(nproc)"
        exit 1
    fi
    
    if [ ! -f "$EXAMPLE_BUILD_DIR/monitor_node_asan" ] || \
       [ ! -f "$EXAMPLE_BUILD_DIR/monitor_node_ubsan" ] || \
       [ ! -f "$EXAMPLE_BUILD_DIR/monitor_node_full" ]; then
        echo -e "${RED}错误: 找不到 monitor 节点${NC}"
        echo "路径: $EXAMPLE_BUILD_DIR/"
        echo "请先在项目根目录构建项目"
        exit 1
    fi
}

# 检查高级模糊器
check_advanced_binaries() {
    if [ ! -f "$EXAMPLE_BUILD_DIR/advanced_fuzzer_node" ]; then
        echo -e "${YELLOW}警告: 找不到 advanced_fuzzer_node${NC}"
        echo "高级模糊测试器未构建"
        echo ""
        echo "要构建高级模糊测试器，请在项目根目录重新 cmake:"
        echo "  cd $PROJECT_ROOT/build"
        echo "  cmake .. -DENABLE_ASAN=ON -DENABLE_UBSAN=ON"
        echo "  make advanced_fuzzer_node -j\$(nproc)"
        echo ""
        return 1
    fi
    return 0
}

check_basic_binaries

# 切换到 fuzzing_test 目录
cd "$FUZZING_TEST_DIR"

# 清理旧的日志文件
echo -e "${YELLOW}清理旧日志文件...${NC}"
mkdir -p output
rm -f output/*.log output/*.out

# 创建 PID 文件目录
mkdir -p .pids

# 清理函数
cleanup() {
    echo ""
    echo -e "${YELLOW}正在停止所有节点...${NC}"
    
    # 发送 SIGTERM 信号
    if [ -f .pids/monitor1.pid ]; then
        kill $(cat .pids/monitor1.pid) 2>/dev/null || true
    fi
    if [ -f .pids/monitor2.pid ]; then
        kill $(cat .pids/monitor2.pid) 2>/dev/null || true
    fi
    if [ -f .pids/monitor3.pid ]; then
        kill $(cat .pids/monitor3.pid) 2>/dev/null || true
    fi
    
    # 等待进程结束
    sleep 2
    
    # 清理 PID 文件
    rm -rf .pids
    
    echo -e "${GREEN}所有节点已停止${NC}"
    echo ""
    echo -e "${BLUE}=== 测试结果摘要 ===${NC}"
    echo ""
    
    # 显示日志摘要
    for log in output/monitor_node_*.log; do
        if [ -f "$log" ]; then
            echo -e "${BLUE}--- $log ---${NC}"
            grep -E "(ANOMALY|ERROR|Statistics)" "$log" | tail -20 || echo "无异常检测"
            echo ""
        fi
    done
    
    echo -e "${GREEN}日志文件：${NC}"
    ls -lh output/*.log 2>/dev/null || echo "无日志文件"
    
    exit 0
}

# 设置信号处理
trap cleanup SIGINT SIGTERM

echo -e "${YELLOW}启动监控节点...${NC}"

# 启动 Monitor Node 1 (ASAN)
echo -e "${BLUE}启动 Monitor Node 1 (ASAN)...${NC}"
"$EXAMPLE_BUILD_DIR/monitor_node_asan" > output/monitor1.out 2>&1 &
MONITOR1_PID=$!
echo $MONITOR1_PID > .pids/monitor1.pid
echo "  PID: $MONITOR1_PID"

# 启动 Monitor Node 2 (UBSAN)
echo -e "${BLUE}启动 Monitor Node 2 (UBSAN)...${NC}"
"$EXAMPLE_BUILD_DIR/monitor_node_ubsan" > output/monitor2.out 2>&1 &
MONITOR2_PID=$!
echo $MONITOR2_PID > .pids/monitor2.pid
echo "  PID: $MONITOR2_PID"

# 启动 Monitor Node 3 (ASAN+UBSAN)
echo -e "${BLUE}启动 Monitor Node 3 (ASAN+UBSAN)...${NC}"
"$EXAMPLE_BUILD_DIR/monitor_node_full" > output/monitor3.out 2>&1 &
MONITOR3_PID=$!
echo $MONITOR3_PID > .pids/monitor3.pid
echo "  PID: $MONITOR3_PID"

# 等待监控节点启动
echo ""
echo -e "${YELLOW}等待监控节点初始化 (5秒)...${NC}"
sleep 5

# 检查监控节点是否正在运行
for pid in $MONITOR1_PID $MONITOR2_PID $MONITOR3_PID; do
    if ! ps -p $pid > /dev/null; then
        echo -e "${RED}错误: 监控节点 (PID $pid) 启动失败${NC}"
        cleanup
        exit 1
    fi
done

echo -e "${GREEN}所有监控节点已启动${NC}"
echo ""

# 启动 Fuzzer Node（前台运行）
echo -e "${BLUE}启动 Fuzzer Node...${NC}"
echo -e "${YELLOW}开始发送模糊测试消息...${NC}"
echo ""

case $TEST_MODE in
    basic)
        echo "使用基础模糊测试器..."
        "$EXAMPLE_BUILD_DIR/fuzzer_node" $MESSAGE_COUNT $INTERVAL_MS
        ;;
    advanced)
        if check_advanced_binaries; then
            echo "使用高级协议感知模糊测试器..."
            "$EXAMPLE_BUILD_DIR/advanced_fuzzer_node" \
                --mode hybrid \
                --iterations $MESSAGE_COUNT \
                --interval $INTERVAL_MS
        else
            echo "回退到基础模糊测试器..."
            "$EXAMPLE_BUILD_DIR/fuzzer_node" $MESSAGE_COUNT $INTERVAL_MS
        fi
        ;;
    attack)
        if check_advanced_binaries; then
            echo "使用攻击模式模糊测试器..."
            "$EXAMPLE_BUILD_DIR/advanced_fuzzer_node" \
                --mode attack \
                --iterations $MESSAGE_COUNT \
                --interval $INTERVAL_MS
        else
            echo "回退到基础模糊测试器..."
            "$EXAMPLE_BUILD_DIR/fuzzer_node" $MESSAGE_COUNT $INTERVAL_MS
        fi
        ;;
    protocol)
        if check_advanced_binaries; then
            echo "使用协议感知模糊测试器..."
            "$EXAMPLE_BUILD_DIR/advanced_fuzzer_node" \
                --mode protocol \
                --iterations $MESSAGE_COUNT \
                --interval $INTERVAL_MS
        else
            echo "回退到基础模糊测试器..."
            "$EXAMPLE_BUILD_DIR/fuzzer_node" $MESSAGE_COUNT $INTERVAL_MS
        fi
        ;;
    inject)
        if check_advanced_binaries; then
            echo "使用网络注入模糊测试器..."
            "$EXAMPLE_BUILD_DIR/advanced_fuzzer_node" \
                --inject \
                --mode attack \
                --iterations $MESSAGE_COUNT \
                --interval $INTERVAL_MS
        else
            echo -e "${RED}网络注入模式需要高级模糊测试器${NC}"
            exit 1
        fi
        ;;
    *)
        echo -e "${RED}未知测试模式: $TEST_MODE${NC}"
        echo "可用模式: basic, advanced, attack, protocol, inject"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}Fuzzer 完成发送${NC}"
echo -e "${YELLOW}等待监控节点处理剩余消息 (5秒)...${NC}"
sleep 5

# 清理
cleanup


