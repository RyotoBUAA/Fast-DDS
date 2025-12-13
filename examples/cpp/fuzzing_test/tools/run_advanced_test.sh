#!/bin/bash
# ============================================================================
# 高级模糊测试运行脚本
# ============================================================================
#
# 使用方法:
#   ./run_advanced_test.sh [选项]
#
# 选项:
#   --mode MODE     模糊测试模式 (protocol/mutation/generation/attack/hybrid)
#   --iterations N  迭代次数 (默认: 10000)
#   --interval MS   发送间隔毫秒 (默认: 50)
#   --inject        启用网络注入模式
#   --with-monitor  同时启动监控节点
#   --libfuzzer     使用 libFuzzer
#   --afl           使用 AFL++
#   --help          显示帮助
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZING_TEST_DIR="$SCRIPT_DIR/.."
BUILD_DIR="${FUZZING_TEST_DIR}/build"

# 默认参数
MODE="hybrid"
ITERATIONS=10000
INTERVAL=50
USE_INJECT=false
WITH_MONITOR=false
USE_LIBFUZZER=false
USE_AFL=false

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  DDS 高级模糊测试"
    echo "=============================================="
    echo -e "${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

show_help() {
    echo "使用方法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --mode MODE     模糊测试模式:"
    echo "                    protocol   - 协议感知模式"
    echo "                    mutation   - 变异模式"
    echo "                    generation - 生成模式"
    echo "                    attack     - 攻击模式"
    echo "                    hybrid     - 混合模式 (默认)"
    echo "  --iterations N  迭代次数 (默认: 10000)"
    echo "  --interval MS   发送间隔毫秒 (默认: 50)"
    echo "  --inject        启用网络注入模式"
    echo "  --with-monitor  同时启动监控节点"
    echo "  --libfuzzer     使用 libFuzzer 覆盖率引导测试"
    echo "  --afl           使用 AFL++ 测试"
    echo "  --help          显示此帮助"
    echo ""
    echo "示例:"
    echo "  $0 --mode attack --iterations 5000"
    echo "  $0 --mode hybrid --with-monitor"
    echo "  $0 --libfuzzer"
    echo "  $0 --inject --mode attack"
}

cleanup() {
    echo ""
    print_info "正在停止所有进程..."
    
    # 停止后台进程
    jobs -p | xargs -r kill 2>/dev/null || true
    
    print_success "清理完成"
}

trap cleanup EXIT INT TERM

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        --interval)
            INTERVAL="$2"
            shift 2
            ;;
        --inject)
            USE_INJECT=true
            shift
            ;;
        --with-monitor)
            WITH_MONITOR=true
            shift
            ;;
        --libfuzzer)
            USE_LIBFUZZER=true
            shift
            ;;
        --afl)
            USE_AFL=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            print_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
done

print_header

# 切换到 fuzzing_test 目录
cd "$FUZZING_TEST_DIR"

# 创建必要目录
mkdir -p "${FUZZING_TEST_DIR}/output/crashes"
mkdir -p "${FUZZING_TEST_DIR}/output/hangs"
mkdir -p "${FUZZING_TEST_DIR}/output/corpus"

# ============================================================================
# libFuzzer 模式
# ============================================================================
if [ "$USE_LIBFUZZER" = true ]; then
    LIBFUZZER_BIN="${FUZZING_TEST_DIR}/build_libfuzzer/libfuzzer_harness"
    
    if [ ! -f "$LIBFUZZER_BIN" ]; then
        print_error "libFuzzer harness 未找到，请先运行: ./tools/build_advanced.sh --libfuzzer"
        exit 1
    fi
    
    print_info "启动 libFuzzer 覆盖率引导模糊测试..."
    echo ""
    echo "配置:"
    echo "  种子目录: ${FUZZING_TEST_DIR}/seeds/"
    echo "  字典文件: ${FUZZING_TEST_DIR}/dictionaries/rtps.dict"
    echo "  输出目录: ${FUZZING_TEST_DIR}/corpus/"
    echo ""
    
    "$LIBFUZZER_BIN" \
        "${FUZZING_TEST_DIR}/seeds/" \
        "${FUZZING_TEST_DIR}/corpus/" \
        -dict="${FUZZING_TEST_DIR}/dictionaries/rtps.dict" \
        -max_len=65536 \
        -print_final_stats=1 \
        -artifact_prefix="${FUZZING_TEST_DIR}/crashes/"
    
    exit 0
fi

# ============================================================================
# AFL++ 模式
# ============================================================================
if [ "$USE_AFL" = true ]; then
    AFL_BIN="${FUZZING_TEST_DIR}/build_afl/afl_harness"
    
    if [ ! -f "$AFL_BIN" ]; then
        print_error "AFL harness 未找到，请先运行: ./tools/build_advanced.sh --afl"
        exit 1
    fi
    
    if ! command -v afl-fuzz &> /dev/null; then
        print_error "afl-fuzz 未安装"
        exit 1
    fi
    
    print_info "启动 AFL++ 模糊测试..."
    echo ""
    echo "配置:"
    echo "  输入目录: ${FUZZING_TEST_DIR}/seeds/"
    echo "  输出目录: ${FUZZING_TEST_DIR}/output/"
    echo "  字典文件: ${FUZZING_TEST_DIR}/dictionaries/rtps.dict"
    echo ""
    
    afl-fuzz \
        -i "${FUZZING_TEST_DIR}/seeds/" \
        -o "${FUZZING_TEST_DIR}/output/" \
        -x "${FUZZING_TEST_DIR}/dictionaries/rtps.dict" \
        -- "$AFL_BIN" @@
    
    exit 0
fi

# ============================================================================
# 高级模糊测试节点模式
# ============================================================================

# 检查构建
if [ ! -d "$BUILD_DIR" ]; then
    print_error "构建目录不存在，请先运行: ./tools/build_advanced.sh --basic"
    exit 1
fi

FUZZER_BIN="${BUILD_DIR}/advanced_fuzzer_node"
MONITOR_BIN="${BUILD_DIR}/monitor_node_full"

if [ ! -f "$FUZZER_BIN" ]; then
    print_error "高级模糊器未找到: $FUZZER_BIN"
    print_info "请运行: ./tools/build_advanced.sh --basic"
    exit 1
fi

echo "配置:"
echo "  模式: ${MODE}"
echo "  迭代次数: ${ITERATIONS}"
echo "  发送间隔: ${INTERVAL}ms"
echo "  网络注入: ${USE_INJECT}"
echo "  监控节点: ${WITH_MONITOR}"
echo ""

# 启动监控节点（如果需要）
if [ "$WITH_MONITOR" = true ]; then
    if [ ! -f "$MONITOR_BIN" ]; then
        print_error "监控节点未找到: $MONITOR_BIN"
    else
        print_info "启动监控节点..."
        "$MONITOR_BIN" > "${FUZZING_TEST_DIR}/output/monitor_advanced.log" 2>&1 &
        MONITOR_PID=$!
        print_success "监控节点已启动 (PID: $MONITOR_PID)"
        sleep 2
    fi
fi

# 构建模糊器命令
FUZZER_CMD="$FUZZER_BIN --mode $MODE -n $ITERATIONS -i $INTERVAL"

if [ "$USE_INJECT" = true ]; then
    FUZZER_CMD="$FUZZER_CMD --inject"
fi

print_info "启动高级模糊测试..."
echo "命令: $FUZZER_CMD"
echo ""

# 运行模糊器
$FUZZER_CMD 2>&1 | tee "${FUZZING_TEST_DIR}/output/advanced_fuzzer.log"

echo ""
print_success "模糊测试完成！"
echo ""

# 显示结果摘要
if [ -d "${FUZZING_TEST_DIR}/output/crashes" ]; then
    CRASH_COUNT=$(ls -1 "${FUZZING_TEST_DIR}/output/crashes/" 2>/dev/null | wc -l)
    if [ "$CRASH_COUNT" -gt 0 ]; then
        echo -e "${RED}发现 $CRASH_COUNT 个崩溃！${NC}"
        echo "查看: ls ${FUZZING_TEST_DIR}/output/crashes/"
    fi
fi

if [ -d "${FUZZING_TEST_DIR}/output/hangs" ]; then
    HANG_COUNT=$(ls -1 "${FUZZING_TEST_DIR}/output/hangs/" 2>/dev/null | wc -l)
    if [ "$HANG_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}发现 $HANG_COUNT 个挂起！${NC}"
        echo "查看: ls ${FUZZING_TEST_DIR}/output/hangs/"
    fi
fi

echo ""
echo "日志文件:"
echo "  模糊器日志: ${FUZZING_TEST_DIR}/output/advanced_fuzzer.log"
if [ "$WITH_MONITOR" = true ]; then
    echo "  监控器日志: ${FUZZING_TEST_DIR}/output/monitor_advanced.log"
fi


