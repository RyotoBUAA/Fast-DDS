#!/bin/bash
# ============================================================================
# 高级模糊测试构建脚本
# ============================================================================
# 
# 这个脚本提供了多种构建配置，用于不同的模糊测试场景。
#
# 使用方法:
#   ./build_advanced.sh [选项]
#
# 选项:
#   --basic          基础构建 (默认)
#   --libfuzzer      启用 libFuzzer 覆盖率引导模糊测试
#   --afl            启用 AFL++ 构建
#   --all            启用所有模糊测试工具
#   --clean          清理构建目录
#   --help           显示帮助信息
#
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
FASTDDS_ROOT="${SCRIPT_DIR}/../../.."

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "  DDS 高级模糊测试构建系统"
    echo "=============================================="
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

show_help() {
    echo "使用方法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --basic          基础构建（包含高级模糊器，不需要特殊编译器）"
    echo "  --libfuzzer      启用 libFuzzer 覆盖率引导模糊测试（需要 Clang）"
    echo "  --afl            启用 AFL++ 构建（需要 afl-clang-fast++）"
    echo "  --all            启用所有模糊测试工具"
    echo "  --sanitizers     启用所有 sanitizers（ASAN + UBSAN）"
    echo "  --clean          清理构建目录"
    echo "  --help           显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --basic           # 基础构建"
    echo "  $0 --libfuzzer       # 使用 libFuzzer"
    echo "  $0 --afl             # 使用 AFL++"
    echo "  $0 --all             # 构建所有工具"
}

check_dependencies() {
    print_info "检查依赖项..."
    
    # 检查 CMake
    if ! command -v cmake &> /dev/null; then
        print_error "CMake 未安装"
        exit 1
    fi
    print_success "CMake: $(cmake --version | head -n1)"
    
    # 检查编译器
    if command -v clang++ &> /dev/null; then
        print_success "Clang++: $(clang++ --version | head -n1)"
        HAS_CLANG=1
    else
        print_warning "Clang++ 未安装（libFuzzer 需要）"
        HAS_CLANG=0
    fi
    
    # 检查 AFL++
    if command -v afl-clang-fast++ &> /dev/null; then
        print_success "AFL++: $(afl-clang-fast++ --version 2>&1 | head -n1)"
        HAS_AFL=1
    else
        print_warning "AFL++ 未安装"
        HAS_AFL=0
    fi
    
    # 检查 Fast-DDS
    if [ -f "${FASTDDS_ROOT}/CMakeLists.txt" ]; then
        print_success "Fast-DDS 源码目录: ${FASTDDS_ROOT}"
    else
        print_warning "Fast-DDS 源码目录未找到，将尝试查找已安装的库"
    fi
    
    echo ""
}

build_basic() {
    print_info "构建基础模糊测试工具..."
    
    mkdir -p "${BUILD_DIR}"
    cd "${BUILD_DIR}"
    
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_ASAN=ON \
        -DENABLE_UBSAN=ON
    
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    print_success "基础构建完成"
}

build_libfuzzer() {
    print_info "构建 libFuzzer 工具..."
    
    if [ "$HAS_CLANG" != "1" ]; then
        print_error "libFuzzer 需要 Clang 编译器"
        exit 1
    fi
    
    mkdir -p "${BUILD_DIR}_libfuzzer"
    cd "${BUILD_DIR}_libfuzzer"
    
    CC=clang CXX=clang++ cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_LIBFUZZER=ON \
        -DENABLE_ASAN=ON \
        -DENABLE_UBSAN=ON
    
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    print_success "libFuzzer 构建完成"
    print_info "运行方法: ./build_libfuzzer/libfuzzer_harness seeds/ -dict=dictionaries/rtps.dict"
}

build_afl() {
    print_info "构建 AFL++ 工具..."
    
    if [ "$HAS_AFL" != "1" ]; then
        print_error "AFL++ 未安装"
        echo ""
        echo "安装 AFL++:"
        echo "  macOS:  brew install aflplusplus"
        echo "  Ubuntu: apt install afl++"
        echo "  源码:   git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus && make"
        exit 1
    fi
    
    mkdir -p "${BUILD_DIR}_afl"
    cd "${BUILD_DIR}_afl"
    
    CC=afl-clang-fast CXX=afl-clang-fast++ cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DENABLE_AFL=ON \
        -DENABLE_ASAN=ON \
        -DENABLE_UBSAN=ON
    
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    
    print_success "AFL++ 构建完成"
    print_info "运行方法: afl-fuzz -i seeds/ -o output/ -x dictionaries/rtps.dict -- ./build_afl/afl_harness @@"
}

build_all() {
    print_info "构建所有模糊测试工具..."
    
    build_basic
    
    if [ "$HAS_CLANG" == "1" ]; then
        cd "${SCRIPT_DIR}"
        build_libfuzzer
    fi
    
    if [ "$HAS_AFL" == "1" ]; then
        cd "${SCRIPT_DIR}"
        build_afl
    fi
    
    print_success "所有工具构建完成"
}

clean_build() {
    print_info "清理构建目录..."
    
    rm -rf "${BUILD_DIR}"
    rm -rf "${BUILD_DIR}_libfuzzer"
    rm -rf "${BUILD_DIR}_afl"
    rm -rf "${SCRIPT_DIR}/crashes"
    rm -rf "${SCRIPT_DIR}/hangs"
    rm -rf "${SCRIPT_DIR}/corpus"
    
    print_success "清理完成"
}

# ============================================================================
# 主程序
# ============================================================================

print_header
check_dependencies

# 默认构建基础版本
BUILD_MODE="basic"

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --basic)
            BUILD_MODE="basic"
            shift
            ;;
        --libfuzzer)
            BUILD_MODE="libfuzzer"
            shift
            ;;
        --afl)
            BUILD_MODE="afl"
            shift
            ;;
        --all)
            BUILD_MODE="all"
            shift
            ;;
        --sanitizers)
            BUILD_MODE="sanitizers"
            shift
            ;;
        --clean)
            clean_build
            exit 0
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

cd "${SCRIPT_DIR}"

case $BUILD_MODE in
    basic)
        build_basic
        ;;
    libfuzzer)
        build_libfuzzer
        ;;
    afl)
        build_afl
        ;;
    all)
        build_all
        ;;
    sanitizers)
        build_basic
        ;;
esac

echo ""
print_success "构建完成！"
echo ""
echo "可用的可执行文件:"
echo ""

if [ -d "${BUILD_DIR}" ]; then
    echo "基础构建目录: ${BUILD_DIR}/"
    ls -la "${BUILD_DIR}"/*.node "${BUILD_DIR}"/*_fuzzer* 2>/dev/null || true
fi

if [ -d "${BUILD_DIR}_libfuzzer" ]; then
    echo ""
    echo "libFuzzer 构建目录: ${BUILD_DIR}_libfuzzer/"
    ls -la "${BUILD_DIR}_libfuzzer"/*harness* 2>/dev/null || true
fi

if [ -d "${BUILD_DIR}_afl" ]; then
    echo ""
    echo "AFL++ 构建目录: ${BUILD_DIR}_afl/"
    ls -la "${BUILD_DIR}_afl"/*harness* 2>/dev/null || true
fi

echo ""
echo "======================================"
echo "  快速开始指南"
echo "======================================"
echo ""
echo "1. 高级协议感知模糊测试:"
echo "   ./build/advanced_fuzzer_node --mode hybrid -n 10000"
echo ""
echo "2. 网络注入模糊测试:"
echo "   ./build/network_injector_fuzzer --inject -t 127.0.0.1 -p 7400"
echo ""
echo "3. libFuzzer 覆盖率引导测试:"
echo "   ./build_libfuzzer/libfuzzer_harness seeds/ -dict=dictionaries/rtps.dict -max_len=65536"
echo ""
echo "4. AFL++ 模糊测试:"
echo "   afl-fuzz -i seeds/ -o output/ -x dictionaries/rtps.dict -- ./build_afl/afl_harness @@"
echo ""

