# DDS Fuzzing Test - Makefile
# 提供便捷的构建和测试命令

.PHONY: all build clean test help run-fuzzer run-monitors install

# 默认目标
all: build

# 构建所有节点
build:
	@echo "构建所有节点..."
	@./build_all.sh

# 清理构建产物
clean:
	@echo "清理构建目录和日志..."
	@rm -rf build build_asan build_ubsan build_full
	@rm -f *.log *.out
	@rm -rf .pids
	@echo "清理完成"

# 运行完整测试
test: build
	@echo "运行模糊测试..."
	@./run_test.sh

# 快速测试（少量消息）
test-quick: build
	@echo "运行快速测试（100条消息）..."
	@./run_test.sh 100 50

# 压力测试（大量消息）
test-stress: build
	@echo "运行压力测试（10000条消息）..."
	@./run_test.sh 10000 10

# 仅运行 Fuzzer 节点（需要手动启动 Monitor）
run-fuzzer:
	@if [ ! -f build/fuzzer_node ]; then \
		echo "错误: 请先运行 'make build'"; \
		exit 1; \
	fi
	@echo "启动 Fuzzer 节点..."
	@cd build && ./fuzzer_node 1000 100

# 运行单个 Monitor 节点
run-monitor-asan:
	@if [ ! -f build_asan/monitor_node_asan ]; then \
		echo "错误: 请先运行 'make build'"; \
		exit 1; \
	fi
	@echo "启动 Monitor 节点 (ASAN)..."
	@cd build_asan && ./monitor_node_asan

run-monitor-ubsan:
	@if [ ! -f build_ubsan/monitor_node_ubsan ]; then \
		echo "错误: 请先运行 'make build'"; \
		exit 1; \
	fi
	@echo "启动 Monitor 节点 (UBSAN)..."
	@cd build_ubsan && ./monitor_node_ubsan

run-monitor-full:
	@if [ ! -f build_full/monitor_node_full ]; then \
		echo "错误: 请先运行 'make build'"; \
		exit 1; \
	fi
	@echo "启动 Monitor 节点 (ASAN+UBSAN)..."
	@cd build_full && ./monitor_node_full

# 查看日志
logs:
	@echo "=== Fuzzer 日志 ==="
	@tail -50 fuzzer_node.log 2>/dev/null || echo "无日志文件"
	@echo ""
	@echo "=== Monitor 1 日志 ==="
	@tail -50 monitor_node_1.log 2>/dev/null || echo "无日志文件"
	@echo ""
	@echo "=== Monitor 2 日志 ==="
	@tail -50 monitor_node_2.log 2>/dev/null || echo "无日志文件"
	@echo ""
	@echo "=== Monitor 3 日志 ==="
	@tail -50 monitor_node_3.log 2>/dev/null || echo "无日志文件"

# 查看异常检测
check-anomalies:
	@echo "检查检测到的异常..."
	@grep -h "ANOMALY" *.log 2>/dev/null || echo "未检测到异常"

# 查看错误
check-errors:
	@echo "检查错误..."
	@grep -h "ERROR" *.log 2>/dev/null || echo "无错误"

# 统计信息
stats:
	@echo "=== 测试统计 ==="
	@grep -h "Statistics" *.log -A 10 2>/dev/null || echo "无统计信息"

# 帮助信息
help:
	@echo "DDS Fuzzing Test - 可用命令："
	@echo ""
	@echo "  make build          - 构建所有节点"
	@echo "  make clean          - 清理构建产物和日志"
	@echo "  make test           - 运行完整测试（推荐）"
	@echo "  make test-quick     - 运行快速测试（100条消息）"
	@echo "  make test-stress    - 运行压力测试（10000条消息）"
	@echo ""
	@echo "  make run-fuzzer         - 单独运行 Fuzzer 节点"
	@echo "  make run-monitor-asan   - 单独运行 Monitor (ASAN)"
	@echo "  make run-monitor-ubsan  - 单独运行 Monitor (UBSAN)"
	@echo "  make run-monitor-full   - 单独运行 Monitor (Full)"
	@echo ""
	@echo "  make logs               - 查看所有日志"
	@echo "  make check-anomalies    - 查看检测到的异常"
	@echo "  make check-errors       - 查看错误信息"
	@echo "  make stats              - 查看统计信息"
	@echo ""
	@echo "快速开始："
	@echo "  1. make build"
	@echo "  2. make test"
	@echo "  3. make check-anomalies"
	@echo ""

# 重新构建
rebuild: clean build

# 完整的测试流程
full: clean build test stats check-anomalies
	@echo ""
	@echo "完整测试流程完成！"

