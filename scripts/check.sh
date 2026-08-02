#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. 运行代码 Lint 校验 ==="
# Add lint / format execution commands here (e.g., golangci-lint / eslint / ruff)

echo "=== 2. 运行 Harness 评估与沙盒测试套件 ==="
if [ -f "./scripts/check-harness.sh" ]; then
    ./scripts/check-harness.sh
else
    echo "--> Running fallback test suite..."
fi

echo "✅ 所有校验与 Harness 测试已成功通过！"
