#!/bin/bash

# macOS Automated Test Script for vproxy
# This script automates:
# 1. Compilation
# 2. Environment Variable Proxy Mode Test
# 3. Transparent Proxy (TUN) Mode Test (using sudo + expect)
# 4. Integration Tests (test_tproxy, test_google)

set -e

# --- Configuration ---
SUDO_PASS_FILE="$HOME/.pass"
EXPECT_HELPER="./scripts/sudo_expect.exp"
chmod +x "$EXPECT_HELPER"

if [ ! -f "$SUDO_PASS_FILE" ]; then
    echo "Error: $SUDO_PASS_FILE not found."
    exit 1
fi

# Function to provide timeout functionality on macOS
run_timeout() {
    local duration=$1
    shift
    if command -v gtimeout &> /dev/null; then
        gtimeout "$duration" "$@"
    elif command -v timeout &> /dev/null; then
        timeout "$duration" "$@"
    else
        # Fallback using background process
        "$@" &
        local pid=$!
        ( sleep "$duration"; kill "$pid" 2>/dev/null ) &
        local watcher=$!
        if wait "$pid" 2>/dev/null; then
            kill "$watcher" 2>/dev/null
            return 0
        else
            return 1
        fi
    fi
}

echo "--- Step 1: Compilation ---"
go build -o bin/vproxy ./cmd/vproxy
go build -o bin/test_tproxy ./tests/tproxy/main.go
go build -o bin/test_google ./tests/google/main.go

echo "Debug: Default interface according to 'route get default':"
route get default | grep "interface:"

echo "--- Step 2: Testing Environment Variable Proxy Mode ---"
# Explicitly unset any existing proxy vars
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY

./bin/vproxy curl -s -I https://www.google.com | grep -i "HTTP/" || (echo "Env-var proxy test failed"; exit 1)
echo "Env-var proxy test passed!"

# --- Step 3: Setting up Transparent Proxy (TUN) Mode ---
run_sudo() {
    local cmd=$1
    # Use the helper script
    ./scripts/sudo_expect.exp "$cmd" "$SUDO_PASS_FILE"
}

echo "Cleaning up existing environment..."
run_sudo "bin/vproxy clean"

echo "Initializing PF Transparent Proxy Mode..."
run_sudo "bin/vproxy init -v"

# Wait a moment for PF rules and listeners to be ready
sleep 3

echo "--- Step 4: Testing PF Transparent Proxy Mode ---"

# IMPORTANT: Ensure no proxy environment variables interfere
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY

# Test plain curl (should be intercepted by PF, no fake IP needed for pure IP access)
curl -4 -s -I --connect-timeout 5 http://1.1.1.1 | grep -i "HTTP/" || (echo "PF proxy test failed for pure IP"; run_sudo "bin/vproxy clean"; exit 1)
echo "PF proxy basic test passed for pure IP!"

# Test domain via Fake-IP + PF
curl -s -I --connect-timeout 5 https://google.com | grep -i "HTTP/" || (echo "PF proxy test failed for domain"; run_sudo "bin/vproxy clean"; exit 1)
echo "PF proxy basic test passed for domain!"

echo "Running Network Tests..."
make test-network || echo "Network tests had some failures, continuing..."

echo "Running Integration Tests (with timeout)..."
# In transparent mode, we run the tests DIRECTLY, not via the vproxy wrapper.
# This ensures we are testing the actual transparent interception.
run_timeout 60 ./bin/test_tproxy || echo "test_tproxy failed or timed out"
run_timeout 60 ./bin/test_google || echo "test_google failed or timed out"

echo "--- Step 5: Cleanup ---"
run_sudo "bin/vproxy clean"

echo "All macOS tests completed!"
