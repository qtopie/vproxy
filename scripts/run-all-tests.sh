#!/bin/bash
set -e

if [ -f ~/.pass ]; then
    PASS=$(cat ~/.pass | tr -d '\n')
    echo "Running initialization with expect..."
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy clean
        expect {
            \"*Password:*\" { send \"$PASS\r\"; exp_continue }
            eof
        }
    "
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy init
        expect {
            \"*Password:*\" { send \"$PASS\r\"; exp_continue }
            eof
        }
    "
    make build-tests
    expect -c "
        set timeout 30
        spawn sudo setcap cap_net_admin,cap_net_bind_service,cap_bpf,cap_sys_resource,cap_dac_override+ep bin/test_ebpf
        expect {
            \"*Password:*\" { send \"$PASS\r\"; exp_continue }
            eof
        }
    "
else
    echo "No ~/.pass found, running with normal sudo..."
    sudo bin/vproxy clean
    sudo bin/vproxy init
fi

echo -e "\n=== Running make test-network ==="
timeout 30s make test-network || true

echo -e "\n=== Running ebpf test via vproxy ==="
timeout 30s bin/vproxy -v bin/test_ebpf || true

echo -e "\n=== Running tproxy test via vproxy ==="
timeout 30s bin/vproxy -v bin/test_tproxy || true

echo -e "\n=== Running agy test script ==="
timeout 60s bash scripts/test-agy.sh || true
