#!/bin/bash

if [ ! -f ~/.pass ]; then
    echo "Error: ~/.pass file not found"
    exit 1
fi
PASS=$(cat ~/.pass | tr -d '\n')

# Stop background server first to ensure we use our own proxy settings for the test
echo "$PASS" | sudo -S bin/vproxy clean >/dev/null 2>&1

expect <<EOF
set timeout 60
spawn sudo env VP_FORCE_IPTABLES=1 HOME=/home/qtopierw USER=qtopierw bin/vproxy -v /home/qtopierw/.local/bin/agy -p "echo helloworld" --print-timeout 10s
expect {
    -re ".*Password:.*" {
        send "$PASS\r"
        exp_continue
    }
    "helloworld" {
        puts "\n✅ Test passed!"
    }
    timeout {
        puts "\n❌ Error: Timed out waiting for output"
        exit 1
    }
    eof
}
EOF
