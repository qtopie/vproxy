#!/bin/bash

# Clean and Init
expect -c "
    set timeout 30
    set pass [exec cat /home/qtopierw/.pass]
    spawn sudo ./bin/vproxy clean
    expect \"*Password:*\" { send \"\$pass\r\"; exp_continue }
    expect eof
" > /dev/null

expect -c "
    set timeout 30
    set pass [exec cat /home/qtopierw/.pass]
    spawn sudo sh -c \"HOME=/home/qtopierw ./bin/vproxy init\"
    expect \"*Password:*\" { send \"\$pass\r\"; exp_continue }
    expect eof
" > /dev/null

echo "Starting 10 concurrent wrapper tests..."
pids=""

for i in {1..10}; do
    ./bin/vproxy ./bin/test_google > /tmp/test_google_$i.log 2>&1 &
    pids="$pids $!"
done

wait $pids

success=0
fail=0

for i in {1..10}; do
    if grep -q "✅ Connection Test Succeeded" /tmp/test_google_$i.log; then
        ((success++))
    else
        echo "Test $i FAILED! Log snippet:"
        tail -n 10 /tmp/test_google_$i.log
        ((fail++))
    fi
done

echo "Concurrency Test Results:"
echo "Success: $success / 10"
echo "Failed: $fail / 10"

if [ $fail -gt 0 ]; then
    exit 1
fi
