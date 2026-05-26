#!/bin/bash
if [ -f ~/.pass ]; then
    PASS=$(cat ~/.pass | tr -d '\n')
    expect -c "
        set timeout 60
        spawn sudo bin/vproxy -v bin/test_ebpf
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
    expect -c "
        set timeout 60
        spawn sudo bin/vproxy -v bin/test_tproxy
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
else
    sudo bin/vproxy -v bin/test_ebpf
    sudo bin/vproxy -v bin/test_tproxy
fi
