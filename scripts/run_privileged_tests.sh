#!/bin/bash
if [ -f ~/.pass ]; then
    PASS=$(cat ~/.pass | tr -d '\n')
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy clean
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
    expect -c "
        set timeout 60
        spawn sudo bin/test_ebpf
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
    expect -c "
        set timeout 60
        spawn sudo bin/test_tproxy
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
else
    sudo bin/vproxy clean
    sudo bin/test_ebpf
    sudo bin/test_tproxy
fi
