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
        set timeout 30
        spawn sudo bin/vproxy init
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
else
    sudo bin/vproxy clean
    sudo bin/vproxy init
fi
