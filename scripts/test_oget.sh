#!/bin/bash
if [ -f ~/.pass ]; then
    PASS=$(cat ~/.pass | tr -d '\n')
    expect -c "
        set timeout 60
        spawn sudo bin/vproxy -v oget https://www.google.com.hk
        expect \"*Password:*\" { send \"$PASS\r\"; exp_continue }
        expect eof
    "
else
    sudo bin/vproxy -v oget https://www.google.com.hk
fi
