#!/bin/bash
expect -c "
    set timeout 30
    set pass [exec cat /home/qtopierw/.pass]
    spawn sudo mkdir -p /etc/vproxy
    expect \"*Password:*\" { send \"\$pass\r\"; exp_continue }
    expect eof
"
expect -c "
    set timeout 30
    set pass [exec cat /home/qtopierw/.pass]
    spawn sudo cp /home/qtopierw/.vproxy/config.json /etc/vproxy/config.json
    expect \"*Password:*\" { send \"\$pass\r\"; exp_continue }
    expect eof
"
