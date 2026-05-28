#!/bin/bash
expect -c "
    set timeout 30
    set pass [exec cat /home/qtopierw/.pass]
    spawn sudo ./bin/vproxy clean
    expect \"*Password:*\" { send \"\$pass\r\"; exp_continue }
    expect eof
"
expect -c "
    set timeout 30
    set pass [exec cat /home/qtopierw/.pass]
    spawn sudo ./bin/vproxy init
    expect \"*Password:*\" { send \"\$pass\r\"; exp_continue }
    expect eof
"
