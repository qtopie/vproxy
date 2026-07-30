在测试vproxy前，先执行清理和初始化环境（如果需要输入密码用expect输入，密码从 ~/.pass 读取）：

```bash
if [ -f ~/.pass ]; then
    PASS=$(cat ~/.pass | tr -d '\n')
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy clean
        expect \"*Password:*\" { send \"\$PASS\r\"; exp_continue }
        eof
    "
    expect -c "
        set timeout 30
        spawn sudo bin/vproxy init
        expect \"*Password:*\" { send \"\$PASS\r\"; exp_continue }
        eof
    "
else
    sudo bin/vproxy clean
    sudo bin/vproxy init
fi
```

你需要通过所有的测试

```bash
make test-network
```

然后通过下面的测试

```bash
bin/vproxy -v bin/test_ebpf

bin/vproxy -v bin/test_tproxy

bin/vproxy -v bin/test_google
```

注意每一步骤都需要加上timeout 防止一直等待 
